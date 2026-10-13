package azure

import (
	"azure-firewall-elastic-shipper/elasticsearch"
	"azure-firewall-elastic-shipper/model"
	"azure-firewall-elastic-shipper/parser"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs/v2/checkpoints"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

type EventHubConsumer struct {
	Processor *azeventhubs.Processor
	EsClient  *elasticsearch.Client
}

type LogEnvelope struct {
	Category string `json:"category"`
}

type DiagnosticPayload struct {
	Records []json.RawMessage `json:"records"`
}

func createCredential(secrets model.AzureClientSecret) *azidentity.ClientSecretCredential {
	cred, err := azidentity.NewClientSecretCredential(secrets.TenantID, secrets.ClientID, secrets.ClientSecret, nil)
	if err != nil {
		slog.Error("Failed to obtain a credential", "error", err)
		os.Exit(1)
	}
	return cred
}

func createCheckpointStore(storageAccountURL string, containerName string, cred *azidentity.ClientSecretCredential, ctx context.Context) *checkpoints.BlobStore {
	blobClient, err := azblob.NewClient(storageAccountURL, cred, nil)
	if err != nil {
		slog.Error("Failed to create blob storage client", "error", err)
		os.Exit(1)
	}

	containerClient := blobClient.ServiceClient().NewContainerClient(containerName)

	_, err = containerClient.GetProperties(ctx, nil)
	if err != nil {
		slog.Error("Failed to connect or access Storage Account container", "containerName", containerName, "error", err)
		os.Exit(1)
	}
	slog.Info("Successfully connected to Azure Blob Storage checkpoint container.")

	checkpointStore, err := checkpoints.NewBlobStore(containerClient, nil)
	if err != nil {
		slog.Error("Failed to create checkpoint store", "error", err)
		os.Exit(1)
	}

	return checkpointStore
}

func createProcessor(fullyQualifiedNamespace string, eventHubName string, cred *azidentity.ClientSecretCredential, checkpointsStore *checkpoints.BlobStore, ctx context.Context) *azeventhubs.Processor {
	consumerClient, err := azeventhubs.NewConsumerClient(fullyQualifiedNamespace, eventHubName, "$Default", cred, nil)
	if err != nil {
		slog.Error("failed to create eventhub consumer client", "error", err)
		os.Exit(1)
	}

	props, err := consumerClient.GetEventHubProperties(ctx, nil)
	if err != nil {
		slog.Error("Failed to connect to Event Hub", "eventHubName", eventHubName, "error", err)
		os.Exit(1)
	}
	slog.Info("Successfully connected to Event Hub!", "partitionsFound", len(props.PartitionIDs))

	options := &azeventhubs.ProcessorOptions{
		StartPositions: azeventhubs.StartPositions{Default: azeventhubs.StartPosition{Earliest: to.Ptr(true)}},
	}

	processor, err := azeventhubs.NewProcessor(consumerClient, checkpointsStore, options)
	if err != nil {
		slog.Error("Failed to create eventhub processor", "error", err)
		os.Exit(1)
	}
	return processor
}

func NewEventHubConsumer(fullyQualifiedNamespace string, eventHubName string, storageAccountURL string, ContainerName string, ctx context.Context, secrets model.AzureClientSecret, esClient *elasticsearch.Client) *EventHubConsumer {
	cred := createCredential(secrets)
	checkpointStore := createCheckpointStore(storageAccountURL, ContainerName, cred, ctx)
	processor := createProcessor(fullyQualifiedNamespace, eventHubName, cred, checkpointStore, ctx)

	return &EventHubConsumer{Processor: processor, EsClient: esClient}
}

func getFWRuleCategoryType(record json.RawMessage) string {
	var envelope LogEnvelope
	if err := json.Unmarshal(record, &envelope); err != nil {
		slog.Error("Failed to parse log record JSON", "error", err)
		return ""
	}

	return envelope.Category
}

func (e *EventHubConsumer) EventHubStartListening(ctx context.Context) error {
	slog.Info("Starting Event HUb Processor...")

	go func() {
		if err := e.Processor.Run(ctx); err != nil {
			slog.Error("Processor stopped with error", "error", err)
		}
	}()

	for {
		partitionClient := e.Processor.NextPartitionClient(ctx)

		if partitionClient == nil {
			slog.Info("Processor stopped or context cancelled. Exiting listener loop.")
			return nil
		}

		go e.handlePartitionClient(ctx, partitionClient)
	}
}

func (e *EventHubConsumer) handlePartitionClient(ctx context.Context, pc *azeventhubs.ProcessorPartitionClient) {
	defer func() {
		if pc != nil {
			err := pc.Close(context.Background())
			if err != nil {
				return
			}
		}
	}()

	for {
		events, err := pc.ReceiveEvents(ctx, 100, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("Error receiving events from partition", "partitionId", pc.PartitionID(), "error", err)
			continue
		}

		if len(events) == 0 {
			continue
		}

		slog.Info("Pulled batch of events!", "count", len(events))
		var networkBatch []model.LogEntityNetworkRule
		var natBatch []model.LogEntityNatRule
		var appBatch []model.LogEntityApplicationRule

		for _, event := range events {
			e.processEvent(event, &networkBatch, &natBatch, &appBatch)
			if ctx.Err() != nil {
				return
			}

		}

		if os.Getenv("SEND_TO_ELASTIC") == "true" {
			if len(networkBatch) > 0 {
				if err := e.EsClient.SendBulk(ctx, "logs-azure-firewall.network", networkBatch); err != nil {
					slog.Error("Failed to send network batch rules to ES", "error", err)
					continue
				}
			}
			if len(natBatch) > 0 {
				if err := e.EsClient.SendBulk(ctx, "logs-azure-firewall.nat", natBatch); err != nil {
					slog.Error("Failed to send nat batch rules to ES", "error", err)
					continue
				}
			}
			if len(appBatch) > 0 {
				if err := e.EsClient.SendBulk(ctx, "logs-azure-firewall.application", appBatch); err != nil {
					slog.Error("Failed to send application nbatch  rules to ES", "error", err)
					continue
				}
			}
		} else {
			for _, item := range networkBatch {
				jsonData, err := json.Marshal(item)
				if err != nil {
					slog.Error("failed to marshal json")
				}
				fmt.Println(string(jsonData))
			}

			for _, item := range natBatch {
				jsonData, err := json.Marshal(item)
				if err != nil {
					slog.Error("failed to marshal json")
				}
				fmt.Println(string(jsonData))
			}

			for _, item := range appBatch {
				jsonData, err := json.Marshal(item)
				if err != nil {
					slog.Error("failed to marshal json")
				}
				fmt.Println(string(jsonData))
			}
		}

		if err := pc.UpdateCheckpoint(ctx, events[len(events)-1], nil); err != nil {
			slog.Error("Failed to update checkpoint", "error", err)
		}
	}
}

func (e *EventHubConsumer) processEvent(event *azeventhubs.ReceivedEventData, networkBatch *[]model.LogEntityNetworkRule, natBatch *[]model.LogEntityNatRule, appBatch *[]model.LogEntityApplicationRule) {
	var diagnosticPayload DiagnosticPayload

	if err := json.Unmarshal(event.Body, &diagnosticPayload); err == nil && len(diagnosticPayload.Records) > 0 {
		for _, record := range diagnosticPayload.Records {
			e.processRecord(record, networkBatch, natBatch, appBatch)
		}
		return
	}

	var directArray []map[string]any
	if err := json.Unmarshal(event.Body, &directArray); err == nil && len(directArray) > 0 {
		for _, item := range directArray {
			itemBytes, _ := json.Marshal(item)
			slog.Info("Individual Firewall Log Array", "item", string(itemBytes))
		}
		return
	}

	slog.Info("Firewall Log fallback:", "body", string(event.Body))
}

func (e *EventHubConsumer) processRecord(record json.RawMessage, networkBatch *[]model.LogEntityNetworkRule, natBatch *[]model.LogEntityNatRule, appBatch *[]model.LogEntityApplicationRule) {
	category := getFWRuleCategoryType(record)

	if category == "AzureFirewallDnsProxy" || category == "AZFWDnsQuery" {
		return
	}

	switch category {
	case "AZFWNetworkRule":
		log, err := parser.ParseNetworkRule(record)
		if err != nil {
			return
		}
		*networkBatch = append(*networkBatch, log)
	case "AZFWNatRule":
		log, err := parser.ParseNatRule(record)
		if err != nil {
			return
		}
		*natBatch = append(*natBatch, log)
	case "AZFWApplicationRule":
		log, err := parser.ParseApplicationRule(record)
		if err != nil {
			return
		}
		*appBatch = append(*appBatch, log)
	default:
		slog.Warn("Encountered unknown Log", "category", category, "raw_payload", string(record))
	}
}
