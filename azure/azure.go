package azure

import (
	"azure-firewall-elastic-shipper/model"
	"azure-firewall-elastic-shipper/parser"
	"context"
	"encoding/json"
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
	}
	return cred
}

func createCheckpointStore(storageAccountURL string, containerName string, cred *azidentity.ClientSecretCredential, ctx context.Context) *checkpoints.BlobStore {
	blobClient, err := azblob.NewClient(storageAccountURL, cred, nil)
	if err != nil {
		slog.Error("Failed to create blob storage client", "error", err)
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
	}

	return checkpointStore
}

func createProcessor(fullyQualifiedNamespace string, eventHubName string, cred *azidentity.ClientSecretCredential, checkpointsStore *checkpoints.BlobStore, ctx context.Context) *azeventhubs.Processor {
	consumerClient, err := azeventhubs.NewConsumerClient(fullyQualifiedNamespace, eventHubName, "$Default", cred, nil)
	if err != nil {
		slog.Error("failed to create eventhub consumer client", "error", err)
	}

	props, err := consumerClient.GetEventHubProperties(ctx, nil)
	if err != nil {
		slog.Error("Failed to connect to Event Hub", "eventHubName", eventHubName, "error", err)
	}
	slog.Info("Successfully connected to Event Hub!", "partitionsFound", len(props.PartitionIDs))

	options := &azeventhubs.ProcessorOptions{
		StartPositions: azeventhubs.StartPositions{Default: azeventhubs.StartPosition{Earliest: to.Ptr(true)}},
	}

	processor, err := azeventhubs.NewProcessor(consumerClient, checkpointsStore, options)
	if err != nil {
		slog.Error("Failed to create eventhub processor", "error", err)
	}
	return processor
}

func NewEventHubConsumer(fullyQualifiedNamespace string, eventHubName string, storageAccountURL string, ContainerName string, ctx context.Context, secrets model.AzureClientSecret) *EventHubConsumer {
	cred := createCredential(secrets)
	checkpointStore := createCheckpointStore(storageAccountURL, ContainerName, cred, ctx)
	processor := createProcessor(fullyQualifiedNamespace, eventHubName, cred, checkpointStore, ctx)

	return &EventHubConsumer{Processor: processor}
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

		if len(events) > 0 {
			slog.Info("Pulled batch of events!", "count", len(events))
		}

		for _, event := range events {
			e.processEvent(event)
			if ctx.Err() != nil {
				return
			}

			if err := pc.UpdateCheckpoint(ctx, event, nil); err != nil {
				slog.Error("Failed to update checkpoint", "error", err)
			}
		}
	}
}

func (e *EventHubConsumer) processEvent(event *azeventhubs.ReceivedEventData) {
	var diagnosticPayload DiagnosticPayload

	if err := json.Unmarshal(event.Body, &diagnosticPayload); err == nil && len(diagnosticPayload.Records) > 0 {
		for _, record := range diagnosticPayload.Records {
			e.processRecord(record)
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

func (e *EventHubConsumer) processRecord(record json.RawMessage) {
	category := getFWRuleCategoryType(record)

	if category == "AzureFirewallDnsProxy" || category == "AZFWDnsQuery" {
		return
	}

	switch category {
	case "AZFWNetworkRule", "AzureFirewallNetworkRule":
		parser.ParseNetworkRule(record)
	case "AZFWNatRule", "AzureFirewallNatRule":
		parser.ParseNatRule(record)
	case "AZFWApplicationRule", "AzureFirewallApplicationRule":
		parser.ParseApplicationRule(record)
	default:
		slog.Warn("Encountered unknown Log", "category", category, "raw_payload", string(record))
	}
}
