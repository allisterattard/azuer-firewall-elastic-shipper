package azure

import (
	"azure-firewall-elastic-shipper/parser"
	"context"
	"encoding/json"
	"log"

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

func createCredential() *azidentity.DefaultAzureCredential {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("Failed to obtain a credential : %v", err)
	}
	return cred
}

func createCheckpointStore(storageAccountURL string, containerName string, cred *azidentity.DefaultAzureCredential, ctx context.Context) *checkpoints.BlobStore {
	blobClient, err := azblob.NewClient(storageAccountURL, cred, nil)
	if err != nil {
		log.Fatalf("Failed to create blob storage client: %v", err)
	}

	containerClient := blobClient.ServiceClient().NewContainerClient(containerName)

	_, err = containerClient.GetProperties(ctx, nil)
	if err != nil {
		log.Fatalf("CRITICAL: Failed to connect or access Storage Account container '%s'. Check permissions or URL! Error: %v", containerName, err)
	}
	log.Println("Successfully connected to Azure Blob Storage checkpoint container.")

	checkpointStore, err := checkpoints.NewBlobStore(containerClient, nil)
	if err != nil {
		log.Fatalf("Failed to create checkpoint store: %v", err)
	}

	return checkpointStore
}

func createProcessor(fullyQualifiedNamespace string, eventHubName string, cred *azidentity.DefaultAzureCredential, checkpointsStore *checkpoints.BlobStore, ctx context.Context) *azeventhubs.Processor {
	consumerClient, err := azeventhubs.NewConsumerClient(fullyQualifiedNamespace, eventHubName, "$Default", cred, nil)
	if err != nil {
		log.Fatalf("failed to create eventhub consumer client: %v", err)
	}

	props, err := consumerClient.GetEventHubProperties(ctx, nil)
	if err != nil {
		log.Fatalf("CRITICAL: Failed to connect to Event Hub '%sCheck namespace/name or IAM permissions! Error: %v", eventHubName, err)
	}
	log.Printf("Successfully connected to Event Hub! Found %d partitions.", len(props.PartitionIDs))

	options := &azeventhubs.ProcessorOptions{
		StartPositions: azeventhubs.StartPositions{Default: azeventhubs.StartPosition{Earliest: to.Ptr(true)}},
	}

	processor, err := azeventhubs.NewProcessor(consumerClient, checkpointsStore, options)
	if err != nil {
		log.Fatalf("Failed to create eventhub processor: %v", err)
	}
	return processor
}

func NewEventHubConsumer(fullyQualifiedNamespace string, eventHubName string, storageAccountURL string, ContainerName string, ctx context.Context) *EventHubConsumer {
	cred := createCredential()
	checkpointStore := createCheckpointStore(storageAccountURL, ContainerName, cred, ctx)
	processor := createProcessor(fullyQualifiedNamespace, eventHubName, cred, checkpointStore, ctx)

	return &EventHubConsumer{Processor: processor}
}

func getFWRuleCategoryType(record json.RawMessage) string {
	var envelope LogEnvelope
	if err := json.Unmarshal(record, &envelope); err != nil {
		log.Printf("Failed to parse log record JSON: %v", err)
		return ""
	}

	return envelope.Category
}

func (e *EventHubConsumer) EventHubStartListening(ctx context.Context) error {
	log.Println("Starting Event HUb Processor...")

	go func() {
		if err := e.Processor.Run(ctx); err != nil {
			log.Printf("Processor stopped with error: %v", err)
		}
	}()

	for {
		partitionClient := e.Processor.NextPartitionClient(ctx)

		if partitionClient == nil {
			log.Println("Processor stopped or context cancelled. Exiting listener loop.")
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
			log.Printf("Error receiving events from partition %s: %v", pc.PartitionID(), err)
			continue
		}

		if len(events) > 0 {
			log.Printf("Pulled batch of %d events!", len(events))
		}

		for _, event := range events {
			e.processEvent(event)
			if ctx.Err() != nil {
				return
			}

			if err := pc.UpdateCheckpoint(ctx, event, nil); err != nil {
				log.Printf("Failed to update checkpoint: %v", err)
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
			log.Printf("Individual Firewall Log Array: %s", string(itemBytes))
		}
		return
	}

	log.Printf("Firewall Log fallback: %s", string(event.Body))
}

func (e *EventHubConsumer) processRecord(record json.RawMessage) {
	category := getFWRuleCategoryType(record)

	switch category {
	case "AZFWNetworkRule":
		parser.ParseNetworkRule(record)
	case "AZFWNatRule":
		parser.ParseNatRule(record)
	case "AZFWApplicationRule":
		parser.ParseApplicationRule(record)
	default:
		log.Printf("Warning: Unhandled rule category: %s", category)
	}
}
