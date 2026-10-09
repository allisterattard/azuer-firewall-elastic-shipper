package main

import (
	"azure-firewall-elastic-shipper/azure"
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	log.Println("Starting Azure Firewall to ElasticSearch Ingestor...")
	namespace := "log-stg.servicebus.windows.net"
	eventHub := "logs-stg"
	storageURL := "https://thanosprometheusdatastg.blob.core.windows.net"
	container := "azure-fw-checkpoint-container"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	consumer := azure.NewEventHubConsumer(namespace, eventHub, storageURL, container, ctx)

	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChannel
		log.Println("Shutdown signal received. Stopping consumer gracefully...")
		cancel()
	}()

	log.Println("Listening for live Azure logs...")
	if err := consumer.EventHubStartListening(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Processor stopped with error: %v", err)
	}

	log.Println("Application successfully shut down")
}
