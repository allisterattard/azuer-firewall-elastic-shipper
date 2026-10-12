package main

import (
	"azure-firewall-elastic-shipper/azure"
	"azure-firewall-elastic-shipper/model"
	"azure-firewall-elastic-shipper/vault"
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
}

func main() {

	slog.Info("Starting Azure Firewall to ElasticSearch Ingestor...")
	secrets := getAzureTokens()
	namespace := "log-stg.servicebus.windows.net"
	eventHub := "logs-stg"
	storageURL := "https://thanosprometheusdatastg.blob.core.windows.net"
	container := "azure-fw-checkpoint-container"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	consumer := azure.NewEventHubConsumer(namespace, eventHub, storageURL, container, ctx, secrets)

	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChannel
		slog.Info("Shutdown signal received. Stopping consumer gracefully...")
		cancel()
	}()

	slog.Info("Listening for live Azure logs...")
	if err := consumer.EventHubStartListening(ctx); err != nil && err != context.Canceled {
		slog.Error("Processor stopped with error", "error", err)
	}

	slog.Info("Application successfully shut down")
}

func getAzureTokens() model.AzureClientSecret {
	clientId := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	tenantId := os.Getenv("AZURE_TENANT_ID")

	if clientId == "" || clientSecret == "" || tenantId == "" {
		roleId := os.Getenv("APPROLE_ROLE_ID")
		secretId := os.Getenv("APPROLE_SECRET_ID")
		if roleId == "" || secretId == "" {
			slog.Error("env var with client id, client secret or tenant id or vault app role id and app role secret id needs to be set")
			os.Exit(1)
		}
		creds := vault.AuthFunc(roleId, secretId)
		return creds
	}
	return model.AzureClientSecret{ClientID: clientId, ClientSecret: clientSecret, TenantID: tenantId}
}
