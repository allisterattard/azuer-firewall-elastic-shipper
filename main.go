package main

import (
	"azure-firewall-elastic-shipper/azure"
	"azure-firewall-elastic-shipper/elasticsearch"
	"azure-firewall-elastic-shipper/healthcheck"
	"azure-firewall-elastic-shipper/model"
	"azure-firewall-elastic-shipper/vault"
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
}

func main() {
	slog.Info("Starting Azure Firewall to ElasticSearch Ingestor...")

	secrets, elasticApiKey := resolveCredentials()

	namespace := os.Getenv("AZURE_EVENTHUB_NS")
	eventHub := os.Getenv("AZURE_EVENTHUB_NAME")
	storageURL := os.Getenv("AZURE_STORAGE_ACCOUNT_URL")
	container := os.Getenv("AZURE_STORAGE_ACCOUNT_CONTAINER")

	if namespace == "" || eventHub == "" || storageURL == "" || container == "" {
		slog.Error("Please make sure AZURE_STORAGE_ACCOUNT_CONTAINER, AZURE_STORAGE_ACCOUNT_URL, AZURE_EVENTHUB_NAME, AZURE_EVENTHUB_NS env var are set")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	esClient := elasticsearch.NewClient(
		os.Getenv("ELASTIC_URL"),
		elasticApiKey,
	)

	if os.Getenv("SEND_TO_ELASTIC") == "true" {
		if err := esClient.EnsureDataStreamTemplate(ctx); err != nil {
			slog.Error("Failed to create data stream template", "error", err)
			os.Exit(1)
		}
	}

	mux := http.NewServeMux()
	healthChecker, err := healthcheck.NewHealthChecker(esClient, storageURL, container, namespace, eventHub, secrets)

	if err != nil {
		slog.Error("Failed to authenticated to Azure", "error", err)
		os.Exit(1)
	}
	go healthChecker.StartBackgroundHealthChecker(ctx, 20*time.Second)

	healthChecker.RegisterRoutes(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("Starting HTTP health server", "port", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server failed", "error", err)
		}
	}()

	consumer := azure.NewEventHubConsumer(namespace, eventHub, storageURL, container, ctx, secrets, esClient)

	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChannel
		slog.Info("Shutdown signal received. Stopping consumer gracefully...")
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP server forced to shutdown", "error", err)
		}
	}()

	slog.Info("Listening for live Azure logs...")
	if err := consumer.EventHubStartListening(ctx); err != nil && err != context.Canceled {
		slog.Error("Processor stopped with error", "error", err)
	}

	slog.Info("Application successfully shut down")
}

func resolveCredentials() (model.AzureClientSecret, string) {
	clientId := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	tenantId := os.Getenv("AZURE_TENANT_ID")
	elasticApiKey := os.Getenv("ELASTIC_API_KEY")
	elasticUrl := os.Getenv("ELASTIC_URL")
	sendToElastic := os.Getenv("SEND_TO_ELASTIC") == "true"

	hasAzureEnv := clientId != "" && clientSecret != "" && tenantId != ""
	hasSendElastic := !sendToElastic || (os.Getenv("ELASTIC_URL") != "" && elasticApiKey != "")

	if hasAzureEnv && hasSendElastic {
		return model.AzureClientSecret{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			TenantID:     tenantId,
		}, elasticApiKey
	}

	roleId := os.Getenv("APPROLE_ROLE_ID")
	secretId := os.Getenv("APPROLE_SECRET_ID")
	if roleId == "" || secretId == "" {
		slog.Error("Missing environment variables: provide direct credentials (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID) or vault APPROLE_ROLE_ID and APPROLE_SECRET_ID")
		os.Exit(1)
	}

	vaultClient := vault.NewClient(roleId, secretId)
	vaultData := vault.GetSecretData(vaultClient)

	if !hasAzureEnv {
		secrets := vault.GetAzureSecrets(vaultData)
		clientId, clientSecret, tenantId = secrets.ClientID, secrets.ClientSecret, secrets.TenantID
	}

	if sendToElastic && elasticApiKey == "" {
		elasticApiKey = vault.GetElasticApiKey(vaultData)

		if elasticUrl == "" {
			slog.Error("Missing environment variables: provide ELASTIC_URL")
			os.Exit(1)
		}
	}

	return model.AzureClientSecret{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		TenantID:     tenantId,
	}, elasticApiKey
}
