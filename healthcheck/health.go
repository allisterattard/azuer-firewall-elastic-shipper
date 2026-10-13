package healthcheck

import (
	"azure-firewall-elastic-shipper/elasticsearch"
	"azure-firewall-elastic-shipper/model"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

type HealthChecker struct {
	mu             sync.RWMutex
	isReady        bool
	esStatus       string
	storageStatus  string
	eventHubStatus string
	lastError      string
	esClient       *elasticsearch.Client
	storageURL     string
	container      string
	namespace      string
	eventhub       string
	creds          azcore.TokenCredential
}

type DependencyStatus struct {
	Component string `json:"component"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}

type HealthResponse struct {
	Status       string             `json:"status"`
	Dependencies []DependencyStatus `json:"dependencies"`
}

func NewHealthChecker(esClient *elasticsearch.Client, storageURL string, container string, namespace string, eventhub string, secrets model.AzureClientSecret) (*HealthChecker, error) {
	creds, err := azidentity.NewClientSecretCredential(secrets.TenantID, secrets.ClientID, secrets.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create azure credential for health checker: %w", err)
	}
	return &HealthChecker{
		esClient:       esClient,
		storageURL:     storageURL,
		container:      container,
		namespace:      namespace,
		eventhub:       eventhub,
		creds:          creds,
		esStatus:       "unknown",
		storageStatus:  "unknown",
		eventHubStatus: "unknown",
	}, nil
}

func (hc *HealthChecker) StartBackgroundHealthChecker(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	hc.runChecks(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping health background checker...")
			return
		case <-ticker.C:
			hc.runChecks(ctx)
		}
	}
}

func (hc *HealthChecker) runChecks(parentCtx context.Context) {
	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer cancel()

	esErrStr := ""
	esHealthy := true
	if os.Getenv("SEND_TO_ELASTIC") == "true" {
		if err := hc.checkElasticsearchHealth(ctx); err != nil {
			esHealthy = false
			esErrStr = err.Error()
			slog.Warn("Elasticsearch unhealthy", "error", err)
		}
	}

	storageErrStr := ""
	storageHealthy := true
	if err := hc.checkBlobStorageHealth(ctx); err != nil {
		storageHealthy = false
		storageErrStr = err.Error()
		slog.Warn("Blob Storage unhealthy", "error", err)
	}

	ehErrStr := ""
	ehHealthy := true
	if err := hc.checkEventHubHealth(ctx); err != nil {
		ehHealthy = false
		ehErrStr = err.Error()
		slog.Warn("Event Hub unhealthy", "error", err)
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()

	if os.Getenv("SEND_TO_ELASTIC") == "true" {
		if esHealthy {
			hc.esStatus = "healthy"
		} else {
			hc.esStatus = fmt.Sprintf("unhealthy: %s", esErrStr)
		}
	} else {
		hc.esStatus = "disabled"
	}

	if storageHealthy {
		hc.storageStatus = "healthy"
	} else {
		hc.storageStatus = fmt.Sprintf("unhealthy: %s", storageErrStr)
	}

	if ehHealthy {
		hc.eventHubStatus = "healthy"
	} else {
		hc.eventHubStatus = fmt.Sprintf("unhealthy: %s", ehErrStr)
	}

	allHealthy := (os.Getenv("SEND_TO_ELASTIC") != "true" || esHealthy) && storageHealthy && ehHealthy

	if hc.isReady != allHealthy && !allHealthy {
		slog.Warn("Application became unhealthy")
	} else if hc.isReady != allHealthy && allHealthy {
		slog.Info("Application became healthy")
	}

	hc.isReady = allHealthy
}

func (hc *HealthChecker) updateStatus(ready bool, errMsg string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if hc.isReady != ready && !ready {
		slog.Warn("Application became unhealthy", "error", errMsg)
	} else if hc.isReady != ready && ready {
		slog.Info("Application became healthy")
	}

	hc.isReady = ready
	hc.lastError = errMsg
}

func (hc *HealthChecker) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		hc.mu.RLock()
		ready := hc.isReady
		esStat := hc.esStatus
		storageStat := hc.storageStatus
		ehStat := hc.eventHubStatus
		hc.mu.RUnlock()

		response := HealthResponse{
			Status: func() string {
				if ready {
					return "healthy"
				}
				return "unhealthy"
			}(),
			Dependencies: []DependencyStatus{
				{Component: "elasticsearch", Status: esStat},
				{Component: "storage", Status: storageStat},
				{Component: "eventhub", Status: ehStat},
			},
		}

		w.Header().Set("Content-Type", "application/json")

		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(response)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})
}

func (hc *HealthChecker) checkElasticsearchHealth(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", hc.esClient.URL+"/_cluster/health", nil)
	if err != nil {
		return err
	}

	if hc.esClient.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", hc.esClient.APIKey))
	}

	resp, err := hc.esClient.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("elasticsearch health check failed with status code %d", resp.StatusCode)
	}

	return nil
}

func (hc *HealthChecker) checkBlobStorageHealth(ctx context.Context) error {
	client, err := azblob.NewClient(hc.storageURL, hc.creds, nil)
	if err != nil {
		return err
	}
	containerClient := client.ServiceClient().NewContainerClient(hc.container)
	_, err = containerClient.GetProperties(ctx, nil)
	return err
}

func (hc *HealthChecker) checkEventHubHealth(ctx context.Context) error {
	client, err := azeventhubs.NewConsumerClient(hc.namespace, hc.eventhub, "$Default", hc.creds, nil)
	if err != nil {
		return err
	}
	defer client.Close(ctx)

	_, err = client.GetEventHubProperties(ctx, nil)
	return err
}
