package elasticsearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

type Client struct {
	URL        string
	APIKey     string
	HTTPClient *http.Client
}

type BulkResponse struct {
	Took   int                         `json:"took"`
	Errors bool                        `json:"errors"`
	Items  []map[string]map[string]any `json:"items"`
}

func NewClient(url, apiKey string) *Client {

	insecureSkipVerify := os.Getenv("ELASTIC_INSECURE_SKIP_VERIFY") == "true"

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			MinVersion:         tls.VersionTLS13,
		},
	}

	if insecureSkipVerify {
		slog.Warn("TLS certificate verification is disabled for Elasticsearch (ELASTIC_INSECURE_SKIP_VERIFY=true)")
	}

	return &Client{
		URL:    url,
		APIKey: apiKey,
		HTTPClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

func (c *Client) EnsureDataStreamTemplate(ctx context.Context) error {
	templateName := os.Getenv("ELASTIC_DATA_STREAM_TEMPLATE")
	if templateName == "" {
		slog.Error("Missing environment variable ELASTIC_DATA_STREAM_TEMPLATE")
		return fmt.Errorf("missing environment variable ELASTIC_DATA_STREAM_TEMPLATE")
	}

	url := fmt.Sprintf("%s/_index_template/%s", c.URL, templateName)

	templateBody := map[string]any{
		"index_patterns": []string{"logs-azure-firewall*"},
		"data_stream":    map[string]any{},
		"priority":       500,
	}

	bodyBytes, err := json.Marshal(templateBody)
	if err != nil {
		slog.Error("Failed to marshal JSON", "error", err)
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		slog.Error("Failed to create request", "error", err)
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", c.APIKey))
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		slog.Error("Failed to send request", "error", err)
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to send request", "status_code", resp.StatusCode, "body", string(body))
		return fmt.Errorf("failed to send request: %s", resp.Status)
	}

	slog.Info("Successfully created data stream template", "template", templateName)
	return nil
}

func (c *Client) SendBulk(ctx context.Context, indexName string, docs interface{}) error {
	var buffer bytes.Buffer
	bodyBytes, err := json.Marshal(docs)
	if err != nil {
		slog.Error("Failed to marshal JSON", "error", err)
		return err
	}

	var rawList []json.RawMessage
	if err := json.Unmarshal(bodyBytes, &rawList); err != nil {
		slog.Error("Failed to unmarshal JSON", "error", err)
		return err
	}

	if len(rawList) == 0 {
		return nil
	}

	metadataLine := fmt.Sprintf(`{"create":{"_index":"%s"}}`, indexName)
	for _, doc := range rawList {
		buffer.WriteString(metadataLine + "\n")
		buffer.Write(doc)
		buffer.WriteString("\n")
	}

	url := fmt.Sprintf("%s/_bulk", c.URL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, &buffer)
	if err != nil {
		slog.Error("Failed to create request", "error", err)
		return err
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	if c.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", c.APIKey))
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		slog.Error("Failed to send request", "error", err)
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to send request", "status_code", resp.StatusCode, "body", string(bodyBytes))
		return fmt.Errorf("failed to send request: %s", resp.Status)
	}

	var bulkResp BulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
		slog.Error("Failed to decode response", "error", err)
		return err
	}

	if bulkResp.Errors {
		errorItemsBytes, _ := json.Marshal(bulkResp.Items)
		slog.Error("Failed to send request", "error", string(errorItemsBytes))
		return fmt.Errorf("failed to send request: %s", string(errorItemsBytes))
	}

	slog.Info("Successfully Shipped batch to ElasticSearch", "index", indexName, "count", len(rawList))

	return nil
}
