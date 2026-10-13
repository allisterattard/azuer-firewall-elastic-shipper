# Azure Firewall to Elasticsearch Log Shipper

![Go](https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A robust, production-grade Go application designed to consume modern diagnostic logs from Azure Firewall via Azure Event Hubs, process them, and stream them securely into Elasticsearch using data streams.

---

## Key Features

* **Modern Azure Firewall Log Ingestion:** Fully supports modern diagnostic categories (`AZFWNetworkRule`, `AZFWNatRule`, `AZFWApplicationRule`). *Note: Legacy diagnostic logs are not supported.*
* **Enterprise Security:** Supports Microsoft Entra ID (Client Secrets) or HashiCorp Vault AppRole integration for secure authentication to Azure and Elasticsearch.
* **Background Health Monitoring:** Implements an asynchronous background health checker (polling every 20 seconds) with thread-safe caching (`sync.RWMutex`) to prevent external API rate-limiting.
* **Kubernetes-Ready Endpoints:** Exposes lightweight `/livez` and structured JSON `/readyz` health endpoints with proper `503 ServiceUnavailable` handling and component-level status breakdowns.
* **Graceful Shutdowns:** Listens for `SIGINT` and `SIGTERM` signals to cleanly drain active connections, wrap up partitions, and stop ingestion pipelines without data loss.

---

## Architecture Overview

```text
[ Azure Firewall ] 
        │
        ▼
[ Azure Event Hub ] ◄── (Azure Blob Storage Checkpoint Store)
        │
        ▼
[ Go Application ] ──(Background Worker)──► Tests Health (EventHub, Blob, ES)
        │
        ├──► POST /readyz & /livez (JSON Health Probes)
        │
        └──► Ships Parsed Logs (via NDJSON Bulk API) ──► [ Elasticsearch Data Streams ]
```

## Environment Variables Reference
| Environment Variable | Required? | Description |
| :--- | :--- | :--- |
|`PORT` | No | HTTP server port for health and liveness endpoints (default: `8080`).|
| `SEND_TO_ELASTIC` |	No |	Set to `true` to ship logs to Elasticsearch; set to `false` to dry-run (print parsed logs to stdout).|
| `AZURE_EVENTHUB_NS` |	Yes |	Azure Event Hub Namespace name (e.g., `your-ns.servicebus.windows.net` or namespace prefix).|
| `AZURE_EVENTHUB_NAME` |	Yes |	Name of the Azure Event Hub instance containing the firewall logs.|
| `AZURE_STORAGE_ACCOUNT_URL` |	Yes |	Azure Blob Storage account URL for checkpointing (e.g., `https://<account>.blob.core.windows.net`).|
| `AZURE_STORAGE_ACCOUNT_CONTAINER` |	Yes	 | Blob container name used for storing Event Hub consumer checkpoints and health verification.|
| `ELASTIC_URL`	 | Yes (if `SEND_TO_ELASTIC=true`) |	Elasticsearch cluster endpoint URL.|
| `ELASTIC_API_KEY` |	Yes  (if direct ES auth) |	Elasticsearch API Key for authentication.|
| `ELASTIC_INSECURE_SKIP_VERIFY` |	No |	Set to `true` to disable TLS certificate verification for Elasticsearch.|
| `ELASTIC_DATA_STREAM_TEMPLATE` |	Yes (if `SEND_TO_ELASTIC=true`) |	Name of the Elasticsearch index template to ensure/create on startup.|
| `AZURE_CLIENT_ID` |	Conditional |	Azure Service Principal Client ID (required if not authenticating via Vault).|
| `AZURE_CLIENT_SECRET` |	Conditional |	Azure Service Principal Client Secret (required if not authenticating via Vault).|
| `AZURE_TENANT_ID` |	Conditional |	Azure Tenant ID (required if not authenticating via Vault).|
| `VAULT_ADDR` |	Conditional |	HashiCorp Vault server URL (required if using Vault AppRole).|
| `APPROLE_ROLE_ID` |	Conditional |	Vault AppRole Role ID for authentication.|
| `APPROLE_SECRET_ID` |	Conditional |	Vault AppRole Secret ID for authentication.|
| `VAULT_KV` |	Conditional |	Vault KV v2 mount path (required if using Vault).|
| `VAULT_SECRET_PATH` |	Conditional |	Vault secret path containing Azure and Elasticsearch credentials.|

## Important Notice: Legacy Log Incompatibility

This application is engineered specifically for modern Azure Firewall diagnostic settings.

- **Supported Categories:** AZFWNetworkRule, AZFWNatRule, AZFWApplicationRule.
- **Not Supported:** Legacy Azure Firewall diagnostic log formats (such as older event structures) are not supported and will result in parsing failures or empty schema fields. Ensure your Azure Firewall diagnostic settings are modern-enabled.

## Health Check & Observability Endpoints

- `GET /livez`

    - **Behavior:** Extremely lightweight check confirming the Go process is alive.
    - **Response:** Returns 200 OK with {"status": "alive"}.

- `GET /readyz`

    - **Behavior:** Reads cached statuses from the background health worker (runs every 20s) without hammering external APIs.
    - **Response (Healthy):** Returns 200 OK and a structured JSON breakdown:

    ```json
    {
      "status": "healthy",
      "dependencies": [
        { "component": "elasticsearch", "status": "healthy" },
        { "component": "storage", "status": "healthy" },
        { "component": "eventhub", "status": "healthy" }
      ]
    }
    ```

  - **Response (Unhealthy):** Returns 503 ServiceUnavailable with detailed component errors.

## Local Development & Testing

1. **Clone the repository:**

``` bash
git clone https://github.com/allisterattard/azuer-firewall-elastic-shipper.git
cd azure-firewall-elastic-shipper
```

2. **Configure environment variables:**
    
    Create a `.env` file or export your required variables (e.g., setting `SEND_TO_ELASTIC=false` for local dry-runs).


3. **Run the application:**

    ```bash
   go run main.go
    ```