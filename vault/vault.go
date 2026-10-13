package vault

import (
	"azure-firewall-elastic-shipper/model"
	"context"
	"log/slog"
	"os"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

func NewClient(roleId string, secretId string) *vault.Client {
	config := vault.DefaultConfig()
	config.Address = os.Getenv("VAULT_ADDR")
	if config.Address == "" {
		slog.Error("env var VAULT_ADDR needs to be set")
		os.Exit(1)
	}
	client, err := vault.NewClient(config)
	if err != nil {
		slog.Error("Failed to create Vault client", "error", err)
		os.Exit(1)
	}

	secretVaultId := &auth.SecretID{FromString: secretId}
	appRoleAuth, err := auth.NewAppRoleAuth(roleId, secretVaultId)
	if err != nil {
		slog.Error("Failed to create AppRole auth method", "error", err)
		os.Exit(1)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		slog.Error("Failed to authenticate with Vault", "error", err)
		os.Exit(1)
	}

	if authInfo == nil {
		slog.Error("Failed to authenticate with Vault")
		os.Exit(1)
	}

	slog.Info("Successfully authenticated with Vault")
	return client
}

func GetSecretData(client *vault.Client) map[string]any {
	vaultKV := os.Getenv("VAULT_KV")
	secretPath := os.Getenv("VAULT_SECRET_PATH")

	if vaultKV == "" || secretPath == "" {
		slog.Error("env var VAULT_KV and VAULT_SECRET_PATH need to be set")
		os.Exit(1)
	}

	secret, err := client.KVv2(vaultKV).Get(context.Background(), secretPath)
	if err != nil {
		slog.Error("Failed to get secret from Vault", "error", err)
		os.Exit(1)
	}
	if secret == nil || secret.Data == nil {
		slog.Error("Failed to get secret from Vault")
		os.Exit(1)
	}

	return secret.Data
}

func GetAzureSecrets(data map[string]any) model.AzureClientSecret {
	clientId, ok := data["AZURE_CLIENT_ID"].(string)
	if !ok {
		slog.Error("AZURE_CLIENT_ID not found in Vault secret")
		os.Exit(1)
	}

	clientSecret, ok := data["AZURE_CLIENT_SECRET"].(string)
	if !ok {
		slog.Error("AZURE_CLIENT_SECRET not found in Vault secret")
		os.Exit(1)
	}

	tenantId, ok := data["AZURE_TENANT_ID"].(string)
	if !ok {
		slog.Error("AZURE_TENANT_ID not found in Vault secret")
		os.Exit(1)
	}

	return model.AzureClientSecret{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		TenantID:     tenantId,
	}
}

func GetElasticApiKey(data map[string]any) string {

	elasticApiKey, ok := data["ELASTIC_API_KEY"].(string)
	if !ok {
		slog.Error("ELASTIC_API_KEY not found in Vault secret")
		os.Exit(1)
	}

	return elasticApiKey
}
