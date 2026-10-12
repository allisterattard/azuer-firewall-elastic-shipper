package vault

import (
	"azure-firewall-elastic-shipper/model"
	"context"
	"log"
	"log/slog"
	"os"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

func AuthFunc(roleId string, secretId string) model.AzureClientSecret {
	config := vault.DefaultConfig()
	config.Address = "https://vault-stg.ivatech.systems"
	client, err := vault.NewClient(config)
	if err != nil {
		slog.Error("unable to initialize vault client", "error", err)
		os.Exit(1)
	}

	vaultKV := os.Getenv("VAULT_KV")
	secretPath := os.Getenv("VAULT_SECRET_PATH")

	if vaultKV == "" || secretPath == "" {
		slog.Error("'vaultKV' and/or 'secretPath' were not set")
		os.Exit(1)
	}
	secretVaultId := &auth.SecretID{FromString: secretId}

	appRoleAuth, err := auth.NewAppRoleAuth(
		roleId,
		secretVaultId,
	)

	if err != nil {
		slog.Error("Unable to initialize AppRole auth method", "error", err)
		os.Exit(1)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		slog.Error("unable to login to AppRole auth method", "error", err)
		os.Exit(1)
	}
	if authInfo == nil {
		slog.Error("no auth info was returned after login")
		os.Exit(1)
	}
	secret, err := client.KVv2(vaultKV).Get(context.Background(), secretPath)
	if err != nil {
		log.Fatalf("unable to read secret: %v", err)
	}

	clientId, ok := secret.Data["AZURE_CLIENT_ID"].(string)
	if !ok {
		log.Fatalf("value type assertion failed: %T %#v", secret.Data["AZURE_CLIENT_ID"], secret.Data["AZURE_CLIENT_ID"])
	}

	clientSecret, ok := secret.Data["AZURE_CLIENT_SECRET"].(string)
	if !ok {
		log.Fatalf("value type assertion failed: %T %#v", secret.Data["AZURE_CLIENT_SECRET"], secret.Data["AZURE_CLIENT_SECRET"])
	}

	tenantId, ok := secret.Data["AZURE_TENANT_ID"].(string)
	if !ok {
		log.Fatalf("value type assertion failed: %T %#v", secret.Data["AZURE_TENANT_ID"], secret.Data["AZURE_TENANT_ID"])
	}
	slog.Info("auth via vault")
	return model.AzureClientSecret{ClientID: clientId, ClientSecret: clientSecret, TenantID: tenantId}
}
