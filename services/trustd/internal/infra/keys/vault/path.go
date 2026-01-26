package vault

import (
	"errors"
	"fmt"

	"proteus/internal/domain"
)

// Vault KV v2 path format (env-scoped, tenant-scoped, purpose-scoped):
// secret/data/proteus/{env}/tenants/{tenant_id}/keys/{purpose}/{kid}
// Stored fields: alg, public_key_base64, private_key_base64.
const vaultKVPathFormat = "secret/data/proteus/%s/tenants/%s/keys/%s/%s"

func vaultPath(env string, ref domain.KeyRef) (string, error) {
	if env == "" {
		return "", errors.New("PROTEUS_ENV is required")
	}
	if err := validateKeyRef(ref); err != nil {
		return "", err
	}
	return fmt.Sprintf(vaultKVPathFormat, env, ref.TenantID, ref.Purpose, ref.KID), nil
}

func validateKeyRef(ref domain.KeyRef) error {
	if ref.TenantID == "" || ref.KID == "" || ref.Purpose == "" {
		return errors.New("key ref is required")
	}
	switch ref.Purpose {
	case domain.KeyPurposeSigning, domain.KeyPurposeLog:
		return nil
	default:
		return errors.New("unsupported key purpose")
	}
}
