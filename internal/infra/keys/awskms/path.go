package awskms

import (
	"errors"
	"fmt"

	"proteus/internal/domain"
)

// AWS Secrets Manager name format (env-scoped, tenant-scoped, purpose-scoped):
// proteus/{env}/tenants/{tenant_id}/keys/{purpose}/{kid}
const awsSecretNameFormat = "proteus/%s/tenants/%s/keys/%s/%s"

func secretName(env string, ref domain.KeyRef) (string, error) {
	if env == "" {
		return "", errors.New("PROTEUS_ENV is required")
	}
	if err := validateKeyRef(ref); err != nil {
		return "", err
	}
	return fmt.Sprintf(awsSecretNameFormat, env, ref.TenantID, ref.Purpose, ref.KID), nil
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
