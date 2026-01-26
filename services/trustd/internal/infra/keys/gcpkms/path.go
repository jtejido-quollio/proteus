package gcpkms

import (
	"errors"
	"fmt"

	"proteus/internal/domain"
)

// GCP Secret Manager name format (env-scoped, tenant-scoped, purpose-scoped):
// proteus-{env}-{tenant_id}-{purpose}-{kid}
const gcpSecretNameFormat = "proteus-%s-%s-%s-%s"

func secretName(env string, ref domain.KeyRef) (string, error) {
	if env == "" {
		return "", errors.New("PROTEUS_ENV is required")
	}
	if err := validateKeyRef(ref); err != nil {
		return "", err
	}
	return fmt.Sprintf(gcpSecretNameFormat, env, ref.TenantID, ref.Purpose, ref.KID), nil
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
