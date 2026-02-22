package infisical

import (
	"strings"

	"ssh-key-bootstrap/providers"
)

type provider struct{}

func init() {
	providers.RegisterProvider(provider{})
}

func (provider) Name() string {
	return "infisical"
}

func (provider) Supports(secretRef string) bool {
	return supportsSecretRef(secretRef)
}

func (provider) Resolve(secretRef string) (string, error) {
	secretRefSpec, err := parseSecretRef(secretRef)
	if err != nil {
		return "", err
	}
	return resolveWithInfisical(secretRefSpec)
}

func supportsSecretRef(secretRef string) bool {
	normalizedRef := strings.ToLower(strings.TrimSpace(secretRef))
	return strings.HasPrefix(normalizedRef, "infisical://") ||
		strings.HasPrefix(normalizedRef, "infisical:") ||
		strings.HasPrefix(normalizedRef, "inf://") ||
		strings.HasPrefix(normalizedRef, "inf:")
}
