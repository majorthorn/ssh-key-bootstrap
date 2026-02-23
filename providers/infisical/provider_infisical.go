package infisical

import (
	"strings"

	"ssh-key-bootstrap/providers"
)

type provider struct{}

type secretRefSpec struct {
	secretName  string
	projectID   string
	environment string
}

type infisicalResolver interface {
	Resolve(secretSpec secretRefSpec) (string, error)
}

var newInfisicalResolver = func() infisicalResolver {
	return sdkProvider{}
}

func init() {
	providers.RegisterProvider(provider{})
}

func (provider) Name() string {
	return "infisical"
}

func (provider) Supports(secretRef string) bool {
	normalizedRef := strings.ToLower(strings.TrimSpace(secretRef))
	return strings.HasPrefix(normalizedRef, "infisical://") ||
		strings.HasPrefix(normalizedRef, "inf://")
}

func (provider) Resolve(secretRef string) (string, error) {
	secretSpec, err := parseSecretRef(secretRef)
	if err != nil {
		return "", err
	}

	return newInfisicalResolver().Resolve(secretSpec)
}
