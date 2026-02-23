package infisical

import (
	"fmt"
	"strings"

	"ssh-key-bootstrap/providers"
)

type provider struct{}

type modeProvider interface {
	Resolve(secretSpec secretRefSpec) (string, error)
}

type secretRefSpec struct {
	secretName  string
	projectID   string
	environment string
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
		strings.HasPrefix(normalizedRef, "infisical:") ||
		strings.HasPrefix(normalizedRef, "inf://") ||
		strings.HasPrefix(normalizedRef, "inf:")
}

func (provider) Resolve(secretRef string) (string, error) {
	secretSpec, err := parseSecretRef(secretRef)
	if err != nil {
		return "", err
	}

	providerInstance, err := newModeProvider()
	if err != nil {
		return "", err
	}

	return providerInstance.Resolve(secretSpec)
}

func newModeProvider() (modeProvider, error) {
	modeConfiguration, err := loadModeConfig()
	if err != nil {
		return nil, err
	}

	switch modeConfiguration.mode {
	case modeCLI:
		return newCLIProvider(modeConfiguration), nil
	case modeAPI:
		return apiProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported infisical mode %q", modeConfiguration.mode)
	}
}
