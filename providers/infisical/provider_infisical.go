package infisical

import (
	"errors"
	"fmt"
	"net/url"
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

func parseSecretRef(secretRef string) (secretRefSpec, error) {
	body, err := parseSecretBody(secretRef)
	if err != nil {
		return secretRefSpec{}, err
	}

	secretNamePart := body
	queryString := ""
	if separatorIndex := strings.Index(body, "?"); separatorIndex >= 0 {
		secretNamePart = body[:separatorIndex]
		queryString = body[separatorIndex+1:]
	}

	secretName := strings.Trim(strings.TrimSpace(secretNamePart), "/")
	if secretName == "" {
		return secretRefSpec{}, errors.New("infisical secret ref is missing secret identifier")
	}

	queryValues, err := url.ParseQuery(queryString)
	if err != nil {
		return secretRefSpec{}, fmt.Errorf("invalid infisical secret ref query: %w", err)
	}

	return secretRefSpec{
		secretName: secretName,
		projectID: firstNonEmpty(
			strings.TrimSpace(queryValues.Get("projectId")),
			strings.TrimSpace(queryValues.Get("projectID")),
			strings.TrimSpace(queryValues.Get("workspaceId")),
			strings.TrimSpace(queryValues.Get("workspaceID")),
		),
		environment: firstNonEmpty(
			strings.TrimSpace(queryValues.Get("environment")),
			strings.TrimSpace(queryValues.Get("env")),
		),
	}, nil
}

func parseSecretBody(secretRef string) (string, error) {
	trimmedRef := strings.TrimSpace(secretRef)
	switch {
	case strings.HasPrefix(strings.ToLower(trimmedRef), "infisical://"):
		trimmedRef = trimmedRef[len("infisical://"):]
	case strings.HasPrefix(strings.ToLower(trimmedRef), "inf://"):
		trimmedRef = trimmedRef[len("inf://"):]
	case strings.HasPrefix(strings.ToLower(trimmedRef), "infisical:"):
		trimmedRef = trimmedRef[len("infisical:"):]
	case strings.HasPrefix(strings.ToLower(trimmedRef), "inf:"):
		trimmedRef = trimmedRef[len("inf:"):]
	default:
		return "", errors.New("invalid infisical secret ref")
	}

	trimmedRef = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(trimmedRef), "//"))
	if trimmedRef == "" {
		return "", errors.New("infisical secret ref is missing secret identifier")
	}
	return trimmedRef, nil
}
