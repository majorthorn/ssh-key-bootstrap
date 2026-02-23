package infisical

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	infisicalsdk "github.com/infisical/go-sdk"
)

const defaultInfisicalSiteURL = "https://app.infisical.com"

type sdkRuntimeConfig struct {
	siteURL          string
	projectID        string
	environment      string
	clientID         string
	clientSecret     string
	organizationSlug string
}

type sdkRetrieveSecretOptions struct {
	secretKey   string
	projectID   string
	environment string
}

type infisicalSDKClient interface {
	LoginUniversalAuth(clientID, clientSecret, organizationSlug string) error
	RetrieveSecret(options sdkRetrieveSecretOptions) (string, error)
}

type infisicalSDKAdapter struct {
	client infisicalsdk.InfisicalClientInterface
}

type sdkProvider struct{}

var (
	envGetter = os.Getenv

	newInfisicalSDKClient = func(siteURL string) infisicalSDKClient {
		return &infisicalSDKAdapter{
			client: infisicalsdk.NewInfisicalClient(context.Background(), infisicalsdk.Config{SiteUrl: siteURL}),
		}
	}

	cacheMu     sync.RWMutex
	secretCache = map[string]string{}
)

func (sdkProvider) Resolve(secretSpec secretRefSpec) (string, error) {
	return resolveWithInfisicalSDK(secretSpec)
}

func resolveWithInfisicalSDK(secretSpec secretRefSpec) (string, error) {
	resolvedConfig, err := loadSDKRuntimeConfig(secretSpec)
	if err != nil {
		return "", err
	}

	cacheKey := buildCacheKey(resolvedConfig, secretSpec.secretName)
	if cachedSecret, ok := getCachedSecret(cacheKey); ok {
		return cachedSecret, nil
	}

	client := newInfisicalSDKClient(resolvedConfig.siteURL)
	if err := client.LoginUniversalAuth(
		resolvedConfig.clientID,
		resolvedConfig.clientSecret,
		resolvedConfig.organizationSlug,
	); err != nil {
		return "", err
	}

	secretValue, err := client.RetrieveSecret(sdkRetrieveSecretOptions{
		secretKey:   secretSpec.secretName,
		projectID:   resolvedConfig.projectID,
		environment: resolvedConfig.environment,
	})
	if err != nil {
		return "", err
	}

	storeCachedSecret(cacheKey, secretValue)
	return secretValue, nil
}

func loadSDKRuntimeConfig(secretSpec secretRefSpec) (sdkRuntimeConfig, error) {
	rawSiteURL := firstNonEmpty(
		strings.TrimSpace(envGetter("INFISICAL_SITE_URL")),
		strings.TrimSpace(envGetter("INFISICAL_API_URL")), // compatibility alias
		defaultInfisicalSiteURL,
	)
	normalizedSiteURL, err := normalizeInfisicalSiteURL(rawSiteURL)
	if err != nil {
		return sdkRuntimeConfig{}, err
	}

	resolvedConfig := sdkRuntimeConfig{
		siteURL:      normalizedSiteURL,
		clientID:     strings.TrimSpace(envGetter("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID")),
		clientSecret: strings.TrimSpace(envGetter("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")),
		projectID: firstNonEmpty(
			secretSpec.projectID,
			strings.TrimSpace(envGetter("INFISICAL_PROJECT_ID")),
		),
		environment: firstNonEmpty(
			secretSpec.environment,
			strings.TrimSpace(envGetter("INFISICAL_ENV")),
			strings.TrimSpace(envGetter("INFISICAL_ENVIRONMENT")),
		),
		organizationSlug: strings.TrimSpace(envGetter("INFISICAL_AUTH_ORGANIZATION_SLUG")),
	}

	if resolvedConfig.clientID == "" {
		return sdkRuntimeConfig{}, errors.New("infisical universal auth client id is required (set INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
	}
	if resolvedConfig.clientSecret == "" {
		return sdkRuntimeConfig{}, errors.New("infisical universal auth client secret is required (set INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")
	}
	if resolvedConfig.projectID == "" {
		return sdkRuntimeConfig{}, errors.New("infisical project id is required (set INFISICAL_PROJECT_ID)")
	}
	if resolvedConfig.environment == "" {
		return sdkRuntimeConfig{}, errors.New("infisical environment is required (set INFISICAL_ENV or INFISICAL_ENVIRONMENT)")
	}

	return resolvedConfig, nil
}

func (providerInstance *infisicalSDKAdapter) LoginUniversalAuth(clientID, clientSecret, organizationSlug string) error {
	authClient := providerInstance.client.Auth()
	if organizationSlug != "" {
		authClient = authClient.WithOrganizationSlug(organizationSlug)
	}

	_, err := authClient.UniversalAuthLogin(clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("infisical universal auth login failed: %w", err)
	}

	return nil
}

func (providerInstance *infisicalSDKAdapter) RetrieveSecret(options sdkRetrieveSecretOptions) (string, error) {
	secret, err := providerInstance.client.Secrets().Retrieve(infisicalsdk.RetrieveSecretOptions{
		SecretKey:   options.secretKey,
		ProjectID:   options.projectID,
		Environment: options.environment,
	})
	if err != nil {
		return "", fmt.Errorf("infisical secret retrieval failed: %w", err)
	}

	secretValue := strings.TrimSpace(secret.SecretValue)
	if secretValue == "" {
		return "", errors.New("infisical response did not contain a non-empty secret value")
	}

	return secretValue, nil
}

func normalizeInfisicalSiteURL(rawSiteURL string) (string, error) {
	parsedSiteURL, err := url.Parse(strings.TrimSpace(rawSiteURL))
	if err != nil {
		return "", fmt.Errorf("invalid infisical site url: %w", err)
	}
	if !strings.EqualFold(parsedSiteURL.Scheme, "https") {
		return "", errors.New("infisical site url must use https")
	}
	if strings.TrimSpace(parsedSiteURL.Host) == "" {
		return "", errors.New("infisical site url must include a host")
	}
	if parsedSiteURL.Path != "" && parsedSiteURL.Path != "/" {
		return "", errors.New("infisical site url must not include a path; set only the host (example: https://app.infisical.com)")
	}
	if parsedSiteURL.RawQuery != "" || parsedSiteURL.Fragment != "" || parsedSiteURL.User != nil {
		return "", errors.New("infisical site url must be a plain host URL without query, fragment, or user info")
	}

	return strings.TrimRight(parsedSiteURL.Scheme+"://"+parsedSiteURL.Host, "/"), nil
}

func buildCacheKey(resolvedConfig sdkRuntimeConfig, secretName string) string {
	return strings.ToLower(strings.TrimSpace(resolvedConfig.siteURL)) + "|" +
		resolvedConfig.projectID + "|" +
		resolvedConfig.environment + "|" +
		resolvedConfig.organizationSlug + "|" +
		resolvedConfig.clientID + "|" +
		strings.TrimSpace(secretName)
}

func getCachedSecret(cacheKey string) (string, bool) {
	cacheMu.RLock()
	defer cacheMu.RUnlock()

	cachedSecret, ok := secretCache[cacheKey]
	return cachedSecret, ok
}

func storeCachedSecret(cacheKey, secretValue string) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	secretCache[cacheKey] = secretValue
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
