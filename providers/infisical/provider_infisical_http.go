package infisical

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIURL       = "https://api.infisical.com"
	requestTimeout      = 10 * time.Second
	maxResponseBodySize = 1024 * 1024
)

type runtimeConfig struct {
	apiURL      string
	token       string
	projectID   string
	environment string
}

var (
	envGetter = os.Getenv

	httpClient = &http.Client{Timeout: requestTimeout}

	cacheMu     sync.RWMutex
	secretCache = map[string]string{}
)

func resolveWithInfisical(secretSpec secretRefSpec) (string, error) {
	resolvedConfig, err := loadRuntimeConfig(secretSpec)
	if err != nil {
		return "", err
	}

	cacheKey := buildCacheKey(resolvedConfig, secretSpec.secretName)
	if cachedSecret, ok := getCachedSecret(cacheKey); ok {
		return cachedSecret, nil
	}

	secretValue, err := requestSecretValue(secretSpec.secretName, resolvedConfig)
	if err != nil {
		return "", err
	}
	storeCachedSecret(cacheKey, secretValue)
	return secretValue, nil
}

func loadRuntimeConfig(secretSpec secretRefSpec) (runtimeConfig, error) {
	resolvedConfig := runtimeConfig{
		apiURL: strings.TrimSpace(envGetter("INFISICAL_API_URL")),
		token:  strings.TrimSpace(envGetter("INFISICAL_TOKEN")),
	}

	if resolvedConfig.apiURL == "" {
		resolvedConfig.apiURL = defaultAPIURL
	}

	resolvedConfig.projectID = firstNonEmpty(
		secretSpec.projectID,
		strings.TrimSpace(envGetter("INFISICAL_PROJECT_ID")),
	)
	resolvedConfig.environment = firstNonEmpty(
		secretSpec.environment,
		strings.TrimSpace(envGetter("INFISICAL_ENV")),
		strings.TrimSpace(envGetter("INFISICAL_ENVIRONMENT")),
	)

	if resolvedConfig.token == "" {
		return runtimeConfig{}, errors.New("infisical token is required (set INFISICAL_TOKEN)")
	}
	if resolvedConfig.projectID == "" {
		return runtimeConfig{}, errors.New("infisical project id is required (set INFISICAL_PROJECT_ID)")
	}
	if resolvedConfig.environment == "" {
		return runtimeConfig{}, errors.New("infisical environment is required (set INFISICAL_ENV or INFISICAL_ENVIRONMENT)")
	}

	return resolvedConfig, nil
}

func requestSecretValue(secretName string, resolvedConfig runtimeConfig) (string, error) {
	endpointURL, err := buildSecretEndpointURL(resolvedConfig, secretName)
	if err != nil {
		return "", err
	}

	request, err := http.NewRequest(http.MethodGet, endpointURL, nil)
	if err != nil {
		return "", fmt.Errorf("create infisical request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+resolvedConfig.token)
	request.Header.Set("Accept", "application/json")

	response, err := httpClient.Do(request) // #nosec G704 -- endpoint is operator-configured for Infisical deployments and validated as HTTPS
	if err != nil {
		return "", fmt.Errorf("infisical request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.CopyN(io.Discard, response.Body, maxResponseBodySize)
		return "", fmt.Errorf("infisical API request failed with status %d", response.StatusCode)
	}

	bodyReader := io.LimitReader(response.Body, maxResponseBodySize)
	var payload struct {
		SecretValue string `json:"secretValue"`
		Value       string `json:"value"`
		Secret      struct {
			SecretValue string `json:"secretValue"`
			Value       string `json:"value"`
		} `json:"secret"`
	}

	if decodeErr := json.NewDecoder(bodyReader).Decode(&payload); decodeErr != nil {
		return "", fmt.Errorf("decode infisical response: %w", decodeErr)
	}

	secretValue := firstNonEmpty(
		strings.TrimSpace(payload.SecretValue),
		strings.TrimSpace(payload.Value),
		strings.TrimSpace(payload.Secret.SecretValue),
		strings.TrimSpace(payload.Secret.Value),
	)
	if secretValue == "" {
		return "", errors.New("infisical response did not contain a non-empty secret value")
	}

	return secretValue, nil
}

func buildSecretEndpointURL(resolvedConfig runtimeConfig, secretName string) (string, error) {
	parsedBaseURL, err := url.Parse(strings.TrimSpace(resolvedConfig.apiURL))
	if err != nil {
		return "", fmt.Errorf("invalid infisical API URL: %w", err)
	}
	if !strings.EqualFold(parsedBaseURL.Scheme, "https") {
		return "", errors.New("infisical API URL must use https")
	}

	parsedBaseURL.Path = strings.TrimRight(parsedBaseURL.Path, "/") + "/api/v3/secrets/raw/" + url.PathEscape(secretName)
	query := parsedBaseURL.Query()
	query.Set("workspaceId", resolvedConfig.projectID)
	query.Set("environment", resolvedConfig.environment)
	parsedBaseURL.RawQuery = query.Encode()

	return parsedBaseURL.String(), nil
}

func buildCacheKey(resolvedConfig runtimeConfig, secretName string) string {
	return strings.ToLower(strings.TrimSpace(resolvedConfig.apiURL)) + "|" +
		resolvedConfig.projectID + "|" +
		resolvedConfig.environment + "|" +
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
