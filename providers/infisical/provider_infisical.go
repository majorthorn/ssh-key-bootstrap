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

	"ssh-key-bootstrap/providers"
)

const (
	defaultInfisicalAPIBaseURL = "https://api.infisical.com"
	infisicalRequestTimeout    = 10 * time.Second
	maxResponseBytes           = 1024 * 1024
)

type providerConfig struct {
	Token       string
	APIURL      string
	ProjectID   string
	Environment string
}

type secretRefInfo struct {
	secretName  string
	projectID   string
	environment string
}

type provider struct {
	httpClient   *http.Client
	envGet       func(string) string
	staticConfig providerConfig

	cacheMu sync.RWMutex
	cache   map[string]string
}

func init() {
	providers.RegisterProvider(newProvider())
}

func newProvider() *provider {
	return &provider{
		httpClient: &http.Client{Timeout: infisicalRequestTimeout},
		envGet:     os.Getenv,
		cache:      map[string]string{},
	}
}

func (providerInstance *provider) Name() string {
	return "infisical"
}

func (providerInstance *provider) Supports(secretRef string) bool {
	_, ok := stripInfisicalPrefix(strings.TrimSpace(secretRef))
	return ok
}

func (providerInstance *provider) Resolve(secretRef string) (string, error) {
	parsedRef, err := parseSecretRef(secretRef)
	if err != nil {
		return "", err
	}

	effectiveConfig := providerInstance.resolveEffectiveConfig(parsedRef)
	if strings.TrimSpace(effectiveConfig.Token) == "" {
		return "", errors.New("infisical token is required (set INFISICAL_TOKEN)")
	}
	if strings.TrimSpace(effectiveConfig.ProjectID) == "" {
		return "", errors.New("infisical project id is required (set INFISICAL_PROJECT_ID)")
	}
	if strings.TrimSpace(effectiveConfig.Environment) == "" {
		return "", errors.New("infisical environment is required (set INFISICAL_ENV or INFISICAL_ENVIRONMENT)")
	}

	cacheKey := buildCacheKey(parsedRef.secretName, effectiveConfig)
	if cachedSecret, ok := providerInstance.getCached(cacheKey); ok {
		return cachedSecret, nil
	}

	resolvedSecret, err := providerInstance.fetchSecret(parsedRef.secretName, effectiveConfig)
	if err != nil {
		return "", err
	}
	providerInstance.storeCached(cacheKey, resolvedSecret)
	return resolvedSecret, nil
}

func (providerInstance *provider) resolveEffectiveConfig(parsedRef secretRefInfo) providerConfig {
	effectiveConfig := providerInstance.staticConfig

	if providerInstance.envGet != nil {
		if token := strings.TrimSpace(providerInstance.envGet("INFISICAL_TOKEN")); token != "" {
			effectiveConfig.Token = token
		}
		if apiURL := strings.TrimSpace(providerInstance.envGet("INFISICAL_API_URL")); apiURL != "" {
			effectiveConfig.APIURL = apiURL
		}
		if projectID := strings.TrimSpace(providerInstance.envGet("INFISICAL_PROJECT_ID")); projectID != "" {
			effectiveConfig.ProjectID = projectID
		}
		if environment := strings.TrimSpace(providerInstance.envGet("INFISICAL_ENV")); environment != "" {
			effectiveConfig.Environment = environment
		}
		if environment := strings.TrimSpace(providerInstance.envGet("INFISICAL_ENVIRONMENT")); environment != "" {
			effectiveConfig.Environment = environment
		}
	}

	if parsedRef.projectID != "" {
		effectiveConfig.ProjectID = parsedRef.projectID
	}
	if parsedRef.environment != "" {
		effectiveConfig.Environment = parsedRef.environment
	}

	if strings.TrimSpace(effectiveConfig.APIURL) == "" {
		effectiveConfig.APIURL = defaultInfisicalAPIBaseURL
	}

	return effectiveConfig
}

func (providerInstance *provider) fetchSecret(secretName string, effectiveConfig providerConfig) (string, error) {
	endpointURL, err := buildSecretEndpoint(effectiveConfig.APIURL, secretName, effectiveConfig.ProjectID, effectiveConfig.Environment)
	if err != nil {
		return "", err
	}

	request, err := http.NewRequest(http.MethodGet, endpointURL, nil)
	if err != nil {
		return "", fmt.Errorf("create infisical request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+effectiveConfig.Token)
	request.Header.Set("Accept", "application/json")

	httpClient := providerInstance.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: infisicalRequestTimeout}
	}

	response, err := httpClient.Do(request) // #nosec G704 -- endpoint is operator-configured for Infisical deployments and validated as HTTPS
	if err != nil {
		return "", fmt.Errorf("infisical request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.CopyN(io.Discard, response.Body, maxResponseBytes)
		return "", fmt.Errorf("infisical API request failed with status %d", response.StatusCode)
	}

	limitedBody := io.LimitReader(response.Body, maxResponseBytes)
	var payload struct {
		SecretValue string `json:"secretValue"`
		Value       string `json:"value"`
		Secret      struct {
			SecretValue string `json:"secretValue"`
			Value       string `json:"value"`
		} `json:"secret"`
	}
	if decodeErr := json.NewDecoder(limitedBody).Decode(&payload); decodeErr != nil {
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

func buildSecretEndpoint(baseAPIURL, secretName, projectID, environment string) (string, error) {
	parsedBaseURL, err := url.Parse(strings.TrimSpace(baseAPIURL))
	if err != nil {
		return "", fmt.Errorf("invalid infisical API URL: %w", err)
	}
	if !strings.EqualFold(parsedBaseURL.Scheme, "https") {
		return "", errors.New("infisical API URL must use https")
	}

	trimmedPath := strings.TrimRight(parsedBaseURL.Path, "/")
	parsedBaseURL.Path = trimmedPath + "/api/v3/secrets/raw/" + url.PathEscape(secretName)

	query := parsedBaseURL.Query()
	query.Set("workspaceId", projectID)
	query.Set("environment", environment)
	parsedBaseURL.RawQuery = query.Encode()

	return parsedBaseURL.String(), nil
}

func parseSecretRef(secretRef string) (secretRefInfo, error) {
	trimmedRef := strings.TrimSpace(secretRef)
	body, ok := stripInfisicalPrefix(trimmedRef)
	if !ok {
		return secretRefInfo{}, fmt.Errorf("invalid infisical secret ref %q", secretRef)
	}

	body = strings.TrimSpace(body)
	body = strings.TrimPrefix(body, "//")

	secretPart := body
	queryString := ""
	if index := strings.Index(body, "?"); index >= 0 {
		secretPart = body[:index]
		queryString = body[index+1:]
	}

	secretName := strings.Trim(strings.TrimSpace(secretPart), "/")
	if secretName == "" {
		return secretRefInfo{}, errors.New("infisical secret ref is missing secret identifier")
	}

	queryValues, err := url.ParseQuery(queryString)
	if err != nil {
		return secretRefInfo{}, fmt.Errorf("invalid infisical secret ref query: %w", err)
	}

	return secretRefInfo{
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

func stripInfisicalPrefix(secretRef string) (string, bool) {
	prefixes := []string{"infisical://", "inf://", "infisical:", "inf:"}
	for _, prefix := range prefixes {
		if len(secretRef) < len(prefix) {
			continue
		}
		if strings.EqualFold(secretRef[:len(prefix)], prefix) {
			return secretRef[len(prefix):], true
		}
	}
	return "", false
}

func buildCacheKey(secretName string, effectiveConfig providerConfig) string {
	return strings.ToLower(strings.TrimSpace(effectiveConfig.APIURL)) + "|" +
		strings.TrimSpace(effectiveConfig.ProjectID) + "|" +
		strings.TrimSpace(effectiveConfig.Environment) + "|" +
		strings.TrimSpace(secretName)
}

func (providerInstance *provider) getCached(cacheKey string) (string, bool) {
	providerInstance.cacheMu.RLock()
	defer providerInstance.cacheMu.RUnlock()

	cachedSecret, ok := providerInstance.cache[cacheKey]
	return cachedSecret, ok
}

func (providerInstance *provider) storeCached(cacheKey, secretValue string) {
	providerInstance.cacheMu.Lock()
	defer providerInstance.cacheMu.Unlock()

	providerInstance.cache[cacheKey] = secretValue
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
