package infisical

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const infisicalRefFormatErr = "invalid secret reference format: expected infisical://<value> or inf://<value>"

func parseSecretRef(secretRef string) (secretRefSpec, error) {
	baseRef, rawQuery, err := splitSchemeAndQuery(secretRef)
	if err != nil {
		return secretRefSpec{}, err
	}

	secretName := strings.TrimSpace(baseRef)
	if secretName == "" {
		return secretRefSpec{}, errors.New("infisical secret ref is missing secret identifier")
	}

	parsedQuery, err := url.ParseQuery(rawQuery)
	if err != nil {
		return secretRefSpec{}, fmt.Errorf("invalid infisical secret ref query: %w", err)
	}

	return secretRefSpec{
		secretName:  secretName,
		projectID:   firstNonEmpty(parsedQuery.Get("projectId"), parsedQuery.Get("projectID"), parsedQuery.Get("workspaceId"), parsedQuery.Get("workspaceID")),
		environment: firstNonEmpty(parsedQuery.Get("environment"), parsedQuery.Get("env")),
	}, nil
}

func splitSchemeAndQuery(secretRef string) (string, string, error) {
	trimmedRef := strings.TrimSpace(secretRef)
	switch {
	case strings.HasPrefix(strings.ToLower(trimmedRef), "infisical://"):
		trimmedRef = trimmedRef[len("infisical://"):]
	case strings.HasPrefix(strings.ToLower(trimmedRef), "inf://"):
		trimmedRef = trimmedRef[len("inf://"):]
	default:
		return "", "", errors.New(infisicalRefFormatErr)
	}

	trimmedRef = strings.TrimSpace(trimmedRef)
	if trimmedRef == "" {
		return "", "", errors.New("infisical secret ref is missing secret identifier")
	}

	queryIndex := strings.Index(trimmedRef, "?")
	if queryIndex == -1 {
		return trimmedRef, "", nil
	}

	baseRef := strings.TrimSpace(trimmedRef[:queryIndex])
	if baseRef == "" {
		return "", "", errors.New("infisical secret ref is missing secret identifier")
	}

	return baseRef, trimmedRef[queryIndex+1:], nil
}
