package infisical

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type secretRefSpec struct {
	secretName  string
	projectID   string
	environment string
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
		return "", fmt.Errorf("invalid infisical secret ref %q", secretRef)
	}

	trimmedRef = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(trimmedRef), "//"))
	if trimmedRef == "" {
		return "", errors.New("infisical secret ref is missing secret identifier")
	}
	return trimmedRef, nil
}
