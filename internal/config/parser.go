package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxDotEnvLineBytes = 1024 * 1024

func parseDotEnvContent(dotEnvContent string) (map[string]string, error) {
	parsedValues := map[string]string{}
	lineScanner := bufio.NewScanner(strings.NewReader(normalizeLF(dotEnvContent)))
	lineScanner.Buffer(make([]byte, 0, 4096), maxDotEnvLineBytes)
	lineNumber := 0

	for lineScanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(lineScanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		separatorIndex := strings.Index(line, "=")
		if separatorIndex <= 0 {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", lineNumber)
		}

		key := strings.TrimSpace(line[:separatorIndex])
		if key == "" {
			return nil, fmt.Errorf("line %d: key is empty", lineNumber)
		}
		if !isValidDotEnvKey(key) {
			return nil, fmt.Errorf("line %d: invalid key %q", lineNumber, key)
		}

		rawValue := strings.TrimSpace(line[separatorIndex+1:])
		parsedValue, err := parseDotEnvValue(rawValue)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		parsedValues[strings.ToUpper(key)] = parsedValue
	}

	if err := lineScanner.Err(); err != nil {
		return nil, err
	}
	return parsedValues, nil
}

func collectNonEmptyDotEnvValues(values map[string]string, keys ...string) []string {
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		value, exists := values[key]
		if !exists {
			continue
		}
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func isValidDotEnvKey(key string) bool {
	if key == "" {
		return false
	}

	for index, character := range key {
		isUpper := character >= 'A' && character <= 'Z'
		isLower := character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		isUnderscore := character == '_'

		if index == 0 {
			if !(isUpper || isLower || isUnderscore) {
				return false
			}
			continue
		}

		if !(isUpper || isLower || isDigit || isUnderscore) {
			return false
		}
	}

	return true
}

func parseDotEnvValue(rawValue string) (string, error) {
	if rawValue == "" {
		return "", nil
	}
	if strings.HasPrefix(rawValue, `"`) {
		if !strings.HasSuffix(rawValue, `"`) || len(rawValue) == 1 {
			return "", errors.New("unterminated double-quoted value")
		}
		parsedValue, err := strconv.Unquote(rawValue)
		if err != nil {
			return "", fmt.Errorf("invalid double-quoted value: %w", err)
		}
		return parsedValue, nil
	}
	if strings.HasPrefix(rawValue, "'") {
		if !strings.HasSuffix(rawValue, "'") || len(rawValue) == 1 {
			return "", errors.New("unterminated single-quoted value")
		}
		return rawValue[1 : len(rawValue)-1], nil
	}
	// For unquoted values, treat '#' as the start of an inline comment.
	// To preserve '#' in values, use single or double quotes.
	if inlineCommentIndex := strings.Index(rawValue, "#"); inlineCommentIndex >= 0 {
		rawValue = rawValue[:inlineCommentIndex]
	}
	return strings.TrimSpace(rawValue), nil
}

func normalizeLF(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.ReplaceAll(value, "\r", "\n")
}

func expandHomePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}
