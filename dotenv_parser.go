package main

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func parseDotEnvContent(dotEnvContent string) (map[string]string, error) {
	parsedValues := map[string]string{}
	lineScanner := bufio.NewScanner(strings.NewReader(normalizeLF(dotEnvContent)))
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
	if inlineCommentIndex := strings.Index(rawValue, " #"); inlineCommentIndex >= 0 {
		rawValue = rawValue[:inlineCommentIndex]
	}
	return strings.TrimSpace(rawValue), nil
}
