package bitwarden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const secretCommandTimeout = 10 * time.Second

func resolveWithBW(secretID string) (string, error) {
	commandOutput, err := runSecretCommand("bw", "get", "secret", secretID, "--raw")
	if err != nil {
		return "", err
	}
	resolvedValue := strings.TrimSpace(commandOutput)
	if resolvedValue == "" {
		return "", errors.New("bw returned an empty secret value")
	}
	return resolvedValue, nil
}

func resolveWithBWS(secretID string) (string, error) {
	commandOutput, err := runSecretCommand("bws", "secret", "get", secretID)
	if err != nil {
		return "", err
	}
	return parseBWSSecretOutput(commandOutput)
}

func parseBWSSecretOutput(commandOutput string) (string, error) {
	var response struct {
		Value string `json:"value"`
	}
	if jsonErr := json.Unmarshal([]byte(commandOutput), &response); jsonErr != nil {
		return "", fmt.Errorf("bws output was not valid JSON: %w", jsonErr)
	}

	if strings.TrimSpace(response.Value) == "" {
		return "", errors.New("bws JSON output did not include a non-empty value")
	}
	return strings.TrimSpace(response.Value), nil
}

func runSecretCommand(command string, args ...string) (string, error) {
	commandContext, cancel := context.WithTimeout(context.Background(), secretCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(commandContext, command, args...)
	commandOutput, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("command timed out after %s", secretCommandTimeout)
		}
		commandResult := strings.TrimSpace(string(commandOutput))
		if commandResult == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, commandResult)
	}
	return string(commandOutput), nil
}
