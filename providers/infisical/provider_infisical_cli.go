package infisical

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type commandRunner func(ctx context.Context, binary string, args []string, env []string) (string, string, error)

type cliProvider struct {
	binaryPath string
	timeout    time.Duration
	lookPath   func(file string) (string, error)
	runCommand commandRunner
}

func newCLIProvider(modeConfiguration modeConfig) cliProvider {
	return cliProvider{
		binaryPath: modeConfiguration.cliBinary,
		timeout:    modeConfiguration.cliTimeout,
		lookPath:   exec.LookPath,
		runCommand: runCLICommand,
	}
}

func (providerInstance cliProvider) Resolve(secretSpec secretRefSpec) (string, error) {
	if _, err := providerInstance.lookPath(providerInstance.binaryPath); err != nil {
		return "", fmt.Errorf("infisical CLI binary %q not found in PATH (set INFISICAL_CLI_BIN to override)", providerInstance.binaryPath)
	}

	commandContext, cancel := context.WithTimeout(context.Background(), providerInstance.timeout)
	defer cancel()

	commandArgs := []string{
		"secrets",
		"get",
		secretSpec.secretName,
		"--workspaceId", secretSpec.projectID,
		"--env", secretSpec.environment,
		"--plain",
	}

	stdout, stderr, err := providerInstance.runCommand(commandContext, providerInstance.binaryPath, commandArgs, nil)
	if err != nil {
		stderr = strings.TrimSpace(stderr)
		if stderr == "" {
			return "", fmt.Errorf("infisical CLI command failed: %w", err)
		}
		return "", fmt.Errorf("infisical CLI command failed: %w: %s", err, stderr)
	}

	secretValue := strings.TrimSpace(stdout)
	if secretValue == "" {
		return "", errors.New("infisical CLI returned an empty secret value")
	}
	return secretValue, nil
}

func runCLICommand(commandContext context.Context, binary string, args []string, env []string) (string, string, error) {
	command := exec.CommandContext(commandContext, binary, args...) // #nosec G204 -- fixed binary path and arg array, no shell evaluation
	if len(env) > 0 {
		command.Env = append(command.Env, env...)
	}

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer

	err := command.Run()
	return stdoutBuffer.String(), stderrBuffer.String(), err
}
