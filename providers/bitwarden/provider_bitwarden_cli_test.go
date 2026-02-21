package bitwarden

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunBWSecretCommand(t *testing.T) {
	commandDirectory := t.TempDir()
	createFakeCommand(t, commandDirectory, "bw", `#!/bin/sh
if [ "$1" != "get" ] || [ "$2" != "secret" ] || [ "$3" != "secret-id" ] || [ "$4" != "--raw" ]; then
  echo "unexpected args" >&2
  exit 1
fi
printf "bw-secret-value"
`)
	t.Setenv("PATH", commandDirectory)

	commandOutput, err := runBWSecretCommand("secret-id")
	if err != nil {
		t.Fatalf("run bw command: %v", err)
	}
	if commandOutput != "bw-secret-value" {
		t.Fatalf("command output = %q, want %q", commandOutput, "bw-secret-value")
	}
}

func TestRunBWSSecretCommand(t *testing.T) {
	commandDirectory := t.TempDir()
	createFakeCommand(t, commandDirectory, "bws", `#!/bin/sh
if [ "$1" != "secret" ] || [ "$2" != "get" ] || [ "$3" != "secret-id" ]; then
  echo "unexpected args" >&2
  exit 1
fi
printf '{"value":"bws-secret-value"}'
`)
	t.Setenv("PATH", commandDirectory)

	commandOutput, err := runBWSSecretCommand("secret-id")
	if err != nil {
		t.Fatalf("run bws command: %v", err)
	}
	if commandOutput != `{"value":"bws-secret-value"}` {
		t.Fatalf("command output = %q, want %q", commandOutput, `{"value":"bws-secret-value"}`)
	}
}

func TestResolveWithBW(t *testing.T) {
	commandDirectory := t.TempDir()
	createFakeCommand(t, commandDirectory, "bw", `#!/bin/sh
printf "  resolved-secret  "
`)
	t.Setenv("PATH", commandDirectory)

	resolvedValue, err := resolveWithBW("secret-id")
	if err != nil {
		t.Fatalf("resolve with bw: %v", err)
	}
	if resolvedValue != "resolved-secret" {
		t.Fatalf("resolved value = %q, want %q", resolvedValue, "resolved-secret")
	}
}

func TestResolveWithBWS(t *testing.T) {
	commandDirectory := t.TempDir()
	createFakeCommand(t, commandDirectory, "bws", `#!/bin/sh
printf '{"value":"resolved-from-bws"}'
`)
	t.Setenv("PATH", commandDirectory)

	resolvedValue, err := resolveWithBWS("secret-id")
	if err != nil {
		t.Fatalf("resolve with bws: %v", err)
	}
	if resolvedValue != "resolved-from-bws" {
		t.Fatalf("resolved value = %q, want %q", resolvedValue, "resolved-from-bws")
	}
}

func TestRunAndCaptureOutput(t *testing.T) {
	t.Run("returns wrapped error when command has output", func(t *testing.T) {
		commandDirectory := t.TempDir()
		createFakeCommand(t, commandDirectory, "fail-with-output", `#!/bin/sh
echo "command failed" >&2
exit 1
`)

		commandContext := context.Background()
		cmd := exec.CommandContext(commandContext, filepath.Join(commandDirectory, "fail-with-output"))
		_, err := runAndCaptureOutput(commandContext, cmd)
		if err == nil {
			t.Fatalf("expected command failure")
		}
		if !strings.Contains(err.Error(), "command failed") {
			t.Fatalf("expected wrapped command output, got %v", err)
		}
	})

	t.Run("returns original error when command output is empty", func(t *testing.T) {
		commandDirectory := t.TempDir()
		createFakeCommand(t, commandDirectory, "fail-without-output", `#!/bin/sh
exit 1
`)

		commandContext := context.Background()
		cmd := exec.CommandContext(commandContext, filepath.Join(commandDirectory, "fail-without-output"))
		_, err := runAndCaptureOutput(commandContext, cmd)
		if err == nil {
			t.Fatalf("expected command failure")
		}
		if strings.Contains(err.Error(), ": ") {
			t.Fatalf("expected original error without wrapped output, got %v", err)
		}
	})

	t.Run("returns timeout error when context deadline is exceeded", func(t *testing.T) {
		commandDirectory := t.TempDir()
		createFakeCommand(t, commandDirectory, "slow-command", `#!/bin/sh
sleep 1
`)

		commandContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		cmd := exec.CommandContext(commandContext, filepath.Join(commandDirectory, "slow-command"))
		_, err := runAndCaptureOutput(commandContext, cmd)
		if err == nil {
			t.Fatalf("expected timeout error")
		}
		if !strings.Contains(err.Error(), "command timed out after") {
			t.Fatalf("expected timeout message, got %v", err)
		}
	})
}

func createFakeCommand(t *testing.T, directory, commandName, scriptBody string) {
	t.Helper()

	commandPath := filepath.Join(directory, commandName)
	writeErr := os.WriteFile(commandPath, []byte(scriptBody), 0o700)
	if writeErr != nil {
		t.Fatalf("write fake command %q: %v", commandName, writeErr)
	}
}
