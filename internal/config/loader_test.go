package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type scriptedRuntimeIO struct {
	interactive bool
	answers     []string
	promptErr   error
	promptCalls int
	printlns    []string
	printfs     []string
}

func (runtime *scriptedRuntimeIO) PromptLine(label string) (string, error) {
	runtime.promptCalls++
	if runtime.promptErr != nil {
		return "", runtime.promptErr
	}
	if len(runtime.answers) == 0 {
		return "", nil
	}
	answer := runtime.answers[0]
	runtime.answers = runtime.answers[1:]
	return answer, nil
}

func (runtime *scriptedRuntimeIO) Println(arguments ...any) {
	runtime.printlns = append(runtime.printlns, fmt.Sprint(arguments...))
}

func (runtime *scriptedRuntimeIO) Printf(format string, arguments ...any) {
	runtime.printfs = append(runtime.printfs, fmt.Sprintf(format, arguments...))
}

func (runtime *scriptedRuntimeIO) IsInteractive() bool {
	return runtime.interactive
}

func TestResolveDotEnvSourceExplicitPath(t *testing.T) {
	t.Parallel()

	runtime := &scriptedRuntimeIO{interactive: true}
	opts := &Options{EnvFile: "  /tmp/custom.env  "}

	path, err := resolveDotEnvSource(opts, runtime)
	if err != nil {
		t.Fatalf("resolveDotEnvSource() error = %v", err)
	}
	if path != "/tmp/custom.env" {
		t.Fatalf("resolveDotEnvSource() = %q, want %q", path, "/tmp/custom.env")
	}
}

func TestResolveDotEnvSourceNonInteractiveWithoutExplicit(t *testing.T) {
	t.Parallel()

	runtime := &scriptedRuntimeIO{interactive: false}
	opts := &Options{}

	path, err := resolveDotEnvSource(opts, runtime)
	if err != nil {
		t.Fatalf("resolveDotEnvSource() error = %v", err)
	}
	if path != "" {
		t.Fatalf("resolveDotEnvSource() = %q, want empty", path)
	}
}

func TestPromptUseSingleConfigSourceYesAfterRetry(t *testing.T) {
	t.Parallel()

	runtime := &scriptedRuntimeIO{answers: []string{"maybe", "y"}}

	use, err := promptUseSingleConfigSource(runtime, ".env", "/tmp/.env")
	if err != nil {
		t.Fatalf("promptUseSingleConfigSource() error = %v", err)
	}
	if !use {
		t.Fatalf("promptUseSingleConfigSource() = false, want true")
	}
	if runtime.promptCalls != 2 {
		t.Fatalf("prompt calls = %d, want %d", runtime.promptCalls, 2)
	}
	if len(runtime.printlns) != 1 || runtime.printlns[0] != "Please answer with y or n." {
		t.Fatalf("unexpected prompt retry output: %v", runtime.printlns)
	}
}

func TestPromptUseSingleConfigSourceNo(t *testing.T) {
	t.Parallel()

	runtime := &scriptedRuntimeIO{answers: []string{"no"}}

	use, err := promptUseSingleConfigSource(runtime, ".env", "/tmp/.env")
	if err != nil {
		t.Fatalf("promptUseSingleConfigSource() error = %v", err)
	}
	if use {
		t.Fatalf("promptUseSingleConfigSource() = true, want false")
	}
}

func TestPromptUseSingleConfigSourcePromptError(t *testing.T) {
	t.Parallel()

	runtime := &scriptedRuntimeIO{promptErr: errors.New("input failed")}

	_, err := promptUseSingleConfigSource(runtime, ".env", "/tmp/.env")
	if err == nil {
		t.Fatalf("expected prompt error")
	}
	if !strings.Contains(err.Error(), "input failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyFilesExplicitEnvFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dotEnvPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(dotEnvPath, []byte("USER=env-user\nPASSWORD=env-password\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	runtime := &scriptedRuntimeIO{interactive: true}
	opts := &Options{EnvFile: dotEnvPath}

	if err := ApplyFiles(opts, runtime); err != nil {
		t.Fatalf("ApplyFiles() error = %v", err)
	}
	if opts.User != "env-user" {
		t.Fatalf("User = %q, want %q", opts.User, "env-user")
	}
	if opts.Password != "env-password" {
		t.Fatalf("Password = %q, want %q", opts.Password, "env-password")
	}
	if len(runtime.printlns) == 0 {
		t.Fatalf("expected interactive summary output")
	}
	if len(runtime.printfs) == 0 {
		t.Fatalf("expected field preview output")
	}
}

func TestApplyFilesNonInteractiveNoSource(t *testing.T) {
	t.Parallel()

	runtime := &scriptedRuntimeIO{interactive: false}
	opts := &Options{}

	if err := ApplyFiles(opts, runtime); err != nil {
		t.Fatalf("ApplyFiles() error = %v", err)
	}
	if opts.EnvFile != "" {
		t.Fatalf("EnvFile = %q, want empty", opts.EnvFile)
	}
}

func TestFileExists(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "config.env")
	if err := os.WriteFile(filePath, []byte("USER=test\n"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	if !fileExists(filePath) {
		t.Fatalf("fileExists(file) = false, want true")
	}
	if fileExists(dir) {
		t.Fatalf("fileExists(dir) = true, want false")
	}
	if fileExists(filepath.Join(dir, "missing.env")) {
		t.Fatalf("fileExists(missing) = true, want false")
	}
}

func TestDiscoverConfigFileNearBinary(t *testing.T) {
	t.Parallel()

	path, err := discoverConfigFileNearBinary()
	if err != nil {
		t.Fatalf("discoverConfigFileNearBinary() error = %v", err)
	}
	if path != "" {
		if !strings.HasSuffix(path, defaultBinaryDotEnvFilename) {
			t.Fatalf("discoverConfigFileNearBinary() path %q does not end with %q", path, defaultBinaryDotEnvFilename)
		}
		if !fileExists(path) {
			t.Fatalf("discoverConfigFileNearBinary() returned non-existent file: %q", path)
		}
	}
}

func ensureDotEnvNearBinary(t *testing.T, content string) string {
	t.Helper()

	executablePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}

	dotEnvPath := filepath.Join(filepath.Dir(executablePath), defaultBinaryDotEnvFilename)
	originalBytes, readErr := os.ReadFile(dotEnvPath)
	if readErr == nil {
		t.Cleanup(func() {
			_ = os.WriteFile(dotEnvPath, originalBytes, 0o600)
		})
		return dotEnvPath
	}

	if writeErr := os.WriteFile(dotEnvPath, []byte(content), 0o600); writeErr != nil {
		t.Skipf("cannot create %q in this environment: %v", dotEnvPath, writeErr)
	}
	t.Cleanup(func() { _ = os.Remove(dotEnvPath) })
	return dotEnvPath
}

func TestResolveDotEnvSourceInteractiveDiscovery(t *testing.T) {
	dotEnvPath := ensureDotEnvNearBinary(t, "USER=discover\n")

	t.Run("accepts discovered dot env", func(testContext *testing.T) {
		runtime := &scriptedRuntimeIO{interactive: true, answers: []string{"y"}}
		opts := &Options{}

		path, err := resolveDotEnvSource(opts, runtime)
		if err != nil {
			testContext.Fatalf("resolveDotEnvSource() error = %v", err)
		}
		if path != dotEnvPath {
			testContext.Fatalf("resolveDotEnvSource() = %q, want %q", path, dotEnvPath)
		}
		if runtime.promptCalls != 1 {
			testContext.Fatalf("prompt calls = %d, want 1", runtime.promptCalls)
		}
	})

	t.Run("rejects discovered dot env", func(testContext *testing.T) {
		runtime := &scriptedRuntimeIO{interactive: true, answers: []string{"n"}}
		opts := &Options{}

		path, err := resolveDotEnvSource(opts, runtime)
		if err != nil {
			testContext.Fatalf("resolveDotEnvSource() error = %v", err)
		}
		if path != "" {
			testContext.Fatalf("resolveDotEnvSource() = %q, want empty", path)
		}
		if runtime.promptCalls != 1 {
			testContext.Fatalf("prompt calls = %d, want 1", runtime.promptCalls)
		}
	})
}
