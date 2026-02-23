package infisical

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCLIProviderMissingBinary(t *testing.T) {
	t.Parallel()

	providerInstance := cliProvider{
		binaryPath: "missing-bin",
		timeout:    10 * time.Second,
		lookPath: func(string) (string, error) {
			return "", errors.New("not found")
		},
		runCommand: func(context.Context, string, []string, []string) (string, string, error) {
			t.Fatalf("runCommand should not be called when binary is missing")
			return "", "", nil
		},
	}

	_, err := providerInstance.Resolve(secretRefSpec{secretName: "ssh-password", projectID: "project-1", environment: "dev"})
	if err == nil {
		t.Fatalf("expected missing binary error")
	}
	if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "binary") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCLIProviderMissingProjectID(t *testing.T) {
	t.Parallel()

	setEnvGetterForTest(t, map[string]string{})

	providerInstance := cliProvider{
		binaryPath: "infisical",
		timeout:    10 * time.Second,
		lookPath: func(string) (string, error) {
			return "/usr/bin/infisical", nil
		},
		runCommand: func(context.Context, string, []string, []string) (string, string, error) {
			t.Fatalf("runCommand should not be called when project id is missing")
			return "", "", nil
		},
	}

	_, err := providerInstance.Resolve(secretRefSpec{secretName: "ssh-password", environment: "dev"})
	if err == nil {
		t.Fatalf("expected missing project id error")
	}
	if !strings.Contains(err.Error(), "INFISICAL_PROJECT_ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCLIProviderUsesEnvFallbacks(t *testing.T) {
	t.Parallel()

	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_PROJECT_ID": "project-from-env",
		"INFISICAL_ENV":        "env-from-env",
	})

	providerInstance := cliProvider{
		binaryPath: "infisical",
		timeout:    10 * time.Second,
		lookPath: func(string) (string, error) {
			return "/usr/bin/infisical", nil
		},
		runCommand: func(_ context.Context, _ string, args []string, _ []string) (string, string, error) {
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--workspaceId project-from-env") {
				t.Fatalf("expected project id from env, args: %v", args)
			}
			if !strings.Contains(joined, "--env env-from-env") {
				t.Fatalf("expected env from INFISICAL_ENV, args: %v", args)
			}
			return "resolved-secret", "", nil
		},
	}

	secretValue, err := providerInstance.Resolve(secretRefSpec{secretName: "ssh-password"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if secretValue != "resolved-secret" {
		t.Fatalf("secretValue = %q, want %q", secretValue, "resolved-secret")
	}
}

func TestCLIProviderResolveSuccess(t *testing.T) {
	t.Parallel()

	providerInstance := cliProvider{
		binaryPath: "infisical",
		timeout:    10 * time.Second,
		lookPath: func(file string) (string, error) {
			if file != "infisical" {
				t.Fatalf("unexpected binary lookup: %q", file)
			}
			return "/usr/bin/infisical", nil
		},
		runCommand: func(_ context.Context, binary string, args []string, env []string) (string, string, error) {
			if binary != "infisical" {
				t.Fatalf("binary = %q, want %q", binary, "infisical")
			}
			if len(env) != 0 {
				t.Fatalf("expected no extra env overrides, got %v", env)
			}
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "secrets get ssh-password") {
				t.Fatalf("unexpected args: %v", args)
			}
			if !strings.Contains(joined, "--workspaceId project-1") {
				t.Fatalf("missing project arg: %v", args)
			}
			if !strings.Contains(joined, "--env dev") {
				t.Fatalf("missing env arg: %v", args)
			}
			return "resolved-secret\n", "", nil
		},
	}

	secretValue, err := providerInstance.Resolve(secretRefSpec{secretName: "ssh-password", projectID: "project-1", environment: "dev"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if secretValue != "resolved-secret" {
		t.Fatalf("secretValue = %q, want %q", secretValue, "resolved-secret")
	}
}

func TestCLIProviderResolveErrorDoesNotIncludeStderr(t *testing.T) {
	t.Parallel()

	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_PROJECT_ID": "project-1",
		"INFISICAL_ENV":        "dev",
	})

	providerInstance := cliProvider{
		binaryPath: "infisical",
		timeout:    10 * time.Second,
		lookPath: func(string) (string, error) {
			return "/usr/bin/infisical", nil
		},
		runCommand: func(context.Context, string, []string, []string) (string, string, error) {
			return "", "permission denied", errors.New("exit status 1")
		},
	}

	_, err := providerInstance.Resolve(secretRefSpec{secretName: "ssh-password", projectID: "project-1", environment: "dev"})
	if err == nil {
		t.Fatalf("expected command failure")
	}
	if strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("stderr should not be included in returned error, got %v", err)
	}
	if !strings.Contains(err.Error(), "infisical CLI command failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
