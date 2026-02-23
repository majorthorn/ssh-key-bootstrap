package infisical

import (
	"strings"
	"testing"
	"time"
)

func setLookupEnvForTest(t *testing.T, values map[string]string) {
	t.Helper()
	originalLookupEnv := lookupEnv
	lookupEnv = func(key string) (string, bool) {
		value, exists := values[key]
		return value, exists
	}
	t.Cleanup(func() {
		lookupEnv = originalLookupEnv
	})
}

func TestLoadModeConfigDefaultsToCLI(t *testing.T) {
	t.Parallel()

	t.Run("unset mode", func(t *testing.T) {
		setLookupEnvForTest(t, map[string]string{})

		configuration, err := loadModeConfig()
		if err != nil {
			t.Fatalf("loadModeConfig() error = %v", err)
		}
		if configuration.mode != modeCLI {
			t.Fatalf("mode = %q, want %q", configuration.mode, modeCLI)
		}
		if configuration.cliBinary != defaultCLIBinary {
			t.Fatalf("cliBinary = %q, want %q", configuration.cliBinary, defaultCLIBinary)
		}
		if configuration.cliTimeout != defaultCLITimeout {
			t.Fatalf("cliTimeout = %s, want %s", configuration.cliTimeout, defaultCLITimeout)
		}
	})

	t.Run("empty mode", func(t *testing.T) {
		setLookupEnvForTest(t, map[string]string{"INFISICAL_MODE": "   "})

		configuration, err := loadModeConfig()
		if err != nil {
			t.Fatalf("loadModeConfig() error = %v", err)
		}
		if configuration.mode != modeCLI {
			t.Fatalf("mode = %q, want %q", configuration.mode, modeCLI)
		}
	})
}

func TestLoadModeConfigSelectsAPI(t *testing.T) {
	t.Parallel()

	setLookupEnvForTest(t, map[string]string{"INFISICAL_MODE": "api"})

	configuration, err := loadModeConfig()
	if err != nil {
		t.Fatalf("loadModeConfig() error = %v", err)
	}
	if configuration.mode != modeAPI {
		t.Fatalf("mode = %q, want %q", configuration.mode, modeAPI)
	}
}

func TestLoadModeConfigInvalidMode(t *testing.T) {
	t.Parallel()

	setLookupEnvForTest(t, map[string]string{"INFISICAL_MODE": "invalid"})

	_, err := loadModeConfig()
	if err == nil {
		t.Fatalf("expected invalid mode error")
	}
	if !strings.Contains(err.Error(), "INFISICAL_MODE") || !strings.Contains(err.Error(), "cli") || !strings.Contains(err.Error(), "api") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadModeConfigCLIBinaryAndTimeoutOverrides(t *testing.T) {
	t.Parallel()

	setLookupEnvForTest(t, map[string]string{
		"INFISICAL_MODE":        "cli",
		"INFISICAL_CLI_BIN":     "custom-infisical",
		"INFISICAL_CLI_TIMEOUT": "30s",
	})

	configuration, err := loadModeConfig()
	if err != nil {
		t.Fatalf("loadModeConfig() error = %v", err)
	}
	if configuration.cliBinary != "custom-infisical" {
		t.Fatalf("cliBinary = %q, want %q", configuration.cliBinary, "custom-infisical")
	}
	if configuration.cliTimeout != 30*time.Second {
		t.Fatalf("cliTimeout = %s, want %s", configuration.cliTimeout, 30*time.Second)
	}
}

func TestLoadModeConfigInvalidCLITimeout(t *testing.T) {
	t.Parallel()

	setLookupEnvForTest(t, map[string]string{
		"INFISICAL_MODE":        "cli",
		"INFISICAL_CLI_TIMEOUT": "not-a-duration",
	})

	_, err := loadModeConfig()
	if err == nil {
		t.Fatalf("expected invalid timeout error")
	}
	if !strings.Contains(err.Error(), "INFISICAL_CLI_TIMEOUT") {
		t.Fatalf("unexpected error: %v", err)
	}
}
