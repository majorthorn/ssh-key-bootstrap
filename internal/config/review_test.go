package config

import (
	"fmt"
	"strings"
	"testing"
)

type testRuntimeIO struct {
	lines []string
}

func (runtimeIO *testRuntimeIO) PromptLine(string) (string, error) { return "", nil }
func (runtimeIO *testRuntimeIO) Println(arguments ...any) {
	runtimeIO.lines = append(runtimeIO.lines, fmt.Sprintln(arguments...))
}
func (runtimeIO *testRuntimeIO) Printf(format string, arguments ...any) {
	runtimeIO.lines = append(runtimeIO.lines, fmt.Sprintf(format, arguments...))
}
func (*testRuntimeIO) IsInteractive() bool { return true }

func TestConfirmLoadedConfigFieldsNoLoadedValues(t *testing.T) {
	t.Parallel()

	programOptions := &Options{}
	runtimeIO := &testRuntimeIO{}

	confirmLoadedConfigFields(programOptions, map[string]bool{}, runtimeIO)

	if len(runtimeIO.lines) != 0 {
		t.Fatalf("expected no output for no loaded values, got %q", strings.Join(runtimeIO.lines, ""))
	}
}

func TestConfirmLoadedConfigFieldsLoadedValues(t *testing.T) {
	t.Parallel()

	programOptions := &Options{
		Server:   "app01",
		Port:     22,
		Password: "super-secret",
	}
	runtimeIO := &testRuntimeIO{}

	confirmLoadedConfigFields(programOptions, map[string]bool{
		"server":   true,
		"port":     true,
		"password": true,
	}, runtimeIO)

	output := strings.Join(runtimeIO.lines, "")
	if !strings.Contains(output, "Loaded configuration values:\n") {
		t.Fatalf("expected header in output, got %q", output)
	}
	if !strings.Contains(output, "Server: app01\n") {
		t.Fatalf("expected server line in output, got %q", output)
	}
	if !strings.Contains(output, "Default Port: 22\n") {
		t.Fatalf("expected port line in output, got %q", output)
	}
	if !strings.Contains(output, "SSH Password: <redacted>\n") {
		t.Fatalf("expected redacted password in output, got %q", output)
	}
}

func TestPreviewHelpers(t *testing.T) {
	t.Parallel()

	if got := previewTextValue("", 10); got != "<empty>" {
		t.Fatalf("previewTextValue(empty) = %q, want %q", got, "<empty>")
	}
	if got := previewTextValue("abcdefghijk", 5); got != "abcde..." {
		t.Fatalf("previewTextValue(truncate) = %q, want %q", got, "abcde...")
	}
	if got := maskSensitiveValue("abcd"); got != "<redacted>" {
		t.Fatalf("maskSensitiveValue = %q, want %q", got, "<redacted>")
	}
	if got := maskSensitiveValue("a"); got != "<redacted>" {
		t.Fatalf("maskSensitiveValue(short) = %q, want %q", got, "<redacted>")
	}
	if got := maskSensitiveValue(""); got != "<empty>" {
		t.Fatalf("maskSensitiveValue(empty) = %q, want %q", got, "<empty>")
	}

	programOptions := &Options{
		Password: "super-secret",
		KeyInput: strings.Repeat("k", 150),
		Server:   "host01",
	}

	passwordPreview := previewFieldValue(configField{
		kind: "password",
		get:  func(optionsValue *Options) string { return optionsValue.Password },
	}, programOptions)
	if passwordPreview != "<redacted>" {
		t.Fatalf("password preview not redacted: %q", passwordPreview)
	}

	keyPreview := previewFieldValue(configField{
		kind: "publickey",
		get:  func(optionsValue *Options) string { return optionsValue.KeyInput },
	}, programOptions)
	if keyPreview != "<redacted>" {
		t.Fatalf("public key preview should be redacted: %q", keyPreview)
	}

	textPreview := previewFieldValue(configField{
		kind: "text",
		get:  func(optionsValue *Options) string { return optionsValue.Server },
	}, programOptions)
	if textPreview != "host01" {
		t.Fatalf("text preview = %q, want %q", textPreview, "host01")
	}
}

func TestConfigFieldsMetadataAndGetters(t *testing.T) {
	t.Parallel()

	fields := configFields()
	if len(fields) == 0 {
		t.Fatalf("configFields() returned no fields")
	}

	optionsValue := &Options{
		Server:                "server-01",
		Servers:               "server-01,server-02",
		User:                  "deploy",
		Password:              "secret",
		PasswordSecretRef:     "bw://secret-id",
		KeyInput:              "ssh-ed25519 AAAATEST",
		Port:                  2222,
		TimeoutSec:            30,
		InsecureIgnoreHostKey: true,
		KnownHosts:            "~/.ssh/known_hosts",
	}

	expectedKeys := map[string]bool{
		"server":                true,
		"servers":               true,
		"user":                  true,
		"password":              true,
		"passwordSecretRef":     true,
		"keyInput":              true,
		"port":                  true,
		"timeoutSec":            true,
		"insecureIgnoreHostKey": true,
		"knownHosts":            true,
	}

	for _, field := range fields {
		if field.key == "" {
			t.Fatalf("field key must not be empty: %+v", field)
		}
		if field.label == "" {
			t.Fatalf("field label must not be empty: %+v", field)
		}
		if field.kind == "" {
			t.Fatalf("field kind must not be empty: %+v", field)
		}
		if field.get == nil {
			t.Fatalf("field getter must not be nil: %+v", field)
		}

		expectedKeys[field.key] = false
		_ = field.get(optionsValue)
	}

	for key, missing := range expectedKeys {
		if missing {
			t.Fatalf("expected field key %q was not found", key)
		}
	}
}
