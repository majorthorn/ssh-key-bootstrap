package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var expectedDotEnvLoadedFields = []string{
	"server",
	"servers",
	"user",
	"password",
	"passwordSecretRef",
	"keyInput",
	"port",
	"timeoutSec",
	"insecureIgnoreHostKey",
	"knownHosts",
}

func writeDotEnv(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	return path
}

func TestApplyDotEnvWithMetadataNoEnvFile(t *testing.T) {
	t.Parallel()

	opts := &Options{}
	loaded, err := ApplyDotEnvWithMetadata(opts)
	if err != nil {
		t.Fatalf("ApplyDotEnvWithMetadata() error = %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("loaded fields = %v, want empty", loaded)
	}
}

func TestApplyDotEnvWithMetadataLoadsFields(t *testing.T) {
	t.Parallel()

	dotEnvPath := writeDotEnv(t, `SERVER=host01
SERVERS=a,b
USER=alice
PASSWORD='secret value'
PASSWORD_SECRET_REF=bw://vault/item
PUBKEY_FILE=~/.ssh/id_ed25519.pub
PORT=2201
TIMEOUT=45
INSECURE_IGNORE_HOST_KEY=true
KNOWN_HOSTS=~/.ssh/known_hosts
`)
	opts := &Options{EnvFile: dotEnvPath}

	loaded, err := ApplyDotEnvWithMetadata(opts)
	if err != nil {
		t.Fatalf("ApplyDotEnvWithMetadata() error = %v", err)
	}

	if opts.Server != "host01" {
		t.Fatalf("Server = %q, want %q", opts.Server, "host01")
	}
	if opts.Servers != "a,b" {
		t.Fatalf("Servers = %q, want %q", opts.Servers, "a,b")
	}
	if opts.User != "alice" {
		t.Fatalf("User = %q, want %q", opts.User, "alice")
	}
	if opts.Password != "secret value" {
		t.Fatalf("Password = %q, want %q", opts.Password, "secret value")
	}
	if opts.PasswordSecretRef != "bw://vault/item" {
		t.Fatalf("PasswordSecretRef = %q, want %q", opts.PasswordSecretRef, "bw://vault/item")
	}
	if opts.KeyInput != "~/.ssh/id_ed25519.pub" {
		t.Fatalf("KeyInput = %q, want %q", opts.KeyInput, "~/.ssh/id_ed25519.pub")
	}
	if opts.Port != 2201 {
		t.Fatalf("Port = %d, want %d", opts.Port, 2201)
	}
	if opts.TimeoutSec != 45 {
		t.Fatalf("TimeoutSec = %d, want %d", opts.TimeoutSec, 45)
	}
	if !opts.InsecureIgnoreHostKey {
		t.Fatalf("InsecureIgnoreHostKey = false, want true")
	}
	if opts.KnownHosts != "~/.ssh/known_hosts" {
		t.Fatalf("KnownHosts = %q, want %q", opts.KnownHosts, "~/.ssh/known_hosts")
	}

	for _, field := range expectedDotEnvLoadedFields {
		if !loaded[field] {
			t.Fatalf("loaded[%q] = false, want true", field)
		}
	}
}

func TestApplyDotEnvWithMetadataConflictingKeySources(t *testing.T) {
	t.Parallel()

	dotEnvPath := writeDotEnv(t, "KEY=inline\nPUBKEY=other\n")
	opts := &Options{EnvFile: dotEnvPath}

	_, err := ApplyDotEnvWithMetadata(opts)
	if err == nil {
		t.Fatalf("expected conflict error")
	}
	if !strings.Contains(err.Error(), "only one of KEY/PUBKEY/PUBKEY_FILE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyDotEnvWithMetadataInvalidPort(t *testing.T) {
	t.Parallel()

	dotEnvPath := writeDotEnv(t, "PORT=nope\n")
	opts := &Options{EnvFile: dotEnvPath}

	_, err := ApplyDotEnvWithMetadata(opts)
	if err == nil {
		t.Fatalf("expected invalid PORT error")
	}
	if !strings.Contains(err.Error(), "PORT") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyDotEnvWithMetadataInvalidTimeout(t *testing.T) {
	t.Parallel()

	dotEnvPath := writeDotEnv(t, "TIMEOUT=nope\n")
	opts := &Options{EnvFile: dotEnvPath}

	_, err := ApplyDotEnvWithMetadata(opts)
	if err == nil {
		t.Fatalf("expected invalid TIMEOUT error")
	}
	if !strings.Contains(err.Error(), "TIMEOUT") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyDotEnvWithMetadataInvalidBool(t *testing.T) {
	t.Parallel()

	dotEnvPath := writeDotEnv(t, "INSECURE_IGNORE_HOST_KEY=not-bool\n")
	opts := &Options{EnvFile: dotEnvPath}

	_, err := ApplyDotEnvWithMetadata(opts)
	if err == nil {
		t.Fatalf("expected invalid INSECURE_IGNORE_HOST_KEY error")
	}
	if !strings.Contains(err.Error(), "INSECURE_IGNORE_HOST_KEY") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyDotEnvWithMetadataParseError(t *testing.T) {
	t.Parallel()

	dotEnvPath := writeDotEnv(t, "BROKEN_LINE\n")
	opts := &Options{EnvFile: dotEnvPath}

	_, err := ApplyDotEnvWithMetadata(opts)
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(err.Error(), "parse .env file") {
		t.Fatalf("unexpected error: %v", err)
	}
}
