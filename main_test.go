package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestNormalizeHost verifies ports/default handling across host inputs.
func TestNormalizeHost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		port    int
		want    string
		wantErr bool
	}{
		{"hostOnly", "example.com", 22, "example.com:22", false},
		{"withPort", "host:2222", 22, "host:2222", false},
		{"ipv6", "[2001:db8::1]", 2022, "[2001:db8::1]:2022", false},
		{"empty", "   ", 22, "", true},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeHost(testCase.raw, testCase.port)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != testCase.want {
				t.Fatalf("got %q want %q", got, testCase.want)
			}
		})
	}
}

// TestResolveHostsNoInput asserts error when no host sources are provided.
func TestResolveHostsNoInput(t *testing.T) {
	t.Parallel()

	if _, err := resolveHosts("", "", "", 22); err == nil {
		t.Fatalf("expected error without hosts")
	}
}

// TestExtractSingleKey validates that only one non-comment key line is kept.
func TestExtractSingleKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"single", "ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAIE", false},
		{"multi", "ssh-ed25519 A\nssh-ed25519 B", true},
		{"empty", "  \n# comment", true},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			key, err := extractSingleKey(testCase.raw)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key != "ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAIE" {
				if testCase.name == "single" {
					t.Fatalf("got %q", key)
				}
			}
		})
	}
}

// TestResolveHosts ensures combined sources deduplicate, normalize, and sort hosts.
func TestResolveHosts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	list := filepath.Join(dir, "servers.txt")
	content := `
# comment line
hostA
hostB:2222
hostA
`

	if err := os.WriteFile(list, []byte(content), 0o600); err != nil {
		t.Fatalf("write list: %v", err)
	}

	got, err := resolveHosts("hostC", "hostA,hostB:2222", list, 22)
	if err != nil {
		t.Fatalf("resolve hosts: %v", err)
	}

	want := []string{"hostA:22", "hostB:2222", "hostC:22"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// TestResolvePublicKeyInline ensures inline key text is parsed and validated.
func TestResolvePublicKeyInline(t *testing.T) {
	t.Parallel()

	pubKey := generateTestKey(t)
	got, err := resolvePublicKey(pubKey, "")
	if err != nil {
		t.Fatalf("resolve inline key: %v", err)
	}
	if got == "" {
		t.Fatalf("empty key")
	}
}

// TestResolvePublicKeyFile ensures file-based keys are read and validated.
func TestResolvePublicKeyFile(t *testing.T) {
	t.Parallel()

	content := generateTestKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	got, err := resolvePublicKey("", path)
	if err != nil {
		t.Fatalf("resolve file key: %v", err)
	}
	if got == "" {
		t.Fatalf("empty key")
	}
}

// TestResolvePublicKeyBothSources rejects simultaneous inline and file inputs.
func TestResolvePublicKeyBothSources(t *testing.T) {
	t.Parallel()

	if _, err := resolvePublicKey("key", "file"); err == nil {
		t.Fatalf("expected error when both sources provided")
	}
}

// generateTestKey synthesizes a valid ed25519 public key for authorized_keys usage.
func generateTestKey(t *testing.T) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}

	return string(ssh.MarshalAuthorizedKey(pk))
}
