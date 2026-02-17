// Developed with assistance from Codex (ChatGPT); the developer is a Go novice and is still learning. Review carefully for bugs before running.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

const (
	// defaultSSHPort is used when a server entry omits ":port".
	defaultSSHPort = 22
	// defaultTimeoutSeconds is the per-host network timeout.
	defaultTimeoutSeconds = 10
	// defaultKnownHostsPath is used for host key verification when secure mode is on.
	defaultKnownHostsPath = "~/.ssh/known_hosts"
)

// addAuthorizedKeyScript runs remotely and appends the key only if missing.
const addAuthorizedKeyScript = `set -eu
umask 077
mkdir -p ~/.ssh
touch ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
IFS= read -r KEY
grep -qxF "$KEY" ~/.ssh/authorized_keys || printf '%s\n' "$KEY" >> ~/.ssh/authorized_keys
`

// options groups all command-line flags and prompted values.
type options struct {
	server                string
	servers               string
	serversFile           string
	user                  string
	password              string
	passwordEnv           string
	pubKey                string
	pubKeyFile            string
	port                  int
	timeoutSec            int
	insecureIgnoreHostKey bool
	knownHosts            string
}

// statusError carries a process exit code plus user-facing error text.
type statusError struct {
	code int
	err  error
}

// Error implements the error interface.
func (e *statusError) Error() string {
	return e.err.Error()
}

func main() {
	// Run the full workflow and map failures to explicit process exit codes.
	if err := run(); err != nil {
		var se *statusError
		if errors.As(err, &se) {
			fmt.Fprintln(os.Stderr, "Error:", se.err)
			os.Exit(se.code)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
}

// run orchestrates parsing, prompting, validation, and key installation.
func run() error {
	// Parse all CLI flags into one options struct.
	opts := parseFlags()

	// Validate static flag constraints and optional env-based password input.
	if err := validateOptions(opts); err != nil {
		return fail(2, "%w", err)
	}

	// Prompt only for fields still missing after flags/env processing.
	inputReader := bufio.NewReader(os.Stdin)
	if err := fillMissingInputs(inputReader, opts); err != nil {
		return fail(2, "%w", err)
	}

	// Build and normalize final host list before networking.
	hosts, err := resolveHosts(opts.server, opts.servers, opts.serversFile, opts.port)
	if err != nil {
		return fail(2, "%w", err)
	}

	// Parse and validate exactly one authorized key line.
	key, err := resolvePublicKey(opts.pubKey, opts.pubKeyFile)
	if err != nil {
		return fail(2, "%w", err)
	}

	// Build SSH client config with secure host-key verification by default.
	clientConfig, err := buildSSHConfig(opts)
	if err != nil {
		return fail(2, "%w", err)
	}

	// Attempt all hosts and keep going to show complete success/failure status.
	failures := 0
	for _, host := range hosts {
		if err := addAuthorizedKey(host, key, clientConfig); err != nil {
			failures++
			fmt.Printf("[FAIL] %s: %v\n", host, err)
			continue
		}
		fmt.Printf("[OK]   %s\n", host)
	}

	// Exit code 1 signals partial or full per-host operation failure.
	if failures > 0 {
		return fail(1, "%d host(s) failed", failures)
	}
	return nil
}

// fail wraps an error with a specific process exit code.
func fail(code int, format string, args ...any) error {
	return &statusError{
		code: code,
		err:  fmt.Errorf(format, args...),
	}
}

// parseFlags binds command-line flags into an options struct.
func parseFlags() *options {
	opts := &options{}

	flag.StringVar(&opts.server, "server", "", "Single server (host or host:port)")
	flag.StringVar(&opts.servers, "servers", "", "Comma-separated servers (host or host:port)")
	flag.StringVar(&opts.serversFile, "servers-file", "", "File with one server per line")

	flag.StringVar(&opts.user, "user", "", "SSH username")
	flag.StringVar(&opts.password, "password", "", "SSH password (less secure than prompt)")
	flag.StringVar(&opts.passwordEnv, "password-env", "", "Environment variable containing SSH password")

	flag.StringVar(&opts.pubKey, "pubkey", "", "Public key text (e.g. ssh-ed25519 AAAA...)")
	flag.StringVar(&opts.pubKeyFile, "pubkey-file", "", "Path to public key file")

	flag.IntVar(&opts.port, "port", defaultSSHPort, "Default SSH port when not specified in server entry")
	flag.IntVar(&opts.timeoutSec, "timeout", defaultTimeoutSeconds, "SSH timeout in seconds")

	flag.BoolVar(&opts.insecureIgnoreHostKey, "insecure-ignore-host-key", false, "Disable host key verification (unsafe)")
	flag.StringVar(&opts.knownHosts, "known-hosts", defaultKnownHostsPath, "Path to known_hosts file")

	flag.Parse()
	return opts
}

// validateOptions checks basic flag validity and handles password-env resolution.
func validateOptions(opts *options) error {
	// Validate numeric fields early for fast feedback.
	if opts.port < 1 || opts.port > 65535 {
		return errors.New("port must be in range 1..65535")
	}
	if opts.timeoutSec <= 0 {
		return errors.New("timeout must be greater than zero")
	}

	// Enforce one password source to avoid ambiguous precedence.
	if strings.TrimSpace(opts.password) != "" && strings.TrimSpace(opts.passwordEnv) != "" {
		return errors.New("use either -password or -password-env, not both")
	}

	// If requested, load password from environment variable.
	envName := strings.TrimSpace(opts.passwordEnv)
	if strings.TrimSpace(opts.password) == "" && envName != "" {
		value := strings.TrimSpace(os.Getenv(envName))
		if value == "" {
			return fmt.Errorf("environment variable %q is empty or not set", envName)
		}
		opts.password = value
	}

	return nil
}

// fillMissingInputs interactively collects required values not set via flags/env.
func fillMissingInputs(inputReader *bufio.Reader, opts *options) error {
	var err error

	// Request username when missing.
	if strings.TrimSpace(opts.user) == "" {
		opts.user, err = promptRequired(inputReader, "SSH username: ")
		if err != nil {
			return err
		}
	}

	// Request password when still missing after optional env lookup.
	if strings.TrimSpace(opts.password) == "" {
		opts.password, err = promptPassword(inputReader, "SSH password: ")
		if err != nil {
			return err
		}
	}

	// Require at least one host source.
	if strings.TrimSpace(opts.server) == "" &&
		strings.TrimSpace(opts.servers) == "" &&
		strings.TrimSpace(opts.serversFile) == "" {
		opts.servers, err = promptRequired(inputReader, "Servers (comma-separated, host or host:port): ")
		if err != nil {
			return err
		}
	}

	// Require a key source; first ask for file, then fallback to inline key paste.
	if strings.TrimSpace(opts.pubKey) == "" && strings.TrimSpace(opts.pubKeyFile) == "" {
		opts.pubKeyFile, err = promptLine(inputReader, "Public key file path (enter to paste key): ")
		if err != nil {
			return err
		}
		opts.pubKeyFile = strings.TrimSpace(opts.pubKeyFile)

		if opts.pubKeyFile == "" {
			opts.pubKey, err = promptRequired(inputReader, "Public key text: ")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// buildSSHConfig creates the SSH config used for every target host.
func buildSSHConfig(opts *options) (*ssh.ClientConfig, error) {
	// Build host key callback based on secure/insecure mode.
	hostKeyCallback, err := buildHostKeyCallback(opts.insecureIgnoreHostKey, opts.knownHosts)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:            opts.user,
		Auth:            []ssh.AuthMethod{ssh.Password(opts.password)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         time.Duration(opts.timeoutSec) * time.Second,
	}, nil
}

// buildHostKeyCallback returns either strict known_hosts validation or explicit insecure mode.
func buildHostKeyCallback(insecure bool, knownHostsPath string) (ssh.HostKeyCallback, error) {
	// Keep insecure mode available, but only when explicitly requested.
	if insecure {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	// Expand "~" and construct callback from the known_hosts file.
	path, err := expandHomePath(strings.TrimSpace(knownHostsPath))
	if err != nil {
		return nil, fmt.Errorf("resolve known_hosts path: %w", err)
	}

	callback, err := knownhosts.New(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("known_hosts file not found at %q (create it or use -insecure-ignore-host-key)", path)
		}
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}

	return callback, nil
}

// expandHomePath expands "~" prefixes in filesystem paths.
func expandHomePath(path string) (string, error) {
	// Guard against empty input from misconfigured flags.
	if path == "" {
		return "", errors.New("path is empty")
	}

	// Fast path for non-home-relative input.
	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return path, nil
	}

	// Resolve current user home directory.
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Handle exact "~" value.
	if path == "~" {
		return home, nil
	}

	// Join the remainder to the home directory.
	return filepath.Join(home, path[2:]), nil
}

// promptLine reads a single line from stdin, trimming surrounding whitespace.
func promptLine(reader *bufio.Reader, label string) (string, error) {
	// Show a prompt before reading.
	fmt.Print(label)

	// Read through newline; EOF is accepted for piped input.
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	return strings.TrimSpace(line), nil
}

// promptRequired keeps prompting until a non-empty value is entered.
func promptRequired(reader *bufio.Reader, label string) (string, error) {
	for {
		value, err := promptLine(reader, label)
		if err != nil {
			return "", err
		}
		if value != "" {
			return value, nil
		}
		fmt.Println("Value is required.")
	}
}

// promptPassword reads a required password with hidden input in terminals.
func promptPassword(reader *bufio.Reader, label string) (string, error) {
	for {
		// Display prompt each attempt.
		fmt.Print(label)

		var pwd string

		// Hide password echo on interactive terminals.
		if term.IsTerminal(int(os.Stdin.Fd())) {
			bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return "", err
			}
			pwd = strings.TrimSpace(string(bytes))
		} else {
			// Fallback for piped input and non-terminal sessions.
			line, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			pwd = strings.TrimSpace(line)
		}

		// Accept only non-empty passwords.
		if pwd != "" {
			return pwd, nil
		}
		fmt.Println("Value is required.")
	}
}

// resolveHosts merges host inputs, normalizes addresses, deduplicates, and sorts.
func resolveHosts(server, servers, serversFile string, defaultPort int) ([]string, error) {
	// Use a set to deduplicate hosts across all input sources.
	hostSet := map[string]struct{}{}

	// addHost validates and inserts one host string.
	addHost := func(raw string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil
		}

		normalized, err := normalizeHost(raw, defaultPort)
		if err != nil {
			return fmt.Errorf("invalid server %q: %w", raw, err)
		}

		hostSet[normalized] = struct{}{}
		return nil
	}

	// Add optional single host input.
	if err := addHost(server); err != nil {
		return nil, err
	}

	// Add optional comma-separated hosts.
	for _, candidateEntry := range strings.Split(servers, ",") {
		if err := addHost(candidateEntry); err != nil {
			return nil, err
		}
	}

	// Add optional file-based hosts (supports blank lines and comments).
	if strings.TrimSpace(serversFile) != "" {
		serversFileHandle, err := os.Open(serversFile)
		if err != nil {
			return nil, fmt.Errorf("open servers file: %w", err)
		}
		defer serversFileHandle.Close()

		fileScanner := bufio.NewScanner(serversFileHandle)
		lineNo := 0
		for fileScanner.Scan() {
			lineNo++
			line := strings.TrimSpace(fileScanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if err := addHost(line); err != nil {
				return nil, fmt.Errorf("servers file line %d: %w", lineNo, err)
			}
		}

		if err := fileScanner.Err(); err != nil {
			return nil, fmt.Errorf("read servers file: %w", err)
		}
	}

	// Require at least one resolved host target.
	if len(hostSet) == 0 {
		return nil, errors.New("no servers provided")
	}

	// Convert set to sorted slice for stable output order.
	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	return hosts, nil
}

// normalizeHost ensures a host string always has a usable host:port form.
func normalizeHost(raw string, defaultPort int) (string, error) {
	// If a port is already present, validate and normalize it.
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if strings.TrimSpace(host) == "" {
			return "", errors.New("missing host")
		}
		if _, err := strconv.Atoi(port); err != nil {
			return "", fmt.Errorf("invalid port %q", port)
		}
		if _, err := net.LookupPort("tcp", port); err != nil {
			return "", fmt.Errorf("invalid port %q", port)
		}
		return net.JoinHostPort(host, port), nil
	}

	// Handle bracketed IPv6 hosts that omit a port, e.g. "[2001:db8::1]".
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	}

	// Reject empty host values after normalization.
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("missing host")
	}

	// Add default port and let net.JoinHostPort bracket IPv6 as needed.
	return net.JoinHostPort(raw, strconv.Itoa(defaultPort)), nil
}

// resolvePublicKey loads and validates exactly one authorized key entry.
func resolvePublicKey(inline, file string) (string, error) {
	// For clarity, allow only one key source at a time.
	if strings.TrimSpace(inline) != "" && strings.TrimSpace(file) != "" {
		return "", errors.New("use either -pubkey or -pubkey-file, not both")
	}

	// Require some key source.
	if strings.TrimSpace(inline) == "" && strings.TrimSpace(file) == "" {
		return "", errors.New("public key is required")
	}

	// Read raw input from file or inline flag.
	var raw string
	if strings.TrimSpace(file) != "" {
		bytes, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read pubkey file: %w", err)
		}
		raw = string(bytes)
	} else {
		raw = inline
	}

	// Extract one non-comment key line and validate authorized_keys syntax.
	key, err := extractSingleKey(raw)
	if err != nil {
		return "", err
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err != nil {
		return "", fmt.Errorf("invalid public key format: %w", err)
	}

	return key, nil
}

// extractSingleKey accepts one non-empty, non-comment line from the provided text.
func extractSingleKey(raw string) (string, error) {
	// Track exactly one logical key line.
	key := ""
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if key != "" {
			return "", errors.New("public key input must contain exactly one key")
		}

		key = line
	}

	// Return scanner errors (rare, but important for very long/bad input).
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read key input: %w", err)
	}

	// Ensure at least one usable key line was found.
	if key == "" {
		return "", errors.New("public key is required")
	}

	return key, nil
}

// addAuthorizedKey opens SSH session and appends key remotely if it does not exist.
func addAuthorizedKey(host, key string, cfg *ssh.ClientConfig) error {
	// Establish TCP+SSH connection to target host.
	client, err := ssh.Dial("tcp", host, cfg)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	// Open a session for running a small shell script.
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer session.Close()

	// Send key via stdin and run idempotent script on remote host.
	session.Stdin = strings.NewReader(key + "\n")
	out, err := session.CombinedOutput(addAuthorizedKeyScript)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, msg)
	}

	return nil
}

// AI disclaimer: generated with Codex (ChatGPT); the developer is a Go novice and is still learning. Validate all paths/flags/tests before deployment.
