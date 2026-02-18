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
// Use explicit "\n" escapes so source-file CRLF does not become part of remote paths.
const addAuthorizedKeyScript = "set -eu\n" +
	"umask 077\n" +
	"mkdir -p ~/.ssh\n" +
	"touch ~/.ssh/authorized_keys\n" +
	"chmod 700 ~/.ssh\n" +
	"chmod 600 ~/.ssh/authorized_keys\n" +
	"IFS= read -r KEY\n" +
	"grep -qxF \"$KEY\" ~/.ssh/authorized_keys || printf '%s\\n' \"$KEY\" >> ~/.ssh/authorized_keys\n"

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
func (statusErr *statusError) Error() string {
	return statusErr.err.Error()
}

func main() {
	// Run the full workflow and map failures to explicit process exit codes.
	if err := run(); err != nil {
		var statusErr *statusError
		if errors.As(err, &statusErr) {
			fmt.Fprintln(os.Stderr, "Error:", statusErr.err)
			os.Exit(statusErr.code)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
}

// run orchestrates parsing, prompting, validation, and key installation.
func run() error {
	// Parse all CLI flags into one options struct.
	programOptions := parseFlags()

	// Validate static flag constraints and optional env-based password input.
	if err := validateOptions(programOptions); err != nil {
		return fail(2, "%w", err)
	}

	// Prompt only for fields still missing after flags/env processing.
	inputReader := bufio.NewReader(os.Stdin)
	if err := fillMissingInputs(inputReader, programOptions); err != nil {
		return fail(2, "%w", err)
	}

	// Build and normalize final host list before networking.
	hosts, err := resolveHosts(programOptions.server, programOptions.servers, programOptions.serversFile, programOptions.port)
	if err != nil {
		return fail(2, "%w", err)
	}

	// Parse and validate exactly one authorized key line.
	publicKey, err := resolvePublicKey(programOptions.pubKey, programOptions.pubKeyFile)
	if err != nil {
		return fail(2, "%w", err)
	}

	// Build SSH client config with secure host-key verification by default.
	clientConfig, err := buildSSHConfig(programOptions)
	if err != nil {
		return fail(2, "%w", err)
	}

	// Attempt all hosts and keep going to show complete success/failure status.
	failures := 0
	for _, host := range hosts {
		if err := addAuthorizedKey(host, publicKey, clientConfig); err != nil {
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
	programOptions := &options{}

	flag.StringVar(&programOptions.server, "server", "", "Single server (host or host:port)")
	flag.StringVar(&programOptions.servers, "servers", "", "Comma-separated servers (host or host:port)")
	flag.StringVar(&programOptions.serversFile, "servers-file", "", "File with one server per line")

	flag.StringVar(&programOptions.user, "user", "", "SSH username")
	flag.StringVar(&programOptions.password, "password", "", "SSH password (less secure than prompt)")
	flag.StringVar(&programOptions.passwordEnv, "password-env", "", "Environment variable containing SSH password")

	flag.StringVar(&programOptions.pubKey, "pubkey", "", "Public key text (e.g. ssh-ed25519 AAAA...)")
	flag.StringVar(&programOptions.pubKeyFile, "pubkey-file", "", "Path to public key file")

	flag.IntVar(&programOptions.port, "port", defaultSSHPort, "Default SSH port when not specified in server entry")
	flag.IntVar(&programOptions.timeoutSec, "timeout", defaultTimeoutSeconds, "SSH timeout in seconds")

	flag.BoolVar(&programOptions.insecureIgnoreHostKey, "insecure-ignore-host-key", false, "Disable host key verification (unsafe)")
	flag.StringVar(&programOptions.knownHosts, "known-hosts", defaultKnownHostsPath, "Path to known_hosts file")

	flag.Parse()
	return programOptions
}

// validateOptions checks basic flag validity and handles password-env resolution.
func validateOptions(programOptions *options) error {
	// Validate numeric fields early for fast feedback.
	if programOptions.port < 1 || programOptions.port > 65535 {
		return errors.New("port must be in range 1..65535")
	}
	if programOptions.timeoutSec <= 0 {
		return errors.New("timeout must be greater than zero")
	}

	// Enforce one password source to avoid ambiguous precedence.
	if strings.TrimSpace(programOptions.password) != "" && strings.TrimSpace(programOptions.passwordEnv) != "" {
		return errors.New("use either -password or -password-env, not both")
	}

	// If requested, load password from environment variable.
	envName := strings.TrimSpace(programOptions.passwordEnv)
	if strings.TrimSpace(programOptions.password) == "" && envName != "" {
		value := strings.TrimSpace(os.Getenv(envName))
		if value == "" {
			return fmt.Errorf("environment variable %q is empty or not set", envName)
		}
		programOptions.password = value
	}

	return nil
}

// fillMissingInputs interactively collects required values not set via flags/env.
func fillMissingInputs(inputReader *bufio.Reader, programOptions *options) error {
	var err error

	// Request username when missing.
	if strings.TrimSpace(programOptions.user) == "" {
		programOptions.user, err = promptRequired(inputReader, "SSH username: ")
		if err != nil {
			return err
		}
	}

	// Request password when still missing after optional env lookup.
	if strings.TrimSpace(programOptions.password) == "" {
		programOptions.password, err = promptPassword(inputReader, "SSH password: ")
		if err != nil {
			return err
		}
	}

	// Require at least one host source.
	if strings.TrimSpace(programOptions.server) == "" &&
		strings.TrimSpace(programOptions.servers) == "" &&
		strings.TrimSpace(programOptions.serversFile) == "" {
		programOptions.servers, err = promptRequired(inputReader, "Servers (comma-separated, host or host:port): ")
		if err != nil {
			return err
		}
	}

	// Require a key source; first ask for file, then fallback to inline key paste.
	if strings.TrimSpace(programOptions.pubKey) == "" && strings.TrimSpace(programOptions.pubKeyFile) == "" {
		programOptions.pubKeyFile, err = promptLine(inputReader, "Public key file path (enter to paste key): ")
		if err != nil {
			return err
		}
		programOptions.pubKeyFile = strings.TrimSpace(programOptions.pubKeyFile)

		if programOptions.pubKeyFile == "" {
			programOptions.pubKey, err = promptRequired(inputReader, "Public key text: ")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// buildSSHConfig creates the SSH config used for every target host.
func buildSSHConfig(programOptions *options) (*ssh.ClientConfig, error) {
	// Build host key callback based on secure/insecure mode.
	hostKeyCallback, err := buildHostKeyCallback(programOptions.insecureIgnoreHostKey, programOptions.knownHosts)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:            programOptions.user,
		Auth:            []ssh.AuthMethod{ssh.Password(programOptions.password)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         time.Duration(programOptions.timeoutSec) * time.Second,
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

		var passwordInput string

		// Hide password echo on interactive terminals.
		if term.IsTerminal(int(os.Stdin.Fd())) {
			bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return "", err
			}
			passwordInput = strings.TrimSpace(string(bytes))
		} else {
			// Fallback for piped input and non-terminal sessions.
			line, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			passwordInput = strings.TrimSpace(line)
		}

		// Accept only non-empty passwords.
		if passwordInput != "" {
			return passwordInput, nil
		}
		fmt.Println("Value is required.")
	}
}

// resolveHosts merges host inputs, normalizes addresses, deduplicates, and sorts.
func resolveHosts(server, servers, serversFile string, defaultPort int) ([]string, error) {
	// Use a set to deduplicate hosts across all input sources.
	hostSet := map[string]struct{}{}

	// addHost validates and inserts one host string.
	addHost := func(rawHost string) error {
		rawHost = strings.TrimSpace(rawHost)
		if rawHost == "" {
			return nil
		}

		normalizedHost, err := normalizeHost(rawHost, defaultPort)
		if err != nil {
			return fmt.Errorf("invalid server %q: %w", rawHost, err)
		}

		hostSet[normalizedHost] = struct{}{}
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
func normalizeHost(rawHost string, defaultPort int) (string, error) {
	// If a port is already present, validate and normalize it.
	if host, port, err := net.SplitHostPort(rawHost); err == nil {
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
	if strings.HasPrefix(rawHost, "[") && strings.HasSuffix(rawHost, "]") {
		rawHost = strings.TrimSuffix(strings.TrimPrefix(rawHost, "["), "]")
	}

	// Reject empty host values after normalization.
	if strings.TrimSpace(rawHost) == "" {
		return "", errors.New("missing host")
	}

	// Add default port and let net.JoinHostPort bracket IPv6 as needed.
	return net.JoinHostPort(rawHost, strconv.Itoa(defaultPort)), nil
}

// resolvePublicKey loads and validates exactly one authorized key entry.
func resolvePublicKey(inlinePublicKey, publicKeyFile string) (string, error) {
	// For clarity, allow only one key source at a time.
	if strings.TrimSpace(inlinePublicKey) != "" && strings.TrimSpace(publicKeyFile) != "" {
		return "", errors.New("use either -pubkey or -pubkey-file, not both")
	}

	// Require some key source.
	if strings.TrimSpace(inlinePublicKey) == "" && strings.TrimSpace(publicKeyFile) == "" {
		return "", errors.New("public key is required")
	}

	// Read raw input from file or inline flag.
	var rawKeyInput string
	if strings.TrimSpace(publicKeyFile) != "" {
		bytes, err := os.ReadFile(publicKeyFile)
		if err != nil {
			return "", fmt.Errorf("read pubkey file: %w", err)
		}
		rawKeyInput = string(bytes)
	} else {
		rawKeyInput = inlinePublicKey
	}

	// Extract one non-comment key line and validate authorized_keys syntax.
	extractedKey, err := extractSingleKey(rawKeyInput)
	if err != nil {
		return "", err
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(extractedKey)); err != nil {
		return "", fmt.Errorf("invalid public key format: %w", err)
	}

	return extractedKey, nil
}

// extractSingleKey accepts one non-empty, non-comment line from the provided text.
func extractSingleKey(rawKeyInput string) (string, error) {
	// Track exactly one logical key line.
	extractedKey := ""
	scanner := bufio.NewScanner(strings.NewReader(rawKeyInput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if extractedKey != "" {
			return "", errors.New("public key input must contain exactly one key")
		}

		extractedKey = line
	}

	// Return scanner errors (rare, but important for very long/bad input).
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read key input: %w", err)
	}

	// Ensure at least one usable key line was found.
	if extractedKey == "" {
		return "", errors.New("public key is required")
	}

	return extractedKey, nil
}

// normalizeLF removes carriage returns to prevent CRLF from leaking into remote shells.
func normalizeLF(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.ReplaceAll(value, "\r", "\n")
}

// addAuthorizedKey opens SSH session and appends key remotely if it does not exist.
func addAuthorizedKey(hostAddress, publicKey string, clientConfig *ssh.ClientConfig) error {
	// Establish TCP+SSH connection to target host.
	client, err := ssh.Dial("tcp", hostAddress, clientConfig)
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
	session.Stdin = strings.NewReader(publicKey + "\n")
	commandOutput, err := session.CombinedOutput(normalizeLF(addAuthorizedKeyScript))
	if err != nil {
		outputMessage := strings.TrimSpace(string(commandOutput))
		if outputMessage == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, outputMessage)
	}

	return nil
}

// AI disclaimer: generated with Codex (ChatGPT); the developer is a Go novice and is still learning. Validate all paths/flags/tests before deployment.
