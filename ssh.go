package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var confirmUnknownHost = promptTrustUnknownHost

func buildSSHConfig(programOptions *options) (*ssh.ClientConfig, error) {
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

func buildHostKeyCallback(insecure bool, knownHostsPath string) (ssh.HostKeyCallback, error) {
	if insecure {
		return ssh.InsecureIgnoreHostKey(), nil // #nosec G106 -- explicitly enabled via --insecure flag
	}

	path, err := expandHomePath(strings.TrimSpace(knownHostsPath))
	if err != nil {
		return nil, fmt.Errorf("resolve known_hosts path: %w", err)
	}

	if err := ensureKnownHostsFile(path); err != nil {
		return nil, fmt.Errorf("prepare known_hosts file: %w", err)
	}

	callback, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}

	var callbackGuard sync.Mutex
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		callbackGuard.Lock()
		defer callbackGuard.Unlock()

		if callbackErr := callback(hostname, remote, key); callbackErr == nil {
			return nil
		} else {
			var keyErr *knownhosts.KeyError
			if !errors.As(callbackErr, &keyErr) || len(keyErr.Want) > 0 {
				return callbackErr
			}

			trustHost, promptErr := confirmUnknownHost(hostname, path, key)
			if promptErr != nil {
				return promptErr
			}
			if !trustHost {
				return fmt.Errorf("host key for %s rejected by user", hostname)
			}

			if appendErr := appendKnownHost(path, hostname, key); appendErr != nil {
				return fmt.Errorf("store trusted host key: %w", appendErr)
			}

			reloadedCallback, reloadErr := knownhosts.New(path)
			if reloadErr != nil {
				return fmt.Errorf("reload known_hosts: %w", reloadErr)
			}
			callback = reloadedCallback
			return nil
		}
	}, nil
}

func ensureKnownHostsFile(path string) error {
	parentDirectory := filepath.Dir(path)
	if parentDirectory != "." {
		if err := os.MkdirAll(parentDirectory, 0o700); err != nil {
			return err
		}
	}

	fileHandle, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600) // #nosec G304 -- known_hosts path is user-configurable by design
	if err != nil {
		return err
	}
	return fileHandle.Close()
}

func promptTrustUnknownHost(hostname, knownHostsPath string, key ssh.PublicKey) (bool, error) {
	if !isTerminal(os.Stdin) {
		return false, fmt.Errorf("unknown host %s and no interactive terminal available to confirm trust", hostname)
	}

	fmt.Printf("The authenticity of host %q can't be established.\n", hostname)
	fmt.Printf("%s key fingerprint is %s.\n", key.Type(), ssh.FingerprintSHA256(key))

	reader := bufio.NewReader(os.Stdin)
	for {
		answer, err := promptLine(reader, fmt.Sprintf("Trust this host and add it to %s? (yes/no): ", knownHostsPath))
		if err != nil {
			return false, err
		}

		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "yes", "y":
			return true, nil
		case "no", "n":
			return false, nil
		default:
			fmt.Println(`Please answer "yes" or "no".`)
		}
	}
}

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	if err := ensureKnownHostsFile(path); err != nil {
		return err
	}

	knownHostLine := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	fileHandle, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) // #nosec G304 -- known_hosts path is user-configurable by design
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	if _, err := fileHandle.WriteString(knownHostLine + "\n"); err != nil {
		return err
	}
	return nil
}

func addAuthorizedKeyWithStatus(hostAddress, publicKey string, clientConfig *ssh.ClientConfig, logf func(format string, args ...any)) error {
	if logf != nil {
		logf("Connecting over SSH...")
	}
	client, err := ssh.Dial("tcp", hostAddress, clientConfig)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	if logf != nil {
		logf("Connected. Opening remote session...")
	}
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer session.Close()

	if logf != nil {
		logf("Applying authorized_keys update...")
	}
	session.Stdin = strings.NewReader(publicKey + "\n")
	commandOutput, err := session.CombinedOutput(normalizeLF(addAuthorizedKeyScript))
	if err != nil {
		outputMessage := strings.TrimSpace(string(commandOutput))
		if outputMessage == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, outputMessage)
	}
	if logf != nil {
		logf("Remote command completed.")
	}
	return nil
}

func resolveHosts(server, servers, serversFile string, defaultPort int) ([]string, error) {
	hostSet := map[string]struct{}{}

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

	for _, candidateEntry := range splitServerEntries(server) {
		if err := addHost(candidateEntry); err != nil {
			return nil, err
		}
	}
	for _, candidateEntry := range splitServerEntries(servers) {
		if err := addHost(candidateEntry); err != nil {
			return nil, err
		}
	}

	if strings.TrimSpace(serversFile) != "" {
		serversFileHandle, err := os.Open(serversFile) // #nosec G304 -- servers file path comes from CLI/config input
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

	if len(hostSet) == 0 {
		return nil, errors.New("no servers provided")
	}

	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, nil
}

func splitServerEntries(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	entries := strings.Split(value, ",")
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func normalizeHost(rawHost string, defaultPort int) (string, error) {
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

	if strings.HasPrefix(rawHost, "[") && strings.HasSuffix(rawHost, "]") {
		rawHost = strings.TrimSuffix(strings.TrimPrefix(rawHost, "["), "]")
	}
	if strings.TrimSpace(rawHost) == "" {
		return "", errors.New("missing host")
	}
	return net.JoinHostPort(rawHost, strconv.Itoa(defaultPort)), nil
}

func resolvePublicKey(keyInput string) (string, error) {
	trimmedInput := strings.TrimSpace(keyInput)
	if trimmedInput == "" {
		return "", errors.New("public key is required")
	}

	inlineKey, inlineErr := parsePublicKeyFromRawInput(trimmedInput)
	if inlineErr == nil {
		return inlineKey, nil
	}

	path, pathErr := expandHomePath(trimmedInput)
	if pathErr != nil {
		path = trimmedInput
	}
	fileBytes, readErr := os.ReadFile(path) // #nosec G304 -- key file path comes from CLI/config input
	if readErr != nil {
		return "", fmt.Errorf("invalid --key value: expected a public key or readable file path %q: %w", trimmedInput, readErr)
	}
	publicKey, parseErr := parsePublicKeyFromRawInput(string(fileBytes))
	if parseErr != nil {
		return "", fmt.Errorf("invalid public key in file %q: %w", path, parseErr)
	}
	return publicKey, nil
}

func parsePublicKeyFromRawInput(rawKeyInput string) (string, error) {
	extractedKey, err := extractSingleKey(rawKeyInput)
	if err != nil {
		return "", err
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(extractedKey)); err != nil {
		return "", fmt.Errorf("invalid public key format: %w", err)
	}
	return extractedKey, nil
}

func extractSingleKey(rawKeyInput string) (string, error) {
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
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read key input: %w", err)
	}
	if extractedKey == "" {
		return "", errors.New("public key is required")
	}
	return extractedKey, nil
}
