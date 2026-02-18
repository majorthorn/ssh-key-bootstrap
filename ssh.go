package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

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
		return ssh.InsecureIgnoreHostKey(), nil
	}

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

func addAuthorizedKey(hostAddress, publicKey string, clientConfig *ssh.ClientConfig) error {
	client, err := ssh.Dial("tcp", hostAddress, clientConfig)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer session.Close()

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

func resolvePublicKey(inlinePublicKey, publicKeyFile string) (string, error) {
	if strings.TrimSpace(inlinePublicKey) != "" && strings.TrimSpace(publicKeyFile) != "" {
		return "", errors.New("use either -pubkey or -pubkey-file, not both")
	}
	if strings.TrimSpace(inlinePublicKey) == "" && strings.TrimSpace(publicKeyFile) == "" {
		return "", errors.New("public key is required")
	}

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
