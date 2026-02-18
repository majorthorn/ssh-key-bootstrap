// Developed with assistance from Codex (ChatGPT); the developer is a Go novice and is still learning. Review carefully for bugs before running.
package main

import (
	"bufio"
	"encoding/json"
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
	// defaultBinaryDotEnvFilename is checked next to the executable when no config flag is provided.
	defaultBinaryDotEnvFilename = ".env"
	// defaultBinaryJSONConfigFilename is checked next to the executable when no config flag is provided.
	defaultBinaryJSONConfigFilename = "config.json"
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
	jsonFile              string
	envFile               string
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
	providedFlagNames := collectProvidedFlagNames()

	// Merge optional config files before validation and interactive prompts.
	if err := applyConfigFiles(programOptions, providedFlagNames); err != nil {
		return fail(2, "%w", err)
	}

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
	flag.StringVar(&programOptions.jsonFile, "json-file", "", "Path to JSON config file")
	flag.StringVar(&programOptions.envFile, "env-file", "", "Path to .env config file")

	flag.IntVar(&programOptions.port, "port", defaultSSHPort, "Default SSH port when not specified in server entry")
	flag.IntVar(&programOptions.timeoutSec, "timeout", defaultTimeoutSeconds, "SSH timeout in seconds")

	flag.BoolVar(&programOptions.insecureIgnoreHostKey, "insecure-ignore-host-key", false, "Disable host key verification (unsafe)")
	flag.StringVar(&programOptions.knownHosts, "known-hosts", defaultKnownHostsPath, "Path to known_hosts file")

	flag.Parse()
	return programOptions
}

// jsonConfigOptions models optional keys accepted from a JSON config file.
type jsonConfigOptions struct {
	Server                *string `json:"server"`
	Servers               *string `json:"servers"`
	ServersFile           *string `json:"servers_file"`
	User                  *string `json:"user"`
	Password              *string `json:"password"`
	PasswordEnv           *string `json:"password_env"`
	PubKey                *string `json:"pubkey"`
	PubKeyFile            *string `json:"pubkey_file"`
	Port                  *int    `json:"port"`
	Timeout               *int    `json:"timeout"`
	InsecureIgnoreHostKey *bool   `json:"insecure_ignore_host_key"`
	KnownHosts            *string `json:"known_hosts"`
}

// collectProvidedFlagNames captures flags explicitly set on the command line.
func collectProvidedFlagNames() map[string]bool {
	providedFlagNames := map[string]bool{}
	flag.Visit(func(currentFlag *flag.Flag) {
		providedFlagNames[currentFlag.Name] = true
	})
	return providedFlagNames
}

// wasFlagProvided checks whether a specific CLI flag was explicitly set.
func wasFlagProvided(providedFlagNames map[string]bool, flagName string) bool {
	return providedFlagNames[flagName]
}

const (
	configSourceTypeDotEnv = "dotenv"
	configSourceTypeJSON   = "json"
)

// configSourceSelection describes one chosen config file source.
type configSourceSelection struct {
	sourceType string
	sourcePath string
}

// applyConfigFiles merges optional JSON/.env file values into options.
func applyConfigFiles(programOptions *options, providedFlagNames map[string]bool) error {
	inputReader := bufio.NewReader(os.Stdin)

	selectedConfigSource, err := selectConfigSource(programOptions, inputReader)
	if err != nil {
		return err
	}
	if selectedConfigSource.sourceType == "" {
		return nil
	}

	loadedFieldNames := map[string]bool{}
	switch selectedConfigSource.sourceType {
	case configSourceTypeDotEnv:
		programOptions.envFile = selectedConfigSource.sourcePath
		programOptions.jsonFile = ""
		loadedFieldNames, err = applyDotEnvConfigFileWithMetadata(programOptions, providedFlagNames)
	case configSourceTypeJSON:
		programOptions.jsonFile = selectedConfigSource.sourcePath
		programOptions.envFile = ""
		loadedFieldNames, err = applyJSONConfigFileWithMetadata(programOptions, providedFlagNames)
	default:
		return fmt.Errorf("unsupported config source type %q", selectedConfigSource.sourceType)
	}
	if err != nil {
		return err
	}

	// Confirmation is mandatory for loaded config values to reduce accidental reuse of stale data.
	if !isInteractiveSession() {
		return errors.New("config file confirmation requires an interactive terminal")
	}

	return confirmLoadedConfigFields(inputReader, programOptions, loadedFieldNames)
}

// selectConfigSource resolves which config source should be loaded for this run.
func selectConfigSource(programOptions *options, inputReader *bufio.Reader) (configSourceSelection, error) {
	flagBasedSelection, selectionWasProvided, err := resolveConfigSourceFromFlags(programOptions, inputReader)
	if err != nil {
		return configSourceSelection{}, err
	}
	if selectionWasProvided {
		return flagBasedSelection, nil
	}

	return discoverConfigSourceNearBinary(programOptions, inputReader)
}

// resolveConfigSourceFromFlags handles -env-file / -json-file selection and conflict resolution.
func resolveConfigSourceFromFlags(programOptions *options, inputReader *bufio.Reader) (configSourceSelection, bool, error) {
	explicitDotEnvPath := strings.TrimSpace(programOptions.envFile)
	explicitJSONPath := strings.TrimSpace(programOptions.jsonFile)

	if explicitDotEnvPath == "" && explicitJSONPath == "" {
		return configSourceSelection{}, false, nil
	}

	if explicitDotEnvPath != "" && explicitJSONPath != "" {
		if !isInteractiveSession() {
			return configSourceSelection{}, false, errors.New("both -env-file and -json-file are set; choose one in an interactive terminal")
		}

		choice, err := promptConfigSourceMenu(inputReader, explicitDotEnvPath, explicitJSONPath, false)
		if err != nil {
			return configSourceSelection{}, false, err
		}

		switch choice {
		case configSourceTypeDotEnv:
			programOptions.envFile = explicitDotEnvPath
			programOptions.jsonFile = ""
			return configSourceSelection{sourceType: configSourceTypeDotEnv, sourcePath: explicitDotEnvPath}, true, nil
		case configSourceTypeJSON:
			programOptions.jsonFile = explicitJSONPath
			programOptions.envFile = ""
			return configSourceSelection{sourceType: configSourceTypeJSON, sourcePath: explicitJSONPath}, true, nil
		default:
			return configSourceSelection{}, false, errors.New("invalid source choice")
		}
	}

	if explicitDotEnvPath != "" {
		programOptions.jsonFile = ""
		return configSourceSelection{sourceType: configSourceTypeDotEnv, sourcePath: explicitDotEnvPath}, true, nil
	}

	programOptions.envFile = ""
	return configSourceSelection{sourceType: configSourceTypeJSON, sourcePath: explicitJSONPath}, true, nil
}

// discoverConfigSourceNearBinary checks for config files beside the executable and prompts for usage.
func discoverConfigSourceNearBinary(programOptions *options, inputReader *bufio.Reader) (configSourceSelection, error) {
	if !isInteractiveSession() {
		return configSourceSelection{}, nil
	}

	dotEnvPath, jsonConfigPath, err := discoverConfigFilesNearBinary()
	if err != nil {
		return configSourceSelection{}, err
	}

	if dotEnvPath == "" && jsonConfigPath == "" {
		return configSourceSelection{}, nil
	}

	if dotEnvPath != "" && jsonConfigPath != "" {
		choice, err := promptConfigSourceMenu(inputReader, dotEnvPath, jsonConfigPath, true)
		if err != nil {
			return configSourceSelection{}, err
		}

		switch choice {
		case configSourceTypeDotEnv:
			programOptions.envFile = dotEnvPath
			programOptions.jsonFile = ""
			return configSourceSelection{sourceType: configSourceTypeDotEnv, sourcePath: dotEnvPath}, nil
		case configSourceTypeJSON:
			programOptions.jsonFile = jsonConfigPath
			programOptions.envFile = ""
			return configSourceSelection{sourceType: configSourceTypeJSON, sourcePath: jsonConfigPath}, nil
		default:
			return configSourceSelection{}, nil
		}
	}

	if dotEnvPath != "" {
		useDotEnv, err := promptUseSingleConfigSource(inputReader, ".env", dotEnvPath)
		if err != nil {
			return configSourceSelection{}, err
		}
		if useDotEnv {
			programOptions.envFile = dotEnvPath
			programOptions.jsonFile = ""
			return configSourceSelection{sourceType: configSourceTypeDotEnv, sourcePath: dotEnvPath}, nil
		}
		return configSourceSelection{}, nil
	}

	useJSONConfig, err := promptUseSingleConfigSource(inputReader, "config.json", jsonConfigPath)
	if err != nil {
		return configSourceSelection{}, err
	}
	if useJSONConfig {
		programOptions.jsonFile = jsonConfigPath
		programOptions.envFile = ""
		return configSourceSelection{sourceType: configSourceTypeJSON, sourcePath: jsonConfigPath}, nil
	}

	return configSourceSelection{}, nil
}

// discoverConfigFilesNearBinary returns existing .env/config.json paths beside the executable.
func discoverConfigFilesNearBinary() (string, string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", "", fmt.Errorf("resolve executable path: %w", err)
	}

	executableDirectory := filepath.Dir(executablePath)
	dotEnvPath := filepath.Join(executableDirectory, defaultBinaryDotEnvFilename)
	jsonConfigPath := filepath.Join(executableDirectory, defaultBinaryJSONConfigFilename)

	if !fileExists(dotEnvPath) {
		dotEnvPath = ""
	}
	if !fileExists(jsonConfigPath) {
		jsonConfigPath = ""
	}

	return dotEnvPath, jsonConfigPath, nil
}

// promptConfigSourceMenu presents a numbered selection when multiple config sources are available.
func promptConfigSourceMenu(inputReader *bufio.Reader, dotEnvPath, jsonConfigPath string, allowSkip bool) (string, error) {
	for {
		fmt.Println("Config files detected. Choose which one to use:")
		fmt.Printf("1) .env (%s)\n", dotEnvPath)
		fmt.Printf("2) config.json (%s)\n", jsonConfigPath)
		if allowSkip {
			fmt.Println("3) Do not use any config file")
		}

		selectionPrompt := "Select option [1-2]: "
		if allowSkip {
			selectionPrompt = "Select option [1-3]: "
		}

		selection, err := promptLine(inputReader, selectionPrompt)
		if err != nil {
			return "", err
		}

		switch strings.TrimSpace(selection) {
		case "1":
			return configSourceTypeDotEnv, nil
		case "2":
			return configSourceTypeJSON, nil
		case "3":
			if allowSkip {
				return "", nil
			}
		}

		fmt.Println("Invalid selection. Please enter one of the listed numbers.")
	}
}

// promptUseSingleConfigSource asks whether the discovered config file should be used.
func promptUseSingleConfigSource(inputReader *bufio.Reader, displayName, sourcePath string) (bool, error) {
	for {
		answer, err := promptLine(inputReader, fmt.Sprintf("Found %s next to the binary at %q. Use it? [y/n]: ", displayName, sourcePath))
		if err != nil {
			return false, err
		}

		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}

		fmt.Println("Please answer with y or n.")
	}
}

// isInteractiveSession reports whether user prompts can be shown reliably.
func isInteractiveSession() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// fileExists reports whether the given path exists and is not a directory.
func fileExists(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !fileInfo.IsDir()
}

// applyJSONConfigFile reads and applies values from -json-file when provided.
func applyJSONConfigFile(programOptions *options, providedFlagNames map[string]bool) error {
	_, err := applyJSONConfigFileWithMetadata(programOptions, providedFlagNames)
	return err
}

// applyJSONConfigFileWithMetadata reads JSON config values and tracks which fields were loaded.
func applyJSONConfigFileWithMetadata(programOptions *options, providedFlagNames map[string]bool) (map[string]bool, error) {
	loadedFieldNames := map[string]bool{}

	if strings.TrimSpace(programOptions.jsonFile) == "" {
		return loadedFieldNames, nil
	}

	jsonFilePath, err := expandHomePath(strings.TrimSpace(programOptions.jsonFile))
	if err != nil {
		return nil, fmt.Errorf("resolve json config path: %w", err)
	}

	jsonBytes, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return nil, fmt.Errorf("read json config file: %w", err)
	}

	jsonDecoder := json.NewDecoder(strings.NewReader(string(jsonBytes)))
	jsonDecoder.DisallowUnknownFields()

	var parsedJSONConfig jsonConfigOptions
	if err := jsonDecoder.Decode(&parsedJSONConfig); err != nil {
		return nil, fmt.Errorf("parse json config file: %w", err)
	}

	var trailingContentCheck struct{}
	if err := jsonDecoder.Decode(&trailingContentCheck); !errors.Is(err, io.EOF) {
		return nil, errors.New("json config file must contain exactly one JSON object")
	}

	if parsedJSONConfig.Server != nil && !wasFlagProvided(providedFlagNames, "server") {
		programOptions.server = strings.TrimSpace(*parsedJSONConfig.Server)
		loadedFieldNames["server"] = true
	}
	if parsedJSONConfig.Servers != nil && !wasFlagProvided(providedFlagNames, "servers") {
		programOptions.servers = strings.TrimSpace(*parsedJSONConfig.Servers)
		loadedFieldNames["servers"] = true
	}
	if parsedJSONConfig.ServersFile != nil && !wasFlagProvided(providedFlagNames, "servers-file") {
		programOptions.serversFile = strings.TrimSpace(*parsedJSONConfig.ServersFile)
		loadedFieldNames["serversFile"] = true
	}
	if parsedJSONConfig.User != nil && !wasFlagProvided(providedFlagNames, "user") {
		programOptions.user = strings.TrimSpace(*parsedJSONConfig.User)
		loadedFieldNames["user"] = true
	}
	if parsedJSONConfig.Password != nil && !wasFlagProvided(providedFlagNames, "password") {
		programOptions.password = *parsedJSONConfig.Password
		loadedFieldNames["password"] = true
	}
	if parsedJSONConfig.PasswordEnv != nil && !wasFlagProvided(providedFlagNames, "password-env") {
		programOptions.passwordEnv = strings.TrimSpace(*parsedJSONConfig.PasswordEnv)
		loadedFieldNames["passwordEnv"] = true
	}
	if parsedJSONConfig.PubKey != nil && !wasFlagProvided(providedFlagNames, "pubkey") {
		programOptions.pubKey = *parsedJSONConfig.PubKey
		loadedFieldNames["pubKey"] = true
	}
	if parsedJSONConfig.PubKeyFile != nil && !wasFlagProvided(providedFlagNames, "pubkey-file") {
		programOptions.pubKeyFile = strings.TrimSpace(*parsedJSONConfig.PubKeyFile)
		loadedFieldNames["pubKeyFile"] = true
	}
	if parsedJSONConfig.Port != nil && !wasFlagProvided(providedFlagNames, "port") {
		programOptions.port = *parsedJSONConfig.Port
		loadedFieldNames["port"] = true
	}
	if parsedJSONConfig.Timeout != nil && !wasFlagProvided(providedFlagNames, "timeout") {
		programOptions.timeoutSec = *parsedJSONConfig.Timeout
		loadedFieldNames["timeoutSec"] = true
	}
	if parsedJSONConfig.InsecureIgnoreHostKey != nil && !wasFlagProvided(providedFlagNames, "insecure-ignore-host-key") {
		programOptions.insecureIgnoreHostKey = *parsedJSONConfig.InsecureIgnoreHostKey
		loadedFieldNames["insecureIgnoreHostKey"] = true
	}
	if parsedJSONConfig.KnownHosts != nil && !wasFlagProvided(providedFlagNames, "known-hosts") {
		programOptions.knownHosts = strings.TrimSpace(*parsedJSONConfig.KnownHosts)
		loadedFieldNames["knownHosts"] = true
	}

	return loadedFieldNames, nil
}

// applyDotEnvConfigFile reads and applies values from -env-file when provided.
func applyDotEnvConfigFile(programOptions *options, providedFlagNames map[string]bool) error {
	_, err := applyDotEnvConfigFileWithMetadata(programOptions, providedFlagNames)
	return err
}

// applyDotEnvConfigFileWithMetadata reads .env config values and tracks which fields were loaded.
func applyDotEnvConfigFileWithMetadata(programOptions *options, providedFlagNames map[string]bool) (map[string]bool, error) {
	loadedFieldNames := map[string]bool{}

	if strings.TrimSpace(programOptions.envFile) == "" {
		return loadedFieldNames, nil
	}

	envFilePath, err := expandHomePath(strings.TrimSpace(programOptions.envFile))
	if err != nil {
		return nil, fmt.Errorf("resolve .env path: %w", err)
	}

	envBytes, err := os.ReadFile(envFilePath)
	if err != nil {
		return nil, fmt.Errorf("read .env file: %w", err)
	}

	parsedEnvValues, err := parseDotEnvContent(string(envBytes))
	if err != nil {
		return nil, fmt.Errorf("parse .env file: %w", err)
	}

	if serverValue, keyExists := parsedEnvValues["SERVER"]; keyExists && !wasFlagProvided(providedFlagNames, "server") {
		programOptions.server = strings.TrimSpace(serverValue)
		loadedFieldNames["server"] = true
	}
	if serversValue, keyExists := parsedEnvValues["SERVERS"]; keyExists && !wasFlagProvided(providedFlagNames, "servers") {
		programOptions.servers = strings.TrimSpace(serversValue)
		loadedFieldNames["servers"] = true
	}
	if serversFileValue, keyExists := parsedEnvValues["SERVERS_FILE"]; keyExists && !wasFlagProvided(providedFlagNames, "servers-file") {
		programOptions.serversFile = strings.TrimSpace(serversFileValue)
		loadedFieldNames["serversFile"] = true
	}
	if userValue, keyExists := parsedEnvValues["USER"]; keyExists && !wasFlagProvided(providedFlagNames, "user") {
		programOptions.user = strings.TrimSpace(userValue)
		loadedFieldNames["user"] = true
	}
	if passwordValue, keyExists := parsedEnvValues["PASSWORD"]; keyExists && !wasFlagProvided(providedFlagNames, "password") {
		programOptions.password = passwordValue
		loadedFieldNames["password"] = true
	}
	if passwordEnvValue, keyExists := parsedEnvValues["PASSWORD_ENV"]; keyExists && !wasFlagProvided(providedFlagNames, "password-env") {
		programOptions.passwordEnv = strings.TrimSpace(passwordEnvValue)
		loadedFieldNames["passwordEnv"] = true
	}
	if publicKeyValue, keyExists := parsedEnvValues["PUBKEY"]; keyExists && !wasFlagProvided(providedFlagNames, "pubkey") {
		programOptions.pubKey = publicKeyValue
		loadedFieldNames["pubKey"] = true
	}
	if publicKeyFileValue, keyExists := parsedEnvValues["PUBKEY_FILE"]; keyExists && !wasFlagProvided(providedFlagNames, "pubkey-file") {
		programOptions.pubKeyFile = strings.TrimSpace(publicKeyFileValue)
		loadedFieldNames["pubKeyFile"] = true
	}
	if portValue, keyExists := parsedEnvValues["PORT"]; keyExists && !wasFlagProvided(providedFlagNames, "port") {
		portNumber, conversionErr := strconv.Atoi(strings.TrimSpace(portValue))
		if conversionErr != nil {
			return nil, fmt.Errorf(".env key PORT must be an integer: %w", conversionErr)
		}
		programOptions.port = portNumber
		loadedFieldNames["port"] = true
	}
	if timeoutValue, keyExists := parsedEnvValues["TIMEOUT"]; keyExists && !wasFlagProvided(providedFlagNames, "timeout") {
		timeoutSeconds, conversionErr := strconv.Atoi(strings.TrimSpace(timeoutValue))
		if conversionErr != nil {
			return nil, fmt.Errorf(".env key TIMEOUT must be an integer: %w", conversionErr)
		}
		programOptions.timeoutSec = timeoutSeconds
		loadedFieldNames["timeoutSec"] = true
	}
	if insecureValue, keyExists := parsedEnvValues["INSECURE_IGNORE_HOST_KEY"]; keyExists && !wasFlagProvided(providedFlagNames, "insecure-ignore-host-key") {
		insecureMode, conversionErr := strconv.ParseBool(strings.TrimSpace(insecureValue))
		if conversionErr != nil {
			return nil, fmt.Errorf(".env key INSECURE_IGNORE_HOST_KEY must be a boolean: %w", conversionErr)
		}
		programOptions.insecureIgnoreHostKey = insecureMode
		loadedFieldNames["insecureIgnoreHostKey"] = true
	}
	if knownHostsValue, keyExists := parsedEnvValues["KNOWN_HOSTS"]; keyExists && !wasFlagProvided(providedFlagNames, "known-hosts") {
		programOptions.knownHosts = strings.TrimSpace(knownHostsValue)
		loadedFieldNames["knownHosts"] = true
	}

	return loadedFieldNames, nil
}

// parseDotEnvContent parses KEY=VALUE lines from .env text.
func parseDotEnvContent(dotEnvContent string) (map[string]string, error) {
	parsedValues := map[string]string{}

	lineScanner := bufio.NewScanner(strings.NewReader(normalizeLF(dotEnvContent)))
	lineNumber := 0
	for lineScanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(lineScanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		separatorIndex := strings.Index(line, "=")
		if separatorIndex <= 0 {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", lineNumber)
		}

		key := strings.TrimSpace(line[:separatorIndex])
		if key == "" {
			return nil, fmt.Errorf("line %d: key is empty", lineNumber)
		}

		rawValue := strings.TrimSpace(line[separatorIndex+1:])
		parsedValue, err := parseDotEnvValue(rawValue)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}

		parsedValues[strings.ToUpper(key)] = parsedValue
	}

	if err := lineScanner.Err(); err != nil {
		return nil, err
	}

	return parsedValues, nil
}

// parseDotEnvValue parses one .env value with simple quote and inline-comment support.
func parseDotEnvValue(rawValue string) (string, error) {
	if rawValue == "" {
		return "", nil
	}

	if strings.HasPrefix(rawValue, `"`) {
		if !strings.HasSuffix(rawValue, `"`) || len(rawValue) == 1 {
			return "", errors.New("unterminated double-quoted value")
		}
		parsedValue, err := strconv.Unquote(rawValue)
		if err != nil {
			return "", fmt.Errorf("invalid double-quoted value: %w", err)
		}
		return parsedValue, nil
	}

	if strings.HasPrefix(rawValue, "'") {
		if !strings.HasSuffix(rawValue, "'") || len(rawValue) == 1 {
			return "", errors.New("unterminated single-quoted value")
		}
		return rawValue[1 : len(rawValue)-1], nil
	}

	if inlineCommentIndex := strings.Index(rawValue, " #"); inlineCommentIndex >= 0 {
		rawValue = rawValue[:inlineCommentIndex]
	}

	return strings.TrimSpace(rawValue), nil
}

// confirmLoadedConfigFields asks the user to verify each loaded config value before continuing.
func confirmLoadedConfigFields(inputReader *bufio.Reader, programOptions *options, loadedFieldNames map[string]bool) error {
	if len(loadedFieldNames) == 0 {
		return nil
	}

	acceptAllRemainingValues := false
	fmt.Println("Review loaded configuration values. For each field choose: yes (y), no/edit (n), or yes to all remaining (a).")

	for _, fieldName := range configuredFieldOrder() {
		if !loadedFieldNames[fieldName] {
			continue
		}
		if acceptAllRemainingValues {
			continue
		}

		for {
			fieldPreview := previewConfiguredField(programOptions, fieldName)
			fmt.Printf("%s: %s\n", configFieldDisplayName(fieldName), fieldPreview)

			answer, err := promptLine(inputReader, "Use this value? [y/n/a]: ")
			if err != nil {
				return err
			}

			switch strings.ToLower(strings.TrimSpace(answer)) {
			case "y", "yes":
				goto confirmed
			case "a", "all":
				acceptAllRemainingValues = true
				goto confirmed
			case "n", "no":
				if err := promptReplacementValueForField(inputReader, programOptions, fieldName); err != nil {
					return err
				}
				goto confirmed
			default:
				fmt.Println("Please answer with y, n, or a.")
			}
		}

	confirmed:
	}

	return nil
}

// configuredFieldOrder defines the stable display/confirmation order for loaded config values.
func configuredFieldOrder() []string {
	return []string{
		"server",
		"servers",
		"serversFile",
		"user",
		"password",
		"passwordEnv",
		"pubKey",
		"pubKeyFile",
		"port",
		"timeoutSec",
		"insecureIgnoreHostKey",
		"knownHosts",
	}
}

// configFieldDisplayName returns a human-friendly name for one config field.
func configFieldDisplayName(fieldName string) string {
	switch fieldName {
	case "server":
		return "Server"
	case "servers":
		return "Servers"
	case "serversFile":
		return "Servers File"
	case "user":
		return "SSH User"
	case "password":
		return "SSH Password"
	case "passwordEnv":
		return "Password Env Variable"
	case "pubKey":
		return "Public Key"
	case "pubKeyFile":
		return "Public Key File"
	case "port":
		return "Default Port"
	case "timeoutSec":
		return "Timeout (Seconds)"
	case "insecureIgnoreHostKey":
		return "Insecure Ignore Host Key"
	case "knownHosts":
		return "Known Hosts Path"
	default:
		return fieldName
	}
}

// previewConfiguredField returns a safe preview for one field value.
func previewConfiguredField(programOptions *options, fieldName string) string {
	switch fieldName {
	case "server":
		return previewTextValue(programOptions.server, 80)
	case "servers":
		return previewTextValue(programOptions.servers, 80)
	case "serversFile":
		return previewTextValue(programOptions.serversFile, 80)
	case "user":
		return previewTextValue(programOptions.user, 80)
	case "password":
		return maskSensitiveValue(programOptions.password)
	case "passwordEnv":
		return previewTextValue(programOptions.passwordEnv, 80)
	case "pubKey":
		return previewPublicKeyValue(programOptions.pubKey)
	case "pubKeyFile":
		return previewTextValue(programOptions.pubKeyFile, 80)
	case "port":
		return strconv.Itoa(programOptions.port)
	case "timeoutSec":
		return strconv.Itoa(programOptions.timeoutSec)
	case "insecureIgnoreHostKey":
		return strconv.FormatBool(programOptions.insecureIgnoreHostKey)
	case "knownHosts":
		return previewTextValue(programOptions.knownHosts, 80)
	default:
		return "<unknown>"
	}
}

// previewTextValue renders a readable single-line preview.
func previewTextValue(value string, maxLength int) string {
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return "<empty>"
	}
	if len(trimmedValue) <= maxLength {
		return trimmedValue
	}
	return trimmedValue[:maxLength] + "..."
}

// previewPublicKeyValue renders a readable preview for public keys.
func previewPublicKeyValue(publicKey string) string {
	return previewTextValue(publicKey, 120)
}

// maskSensitiveValue hides most characters while still showing a short prefix.
func maskSensitiveValue(value string) string {
	if value == "" {
		return "<empty>"
	}

	visiblePrefixLength := 3
	if len(value) <= visiblePrefixLength {
		visiblePrefixLength = 1
	}
	return value[:visiblePrefixLength] + "***"
}

// promptReplacementValueForField asks for a replacement value when the user rejects one field.
func promptReplacementValueForField(inputReader *bufio.Reader, programOptions *options, fieldName string) error {
	switch fieldName {
	case "server":
		replacementValue, err := promptLine(inputReader, "Enter updated server (leave empty to clear): ")
		if err != nil {
			return err
		}
		programOptions.server = strings.TrimSpace(replacementValue)
	case "servers":
		replacementValue, err := promptLine(inputReader, "Enter updated servers list (leave empty to clear): ")
		if err != nil {
			return err
		}
		programOptions.servers = strings.TrimSpace(replacementValue)
	case "serversFile":
		replacementValue, err := promptLine(inputReader, "Enter updated servers file path (leave empty to clear): ")
		if err != nil {
			return err
		}
		programOptions.serversFile = strings.TrimSpace(replacementValue)
	case "user":
		replacementValue, err := promptLine(inputReader, "Enter updated SSH username (leave empty to clear): ")
		if err != nil {
			return err
		}
		programOptions.user = strings.TrimSpace(replacementValue)
	case "password":
		replacementPassword, err := promptPasswordAllowEmpty(inputReader, "Enter updated SSH password (leave empty to clear): ")
		if err != nil {
			return err
		}
		programOptions.password = strings.TrimSpace(replacementPassword)
	case "passwordEnv":
		replacementValue, err := promptLine(inputReader, "Enter updated password environment variable (leave empty to clear): ")
		if err != nil {
			return err
		}
		programOptions.passwordEnv = strings.TrimSpace(replacementValue)
	case "pubKey":
		replacementValue, err := promptLine(inputReader, "Enter updated public key text (leave empty to clear): ")
		if err != nil {
			return err
		}
		programOptions.pubKey = strings.TrimSpace(replacementValue)
	case "pubKeyFile":
		replacementValue, err := promptLine(inputReader, "Enter updated public key file path (leave empty to clear): ")
		if err != nil {
			return err
		}
		programOptions.pubKeyFile = strings.TrimSpace(replacementValue)
	case "port":
		for {
			replacementValue, err := promptLine(inputReader, "Enter updated default port: ")
			if err != nil {
				return err
			}
			parsedPort, parseErr := strconv.Atoi(strings.TrimSpace(replacementValue))
			if parseErr != nil {
				fmt.Println("Port must be an integer.")
				continue
			}
			programOptions.port = parsedPort
			break
		}
	case "timeoutSec":
		for {
			replacementValue, err := promptLine(inputReader, "Enter updated timeout in seconds: ")
			if err != nil {
				return err
			}
			parsedTimeout, parseErr := strconv.Atoi(strings.TrimSpace(replacementValue))
			if parseErr != nil {
				fmt.Println("Timeout must be an integer.")
				continue
			}
			programOptions.timeoutSec = parsedTimeout
			break
		}
	case "insecureIgnoreHostKey":
		for {
			replacementValue, err := promptLine(inputReader, "Enter updated insecure-ignore-host-key value (true/false): ")
			if err != nil {
				return err
			}
			parsedValue, parseErr := strconv.ParseBool(strings.TrimSpace(replacementValue))
			if parseErr != nil {
				fmt.Println("Value must be true or false.")
				continue
			}
			programOptions.insecureIgnoreHostKey = parsedValue
			break
		}
	case "knownHosts":
		replacementValue, err := promptLine(inputReader, "Enter updated known_hosts path (leave empty to clear): ")
		if err != nil {
			return err
		}
		programOptions.knownHosts = strings.TrimSpace(replacementValue)
	default:
		return fmt.Errorf("unsupported config field %q", fieldName)
	}

	return nil
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

// promptPasswordAllowEmpty reads one password value and allows empty responses.
func promptPasswordAllowEmpty(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(bytes), nil
	}

	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	return strings.TrimSpace(line), nil
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
