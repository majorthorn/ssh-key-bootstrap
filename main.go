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
	defaultSSHPort              = 22
	defaultTimeoutSeconds       = 10
	defaultKnownHostsPath       = "~/.ssh/known_hosts"
	defaultBinaryDotEnvFilename = ".env"
	defaultBinaryJSONConfigFile = "config.json"
)

const addAuthorizedKeyScript = "set -eu\n" +
	"umask 077\n" +
	"mkdir -p ~/.ssh\n" +
	"touch ~/.ssh/authorized_keys\n" +
	"chmod 700 ~/.ssh\n" +
	"chmod 600 ~/.ssh/authorized_keys\n" +
	"IFS= read -r KEY\n" +
	"grep -qxF \"$KEY\" ~/.ssh/authorized_keys || printf '%s\\n' \"$KEY\" >> ~/.ssh/authorized_keys\n"

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

type statusError struct {
	code int
	err  error
}

func (statusErr *statusError) Error() string { return statusErr.err.Error() }

func main() {
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

func run() error {
	programOptions := parseFlags()
	providedFlagNames := collectProvidedFlagNames()

	if err := applyConfigFiles(programOptions, providedFlagNames); err != nil {
		return fail(2, "%w", err)
	}
	if err := validateOptions(programOptions); err != nil {
		return fail(2, "%w", err)
	}

	inputReader := bufio.NewReader(os.Stdin)
	if err := fillMissingInputs(inputReader, programOptions); err != nil {
		return fail(2, "%w", err)
	}

	hosts, err := resolveHosts(programOptions.server, programOptions.servers, programOptions.serversFile, programOptions.port)
	if err != nil {
		return fail(2, "%w", err)
	}

	publicKey, err := resolvePublicKey(programOptions.pubKey, programOptions.pubKeyFile)
	if err != nil {
		return fail(2, "%w", err)
	}

	clientConfig, err := buildSSHConfig(programOptions)
	if err != nil {
		return fail(2, "%w", err)
	}

	failures := 0
	for _, host := range hosts {
		if err := addAuthorizedKey(host, publicKey, clientConfig); err != nil {
			failures++
			fmt.Printf("[FAIL] %s: %v\n", host, err)
			continue
		}
		fmt.Printf("[OK]   %s\n", host)
	}

	if failures > 0 {
		return fail(1, "%d host(s) failed", failures)
	}
	return nil
}

func fail(code int, format string, args ...any) error {
	return &statusError{code: code, err: fmt.Errorf(format, args...)}
}

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

func collectProvidedFlagNames() map[string]bool {
	providedFlagNames := map[string]bool{}
	flag.Visit(func(currentFlag *flag.Flag) { providedFlagNames[currentFlag.Name] = true })
	return providedFlagNames
}

func wasFlagProvided(providedFlagNames map[string]bool, flagName string) bool {
	return providedFlagNames[flagName]
}

const (
	configSourceTypeDotEnv = "dotenv"
	configSourceTypeJSON   = "json"
)

type configSourceSelection struct {
	sourceType string
	sourcePath string
}

func applyConfigFiles(programOptions *options, providedFlagNames map[string]bool) error {
	inputReader := bufio.NewReader(os.Stdin)

	selectedConfigSource, err := selectConfigSource(programOptions, inputReader)
	if err != nil {
		return err
	}
	if selectedConfigSource.sourceType == "" {
		return nil
	}

	var loadedFieldNames map[string]bool
	switch selectedConfigSource.sourceType {
	case configSourceTypeDotEnv:
		programOptions.envFile, programOptions.jsonFile = selectedConfigSource.sourcePath, ""
		loadedFieldNames, err = applyDotEnvConfigFileWithMetadata(programOptions, providedFlagNames)
	case configSourceTypeJSON:
		programOptions.jsonFile, programOptions.envFile = selectedConfigSource.sourcePath, ""
		loadedFieldNames, err = applyJSONConfigFileWithMetadata(programOptions, providedFlagNames)
	default:
		return fmt.Errorf("unsupported config source type %q", selectedConfigSource.sourceType)
	}
	if err != nil {
		return err
	}
	if !isInteractiveSession() {
		return errors.New("config file confirmation requires an interactive terminal")
	}

	return confirmLoadedConfigFields(inputReader, programOptions, loadedFieldNames)
}

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
			programOptions.envFile, programOptions.jsonFile = explicitDotEnvPath, ""
			return configSourceSelection{sourceType: configSourceTypeDotEnv, sourcePath: explicitDotEnvPath}, true, nil
		case configSourceTypeJSON:
			programOptions.jsonFile, programOptions.envFile = explicitJSONPath, ""
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
			programOptions.envFile, programOptions.jsonFile = dotEnvPath, ""
			return configSourceSelection{sourceType: configSourceTypeDotEnv, sourcePath: dotEnvPath}, nil
		case configSourceTypeJSON:
			programOptions.jsonFile, programOptions.envFile = jsonConfigPath, ""
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
			programOptions.envFile, programOptions.jsonFile = dotEnvPath, ""
			return configSourceSelection{sourceType: configSourceTypeDotEnv, sourcePath: dotEnvPath}, nil
		}
		return configSourceSelection{}, nil
	}

	useJSONConfig, err := promptUseSingleConfigSource(inputReader, "config.json", jsonConfigPath)
	if err != nil {
		return configSourceSelection{}, err
	}
	if useJSONConfig {
		programOptions.jsonFile, programOptions.envFile = jsonConfigPath, ""
		return configSourceSelection{sourceType: configSourceTypeJSON, sourcePath: jsonConfigPath}, nil
	}
	return configSourceSelection{}, nil
}

func discoverConfigFilesNearBinary() (string, string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", "", fmt.Errorf("resolve executable path: %w", err)
	}

	executableDirectory := filepath.Dir(executablePath)
	dotEnvPath := filepath.Join(executableDirectory, defaultBinaryDotEnvFilename)
	jsonConfigPath := filepath.Join(executableDirectory, defaultBinaryJSONConfigFile)
	if !fileExists(dotEnvPath) {
		dotEnvPath = ""
	}
	if !fileExists(jsonConfigPath) {
		jsonConfigPath = ""
	}
	return dotEnvPath, jsonConfigPath, nil
}

func promptConfigSourceMenu(inputReader *bufio.Reader, dotEnvPath, jsonConfigPath string, allowSkip bool) (string, error) {
	for {
		fmt.Println("Config files detected. Choose which one to use:")
		fmt.Printf("1) .env (%s)\n", dotEnvPath)
		fmt.Printf("2) config.json (%s)\n", jsonConfigPath)
		if allowSkip {
			fmt.Println("3) Do not use any config file")
		}

		prompt := "Select option [1-2]: "
		if allowSkip {
			prompt = "Select option [1-3]: "
		}
		selection, err := promptLine(inputReader, prompt)
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

func isInteractiveSession() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func fileExists(path string) bool {
	fileInfo, err := os.Stat(path)
	return err == nil && !fileInfo.IsDir()
}

func applyJSONConfigFile(programOptions *options, providedFlagNames map[string]bool) error {
	_, err := applyJSONConfigFileWithMetadata(programOptions, providedFlagNames)
	return err
}

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

	setLoaded := func(flagName, fieldName string, apply func()) {
		if wasFlagProvided(providedFlagNames, flagName) {
			return
		}
		apply()
		loadedFieldNames[fieldName] = true
	}

	if parsedJSONConfig.Server != nil {
		setLoaded("server", "server", func() { programOptions.server = strings.TrimSpace(*parsedJSONConfig.Server) })
	}
	if parsedJSONConfig.Servers != nil {
		setLoaded("servers", "servers", func() { programOptions.servers = strings.TrimSpace(*parsedJSONConfig.Servers) })
	}
	if parsedJSONConfig.ServersFile != nil {
		setLoaded("servers-file", "serversFile", func() { programOptions.serversFile = strings.TrimSpace(*parsedJSONConfig.ServersFile) })
	}
	if parsedJSONConfig.User != nil {
		setLoaded("user", "user", func() { programOptions.user = strings.TrimSpace(*parsedJSONConfig.User) })
	}
	if parsedJSONConfig.Password != nil {
		setLoaded("password", "password", func() { programOptions.password = *parsedJSONConfig.Password })
	}
	if parsedJSONConfig.PasswordEnv != nil {
		setLoaded("password-env", "passwordEnv", func() { programOptions.passwordEnv = strings.TrimSpace(*parsedJSONConfig.PasswordEnv) })
	}
	if parsedJSONConfig.PubKey != nil {
		setLoaded("pubkey", "pubKey", func() { programOptions.pubKey = *parsedJSONConfig.PubKey })
	}
	if parsedJSONConfig.PubKeyFile != nil {
		setLoaded("pubkey-file", "pubKeyFile", func() { programOptions.pubKeyFile = strings.TrimSpace(*parsedJSONConfig.PubKeyFile) })
	}
	if parsedJSONConfig.Port != nil {
		setLoaded("port", "port", func() { programOptions.port = *parsedJSONConfig.Port })
	}
	if parsedJSONConfig.Timeout != nil {
		setLoaded("timeout", "timeoutSec", func() { programOptions.timeoutSec = *parsedJSONConfig.Timeout })
	}
	if parsedJSONConfig.InsecureIgnoreHostKey != nil {
		setLoaded("insecure-ignore-host-key", "insecureIgnoreHostKey", func() { programOptions.insecureIgnoreHostKey = *parsedJSONConfig.InsecureIgnoreHostKey })
	}
	if parsedJSONConfig.KnownHosts != nil {
		setLoaded("known-hosts", "knownHosts", func() { programOptions.knownHosts = strings.TrimSpace(*parsedJSONConfig.KnownHosts) })
	}

	return loadedFieldNames, nil
}

func applyDotEnvConfigFile(programOptions *options, providedFlagNames map[string]bool) error {
	_, err := applyDotEnvConfigFileWithMetadata(programOptions, providedFlagNames)
	return err
}

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

	setLoaded := func(flagName, fieldName string, apply func() error) error {
		if wasFlagProvided(providedFlagNames, flagName) {
			return nil
		}
		if err := apply(); err != nil {
			return err
		}
		loadedFieldNames[fieldName] = true
		return nil
	}

	if serverValue, ok := parsedEnvValues["SERVER"]; ok {
		_ = setLoaded("server", "server", func() error { programOptions.server = strings.TrimSpace(serverValue); return nil })
	}
	if serversValue, ok := parsedEnvValues["SERVERS"]; ok {
		_ = setLoaded("servers", "servers", func() error { programOptions.servers = strings.TrimSpace(serversValue); return nil })
	}
	if serversFileValue, ok := parsedEnvValues["SERVERS_FILE"]; ok {
		_ = setLoaded("servers-file", "serversFile", func() error { programOptions.serversFile = strings.TrimSpace(serversFileValue); return nil })
	}
	if userValue, ok := parsedEnvValues["USER"]; ok {
		_ = setLoaded("user", "user", func() error { programOptions.user = strings.TrimSpace(userValue); return nil })
	}
	if passwordValue, ok := parsedEnvValues["PASSWORD"]; ok {
		_ = setLoaded("password", "password", func() error { programOptions.password = passwordValue; return nil })
	}
	if passwordEnvValue, ok := parsedEnvValues["PASSWORD_ENV"]; ok {
		_ = setLoaded("password-env", "passwordEnv", func() error { programOptions.passwordEnv = strings.TrimSpace(passwordEnvValue); return nil })
	}
	if publicKeyValue, ok := parsedEnvValues["PUBKEY"]; ok {
		_ = setLoaded("pubkey", "pubKey", func() error { programOptions.pubKey = publicKeyValue; return nil })
	}
	if publicKeyFileValue, ok := parsedEnvValues["PUBKEY_FILE"]; ok {
		_ = setLoaded("pubkey-file", "pubKeyFile", func() error { programOptions.pubKeyFile = strings.TrimSpace(publicKeyFileValue); return nil })
	}
	if portValue, ok := parsedEnvValues["PORT"]; ok {
		if err := setLoaded("port", "port", func() error {
			portNumber, conversionErr := strconv.Atoi(strings.TrimSpace(portValue))
			if conversionErr != nil {
				return fmt.Errorf(".env key PORT must be an integer: %w", conversionErr)
			}
			programOptions.port = portNumber
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if timeoutValue, ok := parsedEnvValues["TIMEOUT"]; ok {
		if err := setLoaded("timeout", "timeoutSec", func() error {
			timeoutSeconds, conversionErr := strconv.Atoi(strings.TrimSpace(timeoutValue))
			if conversionErr != nil {
				return fmt.Errorf(".env key TIMEOUT must be an integer: %w", conversionErr)
			}
			programOptions.timeoutSec = timeoutSeconds
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if insecureValue, ok := parsedEnvValues["INSECURE_IGNORE_HOST_KEY"]; ok {
		if err := setLoaded("insecure-ignore-host-key", "insecureIgnoreHostKey", func() error {
			insecureMode, conversionErr := strconv.ParseBool(strings.TrimSpace(insecureValue))
			if conversionErr != nil {
				return fmt.Errorf(".env key INSECURE_IGNORE_HOST_KEY must be a boolean: %w", conversionErr)
			}
			programOptions.insecureIgnoreHostKey = insecureMode
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if knownHostsValue, ok := parsedEnvValues["KNOWN_HOSTS"]; ok {
		_ = setLoaded("known-hosts", "knownHosts", func() error { programOptions.knownHosts = strings.TrimSpace(knownHostsValue); return nil })
	}

	return loadedFieldNames, nil
}

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

type configField struct {
	key           string
	label         string
	prompt        string
	kind          string
	passwordInput bool
	get           func(*options) string
	set           func(*options, string) error
}

func confirmLoadedConfigFields(inputReader *bufio.Reader, programOptions *options, loadedFieldNames map[string]bool) error {
	if len(loadedFieldNames) == 0 {
		return nil
	}

	acceptAllRemainingValues := false
	fmt.Println("Review loaded configuration values. For each field choose: yes (y), no/edit (n), or yes to all remaining (a).")

	for _, field := range configFields() {
		if !loadedFieldNames[field.key] || acceptAllRemainingValues {
			continue
		}

		for {
			fmt.Printf("%s: %s\n", field.label, previewFieldValue(field, programOptions))

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
				if err := promptReplacementValueForField(inputReader, programOptions, field); err != nil {
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

func configFields() []configField {
	return []configField{
		{key: "server", label: "Server", prompt: "Enter updated server (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.server }, set: func(optionsValue *options, value string) error {
			optionsValue.server = strings.TrimSpace(value)
			return nil
		}},
		{key: "servers", label: "Servers", prompt: "Enter updated servers list (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.servers }, set: func(optionsValue *options, value string) error {
			optionsValue.servers = strings.TrimSpace(value)
			return nil
		}},
		{key: "serversFile", label: "Servers File", prompt: "Enter updated servers file path (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.serversFile }, set: func(optionsValue *options, value string) error {
			optionsValue.serversFile = strings.TrimSpace(value)
			return nil
		}},
		{key: "user", label: "SSH User", prompt: "Enter updated SSH username (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.user }, set: func(optionsValue *options, value string) error {
			optionsValue.user = strings.TrimSpace(value)
			return nil
		}},
		{key: "password", label: "SSH Password", prompt: "Enter updated SSH password (leave empty to clear): ", kind: "password", passwordInput: true, get: func(optionsValue *options) string { return optionsValue.password }, set: func(optionsValue *options, value string) error {
			optionsValue.password = strings.TrimSpace(value)
			return nil
		}},
		{key: "passwordEnv", label: "Password Env Variable", prompt: "Enter updated password environment variable (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.passwordEnv }, set: func(optionsValue *options, value string) error {
			optionsValue.passwordEnv = strings.TrimSpace(value)
			return nil
		}},
		{key: "pubKey", label: "Public Key", prompt: "Enter updated public key text (leave empty to clear): ", kind: "publickey", get: func(optionsValue *options) string { return optionsValue.pubKey }, set: func(optionsValue *options, value string) error {
			optionsValue.pubKey = strings.TrimSpace(value)
			return nil
		}},
		{key: "pubKeyFile", label: "Public Key File", prompt: "Enter updated public key file path (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.pubKeyFile }, set: func(optionsValue *options, value string) error {
			optionsValue.pubKeyFile = strings.TrimSpace(value)
			return nil
		}},
		{key: "port", label: "Default Port", prompt: "Enter updated default port: ", kind: "text", get: func(optionsValue *options) string { return strconv.Itoa(optionsValue.port) }, set: func(optionsValue *options, value string) error {
			parsedPort, parseErr := strconv.Atoi(strings.TrimSpace(value))
			if parseErr != nil {
				return errors.New("port must be an integer")
			}
			optionsValue.port = parsedPort
			return nil
		}},
		{key: "timeoutSec", label: "Timeout (Seconds)", prompt: "Enter updated timeout in seconds: ", kind: "text", get: func(optionsValue *options) string { return strconv.Itoa(optionsValue.timeoutSec) }, set: func(optionsValue *options, value string) error {
			parsedTimeout, parseErr := strconv.Atoi(strings.TrimSpace(value))
			if parseErr != nil {
				return errors.New("timeout must be an integer")
			}
			optionsValue.timeoutSec = parsedTimeout
			return nil
		}},
		{key: "insecureIgnoreHostKey", label: "Insecure Ignore Host Key", prompt: "Enter updated insecure-ignore-host-key value (true/false): ", kind: "text", get: func(optionsValue *options) string { return strconv.FormatBool(optionsValue.insecureIgnoreHostKey) }, set: func(optionsValue *options, value string) error {
			parsedValue, parseErr := strconv.ParseBool(strings.TrimSpace(value))
			if parseErr != nil {
				return errors.New("value must be true or false")
			}
			optionsValue.insecureIgnoreHostKey = parsedValue
			return nil
		}},
		{key: "knownHosts", label: "Known Hosts Path", prompt: "Enter updated known_hosts path (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.knownHosts }, set: func(optionsValue *options, value string) error {
			optionsValue.knownHosts = strings.TrimSpace(value)
			return nil
		}},
	}
}

func previewFieldValue(field configField, programOptions *options) string {
	value := field.get(programOptions)
	switch field.kind {
	case "password":
		return maskSensitiveValue(value)
	case "publickey":
		return previewTextValue(value, 120)
	default:
		return previewTextValue(value, 80)
	}
}

func promptReplacementValueForField(inputReader *bufio.Reader, programOptions *options, field configField) error {
	for {
		var replacementValue string
		var err error
		if field.passwordInput {
			replacementValue, err = promptPasswordAllowEmpty(inputReader, field.prompt)
		} else {
			replacementValue, err = promptLine(inputReader, field.prompt)
		}
		if err != nil {
			return err
		}
		if err := field.set(programOptions, replacementValue); err != nil {
			fmt.Println(err.Error())
			continue
		}
		return nil
	}
}

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

func validateOptions(programOptions *options) error {
	if programOptions.port < 1 || programOptions.port > 65535 {
		return errors.New("port must be in range 1..65535")
	}
	if programOptions.timeoutSec <= 0 {
		return errors.New("timeout must be greater than zero")
	}
	if strings.TrimSpace(programOptions.password) != "" && strings.TrimSpace(programOptions.passwordEnv) != "" {
		return errors.New("use either -password or -password-env, not both")
	}

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

func fillMissingInputs(inputReader *bufio.Reader, programOptions *options) error {
	var err error

	if strings.TrimSpace(programOptions.user) == "" {
		programOptions.user, err = promptRequired(inputReader, "SSH username: ")
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(programOptions.password) == "" {
		programOptions.password, err = promptPassword(inputReader, "SSH password: ")
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(programOptions.server) == "" &&
		strings.TrimSpace(programOptions.servers) == "" &&
		strings.TrimSpace(programOptions.serversFile) == "" {
		programOptions.servers, err = promptRequired(inputReader, "Servers (comma-separated, host or host:port): ")
		if err != nil {
			return err
		}
	}

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

func expandHomePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

func promptLine(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

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

func promptPassword(reader *bufio.Reader, label string) (string, error) {
	for {
		fmt.Print(label)

		var passwordInput string
		if term.IsTerminal(int(os.Stdin.Fd())) {
			bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return "", err
			}
			passwordInput = strings.TrimSpace(string(bytes))
		} else {
			line, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			passwordInput = strings.TrimSpace(line)
		}

		if passwordInput != "" {
			return passwordInput, nil
		}
		fmt.Println("Value is required.")
	}
}

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

	if err := addHost(server); err != nil {
		return nil, err
	}
	for _, candidateEntry := range strings.Split(servers, ",") {
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

func normalizeLF(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.ReplaceAll(value, "\r", "\n")
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
