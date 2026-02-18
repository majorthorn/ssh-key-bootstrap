package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
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

func (statusErr *statusError) Error() string {
	return statusErr.err.Error()
}

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

func collectProvidedFlagNames() map[string]bool {
	providedFlagNames := map[string]bool{}
	flag.Visit(func(currentFlag *flag.Flag) { providedFlagNames[currentFlag.Name] = true })
	return providedFlagNames
}

func wasFlagProvided(providedFlagNames map[string]bool, flagName string) bool {
	return providedFlagNames[flagName]
}

func fail(code int, format string, args ...any) error {
	return &statusError{code: code, err: fmt.Errorf(format, args...)}
}
