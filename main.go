package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
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
	skipConfigReview      bool
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
	normalizeHelpArg()

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Options:")
		flag.PrintDefaults()
	}

	flag.StringVar(&programOptions.server, "server", "", "Hosts (host or host:port, comma-separated)")
	flag.StringVar(&programOptions.server, "host", "", "Alias for -server")
	flag.StringVar(&programOptions.server, "s", "", "Alias for -server")
	flag.StringVar(&programOptions.serversFile, "servers-file", "", "File with one server per line")
	flag.StringVar(&programOptions.serversFile, "hosts-file", "", "Alias for -servers-file")
	flag.StringVar(&programOptions.serversFile, "f", "", "Alias for -servers-file")

	flag.StringVar(&programOptions.user, "user", "", "SSH username")
	flag.StringVar(&programOptions.user, "u", "", "Alias for -user")
	flag.StringVar(&programOptions.password, "password", "", "SSH password (less secure than prompt)")
	flag.StringVar(&programOptions.password, "pass", "", "Alias for -password")
	flag.StringVar(&programOptions.password, "w", "", "Alias for -password")
	flag.StringVar(&programOptions.passwordEnv, "password-env", "", "Environment variable containing SSH password")
	flag.StringVar(&programOptions.passwordEnv, "pass-env", "", "Alias for -password-env")
	flag.StringVar(&programOptions.passwordEnv, "e", "", "Alias for -password-env")

	flag.StringVar(&programOptions.pubKey, "pubkey", "", "Public key text (e.g. ssh-ed25519 AAAA...)")
	flag.StringVar(&programOptions.pubKey, "key", "", "Alias for -pubkey")
	flag.StringVar(&programOptions.pubKey, "k", "", "Alias for -pubkey")
	flag.StringVar(&programOptions.pubKeyFile, "pubkey-file", "", "Path to public key file")
	flag.StringVar(&programOptions.pubKeyFile, "key-file", "", "Alias for -pubkey-file")
	flag.StringVar(&programOptions.pubKeyFile, "K", "", "Alias for -pubkey-file")
	flag.StringVar(&programOptions.jsonFile, "json-file", "", "Path to JSON config file")
	flag.StringVar(&programOptions.jsonFile, "json", "", "Alias for -json-file")
	flag.StringVar(&programOptions.jsonFile, "j", "", "Alias for -json-file")
	flag.StringVar(&programOptions.envFile, "env-file", "", "Path to .env config file")
	flag.StringVar(&programOptions.envFile, "env", "", "Alias for -env-file")
	flag.StringVar(&programOptions.envFile, "d", "", "Alias for -env-file")
	flag.BoolVar(&programOptions.skipConfigReview, "skip-config-review", false, "Skip interactive review of values loaded from config files")
	flag.BoolVar(&programOptions.skipConfigReview, "skip-review", false, "Alias for -skip-config-review")
	flag.BoolVar(&programOptions.skipConfigReview, "r", false, "Alias for -skip-config-review")

	flag.IntVar(&programOptions.port, "port", defaultSSHPort, "Default SSH port when not specified in server entry")
	flag.IntVar(&programOptions.port, "p", defaultSSHPort, "Alias for -port")
	flag.IntVar(&programOptions.timeoutSec, "timeout", defaultTimeoutSeconds, "SSH timeout in seconds")
	flag.IntVar(&programOptions.timeoutSec, "t", defaultTimeoutSeconds, "Alias for -timeout")

	flag.BoolVar(&programOptions.insecureIgnoreHostKey, "insecure-ignore-host-key", false, "Disable host key verification (unsafe)")
	flag.BoolVar(&programOptions.insecureIgnoreHostKey, "insecure", false, "Alias for -insecure-ignore-host-key")
	flag.BoolVar(&programOptions.insecureIgnoreHostKey, "i", false, "Alias for -insecure-ignore-host-key")
	flag.StringVar(&programOptions.knownHosts, "known-hosts", defaultKnownHostsPath, "Path to known_hosts file")
	flag.StringVar(&programOptions.knownHosts, "known", defaultKnownHostsPath, "Alias for -known-hosts")
	flag.StringVar(&programOptions.knownHosts, "o", defaultKnownHostsPath, "Alias for -known-hosts")

	flag.Parse()
	return programOptions
}

func collectProvidedFlagNames() map[string]bool {
	providedFlagNames := map[string]bool{}
	flag.Visit(func(currentFlag *flag.Flag) { providedFlagNames[canonicalFlagName(currentFlag.Name)] = true })
	return providedFlagNames
}

func wasFlagProvided(providedFlagNames map[string]bool, flagName string) bool {
	return providedFlagNames[flagName]
}

func canonicalFlagName(flagName string) string {
	flagAliases := map[string]string{
		"host":        "server",
		"s":           "server",
		"hosts-file":  "servers-file",
		"f":           "servers-file",
		"u":           "user",
		"pass":        "password",
		"w":           "password",
		"pass-env":    "password-env",
		"e":           "password-env",
		"key":         "pubkey",
		"k":           "pubkey",
		"key-file":    "pubkey-file",
		"K":           "pubkey-file",
		"json":        "json-file",
		"j":           "json-file",
		"env":         "env-file",
		"d":           "env-file",
		"skip-review": "skip-config-review",
		"r":           "skip-config-review",
		"p":           "port",
		"t":           "timeout",
		"insecure":    "insecure-ignore-host-key",
		"i":           "insecure-ignore-host-key",
		"known":       "known-hosts",
		"o":           "known-hosts",
	}
	if canonicalName, exists := flagAliases[flagName]; exists {
		return canonicalName
	}
	return flagName
}

func normalizeHelpArg() {
	for i := 1; i < len(os.Args); i++ {
		if strings.TrimSpace(os.Args[i]) == "--help" {
			os.Args[i] = "-h"
		}
	}
}

func fail(code int, format string, args ...any) error {
	return &statusError{code: code, err: fmt.Errorf(format, args...)}
}
