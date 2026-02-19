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
	keyInput              string
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

	fmt.Println("[INFO] Loading configuration...")
	if err := applyConfigFiles(programOptions, providedFlagNames); err != nil {
		return fail(2, "%w", err)
	}
	fmt.Println("[INFO] Validating options...")
	if err := validateOptions(programOptions); err != nil {
		return fail(2, "%w", err)
	}

	inputReader := bufio.NewReader(os.Stdin)
	fmt.Println("[INFO] Collecting missing inputs...")
	if err := fillMissingInputs(inputReader, programOptions); err != nil {
		return fail(2, "%w", err)
	}

	fmt.Println("[INFO] Resolving target hosts...")
	hosts, err := resolveHosts(programOptions.server, programOptions.servers, programOptions.serversFile, programOptions.port)
	if err != nil {
		return fail(2, "%w", err)
	}
	fmt.Printf("[INFO] %d host(s) queued.\n", len(hosts))

	fmt.Println("[INFO] Resolving public key...")
	publicKey, err := resolvePublicKey(programOptions.keyInput)
	if err != nil {
		return fail(2, "%w", err)
	}

	fmt.Println("[INFO] Building SSH client configuration...")
	clientConfig, err := buildSSHConfig(programOptions)
	if err != nil {
		return fail(2, "%w", err)
	}

	failures := 0
	for _, host := range hosts {
		fmt.Printf("[INFO] [%s] Starting...\n", host)
		if err := addAuthorizedKeyWithStatus(host, publicKey, clientConfig, func(format string, args ...any) {
			fmt.Printf("[INFO] [%s] %s\n", host, fmt.Sprintf(format, args...))
		}); err != nil {
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
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintln(output, "Target Hosts:")
		fmt.Fprintln(output, "  --host, -s <hosts>         Comma-separated hosts (host or host:port)")
		fmt.Fprintln(output, "  --hosts-file, -f <path>    File with one host per line")
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Authentication:")
		fmt.Fprintln(output, "  --user, -u <name>          SSH username")
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Key Input:")
		fmt.Fprintln(output, "  --key, -k <value>          Public key text or public key file path")
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Config:")
		fmt.Fprintln(output, "  --json, -j <path>          JSON config file")
		fmt.Fprintln(output, "  --env, -d <path>           .env config file")
		fmt.Fprintln(output, "  --skip-review, -r          Skip interactive config review")
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Connection:")
		fmt.Fprintf(output, "  --port, -p <n>             Default SSH port (default: %d)\n", defaultSSHPort)
		fmt.Fprintf(output, "  --timeout, -t <sec>        SSH timeout seconds (default: %d)\n", defaultTimeoutSeconds)
		fmt.Fprintf(output, "  --known, -o <path>         known_hosts path (default: %s)\n", defaultKnownHostsPath)
		fmt.Fprintln(output, "  --insecure, -i             Disable host key verification (unsafe)")
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Help:")
		fmt.Fprintln(output, "  --help, -h                 Show this help")
	}

	flag.StringVar(&programOptions.server, "host", "", "Comma-separated hosts")
	flag.StringVar(&programOptions.server, "s", "", "Short for --host")
	flag.StringVar(&programOptions.serversFile, "hosts-file", "", "Path to hosts file")
	flag.StringVar(&programOptions.serversFile, "f", "", "Short for --hosts-file")

	flag.StringVar(&programOptions.user, "user", "", "SSH username")
	flag.StringVar(&programOptions.user, "u", "", "Short for --user")

	flag.StringVar(&programOptions.keyInput, "key", "", "Public key text or public key file path")
	flag.StringVar(&programOptions.keyInput, "k", "", "Short for --key")
	flag.StringVar(&programOptions.jsonFile, "json", "", "Path to JSON config file")
	flag.StringVar(&programOptions.jsonFile, "j", "", "Short for --json")
	flag.StringVar(&programOptions.envFile, "env", "", "Path to .env config file")
	flag.StringVar(&programOptions.envFile, "d", "", "Short for --env")
	flag.BoolVar(&programOptions.skipConfigReview, "skip-review", false, "Skip config review prompts")
	flag.BoolVar(&programOptions.skipConfigReview, "r", false, "Short for --skip-review")

	flag.IntVar(&programOptions.port, "port", defaultSSHPort, "Default SSH port when not specified in server entry")
	flag.IntVar(&programOptions.port, "p", defaultSSHPort, "Short for --port")
	flag.IntVar(&programOptions.timeoutSec, "timeout", defaultTimeoutSeconds, "SSH timeout in seconds")
	flag.IntVar(&programOptions.timeoutSec, "t", defaultTimeoutSeconds, "Short for --timeout")

	flag.BoolVar(&programOptions.insecureIgnoreHostKey, "insecure", false, "Disable host key verification (unsafe)")
	flag.BoolVar(&programOptions.insecureIgnoreHostKey, "i", false, "Short for --insecure")
	flag.StringVar(&programOptions.knownHosts, "known", defaultKnownHostsPath, "Path to known_hosts file")
	flag.StringVar(&programOptions.knownHosts, "o", defaultKnownHostsPath, "Short for --known")

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
		"key":         "key",
		"k":           "key",
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
