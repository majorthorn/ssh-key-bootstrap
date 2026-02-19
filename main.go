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
	appName                     = "vibe-ssh-lift"
	defaultSSHPort              = 22
	defaultTimeoutSeconds       = 10
	defaultKnownHostsPath       = "~/.ssh/known_hosts"
	defaultBinaryDotEnvFilename = ".env"
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
	user                  string
	password              string
	passwordSecretRef     string
	keyInput              string
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
	programOptions, err := parseFlags()
	if err != nil {
		return fail(2, "%w", err)
	}

	fmt.Println("[INFO] Loading configuration...")
	if err := applyConfigFiles(programOptions); err != nil {
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
	hosts, err := resolveHosts(programOptions.server, programOptions.servers, programOptions.port)
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

func parseFlags() (*options, error) {
	programOptions := &options{
		port:       defaultSSHPort,
		timeoutSec: defaultTimeoutSeconds,
		knownHosts: defaultKnownHostsPath,
	}
	normalizeHelpArg()

	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "Usage: %s [--env <path>]\n\n", appName)
		fmt.Fprintln(output, "Config:")
		fmt.Fprintln(output, "  --env <path>               .env config file")
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Any missing values are prompted interactively.")
	}

	flag.StringVar(&programOptions.envFile, "env", "", "Path to .env config file")

	flag.Parse()
	if flag.NArg() > 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flag.Args(), ", "))
	}
	return programOptions, nil
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
