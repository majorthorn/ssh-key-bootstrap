package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func setCommandLineForTest(t *testing.T, args []string) {
	t.Helper()

	originalArgs := os.Args
	originalCommandLine := flag.CommandLine
	originalUsage := flag.Usage

	os.Args = append([]string(nil), args...)
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalCommandLine
		flag.Usage = originalUsage
	})
}

func captureWriters(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()

	originalOutput := getStandardOutputWriter()
	originalError := getStandardErrorWriter()

	outputBuffer := &bytes.Buffer{}
	errorBuffer := &bytes.Buffer{}
	setStandardWriters(outputBuffer, errorBuffer)

	t.Cleanup(func() {
		setStandardWriters(originalOutput, originalError)
	})

	return outputBuffer, errorBuffer
}

func stubPromptPasswordHooks(
	t *testing.T,
	isTerminalStub func(*os.File) bool,
	readPasswordStub func(*os.File) ([]byte, error),
) {
	t.Helper()

	originalIsTerminal := isTerminalForPasswordPrompt
	originalReadPassword := readPasswordForPrompt
	isTerminalForPasswordPrompt = isTerminalStub
	readPasswordForPrompt = readPasswordStub

	t.Cleanup(func() {
		isTerminalForPasswordPrompt = originalIsTerminal
		readPasswordForPrompt = originalReadPassword
	})
}

func stubTrustPromptHooks(
	t *testing.T,
	isTerminalStub func(*os.File) bool,
	promptLineStub func(*bufio.Reader, string) (string, error),
	promptWithTimeoutStub func(*bufio.Reader, string, time.Duration) (string, bool, error),
) {
	t.Helper()

	originalIsTerminal := isTerminalForTrustPrompt
	originalPromptLine := promptLineForTrustPrompt
	originalPromptLineWithTimeout := promptLineForTrustPromptWithTimeout
	isTerminalForTrustPrompt = isTerminalStub
	promptLineForTrustPrompt = promptLineStub
	promptLineForTrustPromptWithTimeout = promptWithTimeoutStub

	t.Cleanup(func() {
		isTerminalForTrustPrompt = originalIsTerminal
		promptLineForTrustPrompt = originalPromptLine
		promptLineForTrustPromptWithTimeout = originalPromptLineWithTimeout
	})
}

func stubSSHDialHook(
	t *testing.T,
	dialStub func(string, string, *ssh.ClientConfig) (*ssh.Client, error),
) {
	t.Helper()

	originalSSHDial := sshDial
	sshDial = dialStub
	t.Cleanup(func() {
		sshDial = originalSSHDial
	})
}

func newSocketPair(t *testing.T) (net.Conn, net.Conn, func()) {
	t.Helper()

	fileDescriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("unix socketpair is unavailable in this environment: %v", err)
	}

	clientFile := os.NewFile(uintptr(fileDescriptors[0]), "client-sock")
	serverFile := os.NewFile(uintptr(fileDescriptors[1]), "server-sock")

	clientConn, err := net.FileConn(clientFile)
	if err != nil {
		_ = clientFile.Close()
		_ = serverFile.Close()
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("socketpair connections are unavailable in this environment: %v", err)
		}
		t.Fatalf("create client net.Conn from socketpair: %v", err)
	}
	serverConn, err := net.FileConn(serverFile)
	if err != nil {
		_ = clientConn.Close()
		_ = clientFile.Close()
		_ = serverFile.Close()
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("socketpair connections are unavailable in this environment: %v", err)
		}
		t.Fatalf("create server net.Conn from socketpair: %v", err)
	}

	_ = clientFile.Close()
	_ = serverFile.Close()

	cleanup := func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	}
	return clientConn, serverConn, cleanup
}

type alwaysFailWriter struct{}

func (alwaysFailWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced write failure")
}

type failOnSecondWrite struct {
	writeCount int
}

func (writer *failOnSecondWrite) Write(data []byte) (int, error) {
	writer.writeCount++
	if writer.writeCount == 2 {
		return 0, errors.New("forced second-write failure")
	}
	return len(data), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("forced read failure")
}

func TestStatusErrorError(t *testing.T) {
	if got := (&statusError{code: 2, err: errors.New("boom")}).Error(); got != "boom" {
		t.Fatalf("statusError.Error() = %q, want %q", got, "boom")
	}
}

func TestStatusErrorErrorNilSafe(t *testing.T) {
	var statusErr *statusError
	if got := statusErr.Error(); got != "" {
		t.Fatalf("nil statusError.Error() = %q, want empty", got)
	}

	statusErr = &statusError{code: 2}
	if got := statusErr.Error(); got != "" {
		t.Fatalf("statusError with nil err returned %q, want empty", got)
	}
}

func TestFailReturnsStatusError(t *testing.T) {
	err := fail(7, "bad input: %s", "value")

	var statusErr *statusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("fail() error type = %T, want *statusError", err)
	}
	if statusErr.code != 7 {
		t.Fatalf("statusErr.code = %d, want %d", statusErr.code, 7)
	}
	if statusErr.Error() != "bad input: value" {
		t.Fatalf("statusErr.Error() = %q, want %q", statusErr.Error(), "bad input: value")
	}
}

func TestParseFlagsDefaults(t *testing.T) {
	setCommandLineForTest(t, []string{"ssh-key-bootstrap"})

	programOptions, err := parseFlags()
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if programOptions.EnvFile != "" {
		t.Fatalf("EnvFile = %q, want empty", programOptions.EnvFile)
	}
	if programOptions.Port != defaultSSHPort {
		t.Fatalf("Port = %d, want %d", programOptions.Port, defaultSSHPort)
	}
	if programOptions.TimeoutSec != defaultTimeoutSeconds {
		t.Fatalf("TimeoutSec = %d, want %d", programOptions.TimeoutSec, defaultTimeoutSeconds)
	}
	if programOptions.KnownHosts != defaultKnownHostsPath {
		t.Fatalf("KnownHosts = %q, want %q", programOptions.KnownHosts, defaultKnownHostsPath)
	}
}

func TestParseFlagsEnv(t *testing.T) {
	setCommandLineForTest(t, []string{"ssh-key-bootstrap", "--env", "/tmp/test.env"})

	programOptions, err := parseFlags()
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if programOptions.EnvFile != "/tmp/test.env" {
		t.Fatalf("EnvFile = %q, want %q", programOptions.EnvFile, "/tmp/test.env")
	}
}

func TestParseFlagsUsageText(t *testing.T) {
	setCommandLineForTest(t, []string{"ssh-key-bootstrap"})
	_, errorBuffer := captureWriters(t)

	if _, err := parseFlags(); err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	flag.Usage()

	usageOutput := errorBuffer.String()
	if !strings.Contains(usageOutput, "Usage: ssh-key-bootstrap [--env <path>]") {
		t.Fatalf("usage output missing usage line: %q", usageOutput)
	}
	if !strings.Contains(usageOutput, "--env <path>") {
		t.Fatalf("usage output missing --env flag docs: %q", usageOutput)
	}
}

func TestParseFlagsUnexpectedPositionalArgs(t *testing.T) {
	setCommandLineForTest(t, []string{"ssh-key-bootstrap", "unexpected-arg"})

	programOptions, err := parseFlags()
	if err == nil {
		t.Fatalf("expected positional arg error")
	}
	if programOptions != nil {
		t.Fatalf("programOptions = %#v, want nil on error", programOptions)
	}
	if !strings.Contains(err.Error(), "unexpected positional arguments") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeHelpArg(t *testing.T) {
	originalArgs := os.Args
	os.Args = []string{"ssh-key-bootstrap", " --help ", "--env", "config.env"}
	t.Cleanup(func() { os.Args = originalArgs })

	normalizeHelpArg()
	if os.Args[1] != "-h" {
		t.Fatalf("os.Args[1] = %q, want %q", os.Args[1], "-h")
	}
	if os.Args[2] != "--env" {
		t.Fatalf("os.Args[2] changed unexpectedly to %q", os.Args[2])
	}
}

func TestRunReturnsStatusErrorForParseFailure(t *testing.T) {
	setCommandLineForTest(t, []string{"ssh-key-bootstrap", "extra"})

	err := run()
	if err == nil {
		t.Fatalf("expected run() error")
	}

	var statusErr *statusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("run() error type = %T, want *statusError", err)
	}
	if statusErr.code != 2 {
		t.Fatalf("statusErr.code = %d, want %d", statusErr.code, 2)
	}
	if !strings.Contains(statusErr.Error(), "unexpected positional arguments") {
		t.Fatalf("unexpected run() error: %v", statusErr)
	}
}

func TestRunReturnsHostFailureWhenSSHDialFails(t *testing.T) {
	outputBuffer, _ := captureWriters(t)

	publicKey := strings.TrimSpace(generateTestKey(t))
	dotEnvPath := filepath.Join(t.TempDir(), ".env")
	dotEnvContent := strings.Join([]string{
		"SERVER=127.0.0.1:1",
		"USER=deploy",
		"PASSWORD=password",
		"KEY='" + publicKey + "'",
		"INSECURE_IGNORE_HOST_KEY=true",
		"TIMEOUT=1",
		"",
	}, "\n")
	if err := os.WriteFile(dotEnvPath, []byte(dotEnvContent), 0o600); err != nil {
		t.Fatalf("write .env file: %v", err)
	}

	setCommandLineForTest(t, []string{"ssh-key-bootstrap", "--env", dotEnvPath})

	err := run()
	if err == nil {
		t.Fatalf("expected run() error")
	}

	var statusErr *statusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("run() error type = %T, want *statusError", err)
	}
	if statusErr.code != 1 {
		t.Fatalf("statusErr.code = %d, want %d", statusErr.code, 1)
	}
	if !strings.Contains(statusErr.Error(), "1 host(s) failed") {
		t.Fatalf("unexpected run() error: %v", statusErr)
	}

	output := outputBuffer.String()
	if !strings.Contains(output, "TASK [Add authorized key]") {
		t.Fatalf("run output missing Add authorized key task: %q", output)
	}
	if !strings.Contains(output, "failed: [127.0.0.1:1]") {
		t.Fatalf("run output missing host failure line: %q", output)
	}
	if !strings.Contains(output, "PLAY RECAP") {
		t.Fatalf("run output missing recap: %q", output)
	}
}

func TestMainExitsWithStatusErrorCode(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_MAIN_EXIT") == "1" {
		os.Args = []string{"ssh-key-bootstrap", "unexpected-positional-arg"}
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		return
	}

	command := exec.Command(os.Args[0], "-test.run=TestMainExitsWithStatusErrorCode")
	command.Env = append(os.Environ(), "GO_WANT_HELPER_MAIN_EXIT=1")
	err := command.Run()
	if err == nil {
		t.Fatalf("expected helper process to exit non-zero")
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError, got %T (%v)", err, err)
	}
	if exitErr.ExitCode() != 2 {
		t.Fatalf("main() exit code = %d, want %d", exitErr.ExitCode(), 2)
	}
}

func TestOutputAnsibleTaskFormatting(t *testing.T) {
	outputBuffer, _ := captureWriters(t)

	outputAnsibleTask("Short task")
	longTaskName := strings.Repeat("x", ansibleTaskPaddingWidth+10)
	outputAnsibleTask(longTaskName)

	output := outputBuffer.String()
	if !strings.Contains(output, "TASK [Short task]") {
		t.Fatalf("missing short task output: %q", output)
	}
	if !strings.Contains(output, "TASK ["+longTaskName+"] *****\n") {
		t.Fatalf("expected minimum 5-star padding for long task; output=%q", output)
	}
}

func TestOutputAnsibleHostStatusFormatting(t *testing.T) {
	outputBuffer, _ := captureWriters(t)

	outputAnsibleHostStatus("ok", "host01", "")
	outputAnsibleHostStatus("failed", "host02", "  permission denied  ")

	output := outputBuffer.String()
	if !strings.Contains(output, "ok: [host01]\n") {
		t.Fatalf("missing ok line: %q", output)
	}
	if !strings.Contains(output, "failed: [host02] => permission denied\n") {
		t.Fatalf("missing failed line: %q", output)
	}
}

func TestOutputAnsiblePlayRecapFormatting(t *testing.T) {
	outputBuffer, _ := captureWriters(t)

	outputAnsiblePlayRecap([]string{"hostA", "hostB"}, map[string]hostRunRecap{
		"hostA": {ok: 1, changed: 1, failed: 0},
		"hostB": {ok: 0, changed: 0, failed: 1},
	})

	output := outputBuffer.String()
	if !strings.Contains(output, "PLAY RECAP") {
		t.Fatalf("missing recap header: %q", output)
	}
	if !strings.Contains(output, "hostA") || !strings.Contains(output, "ok=1 changed=1 unreachable=0 failed=0") {
		t.Fatalf("missing hostA recap line: %q", output)
	}
	if !strings.Contains(output, "hostB") || !strings.Contains(output, "ok=0 changed=0 unreachable=0 failed=1") {
		t.Fatalf("missing hostB recap line: %q", output)
	}
}

func TestPromptRequiredRetriesUntilValue(t *testing.T) {
	outputBuffer, _ := captureWriters(t)
	reader := bufio.NewReader(strings.NewReader("\n  alice\n"))

	value, err := promptRequired(reader, "SSH username: ")
	if err != nil {
		t.Fatalf("promptRequired() error = %v", err)
	}
	if value != "alice" {
		t.Fatalf("promptRequired() value = %q, want %q", value, "alice")
	}

	output := outputBuffer.String()
	if strings.Count(output, "SSH username: ") != 2 {
		t.Fatalf("expected two prompts, output=%q", output)
	}
	if strings.Count(output, "Value is required.") != 1 {
		t.Fatalf("expected one validation message, output=%q", output)
	}
}

func TestPromptRequiredReturnsReaderError(t *testing.T) {
	captureWriters(t)
	reader := bufio.NewReader(errReader{})

	_, err := promptRequired(reader, "SSH username: ")
	if err == nil {
		t.Fatalf("expected promptRequired() error")
	}
	if !strings.Contains(err.Error(), "forced read failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPromptPasswordReadsFromReaderWhenNotTerminal(t *testing.T) {
	if isTerminal(os.Stdin) {
		t.Skip("stdin is a terminal; this test exercises non-interactive password input")
	}

	outputBuffer, _ := captureWriters(t)
	reader := bufio.NewReader(strings.NewReader("\n  secret-password  \n"))

	value, err := promptPassword(reader, os.Stdin, "SSH password: ")
	if err != nil {
		t.Fatalf("promptPassword() error = %v", err)
	}
	if value != "secret-password" {
		t.Fatalf("promptPassword() value = %q, want %q", value, "secret-password")
	}

	output := outputBuffer.String()
	if strings.Count(output, "SSH password: ") != 2 {
		t.Fatalf("expected two password prompts, output=%q", output)
	}
	if strings.Count(output, "Value is required.") != 1 {
		t.Fatalf("expected one validation message, output=%q", output)
	}
}

func TestPromptPasswordUsesTerminalReadPasswordWhenAvailable(t *testing.T) {
	outputBuffer, _ := captureWriters(t)
	stubPromptPasswordHooks(
		t,
		func(*os.File) bool { return true },
		func(*os.File) ([]byte, error) { return []byte("terminal-secret"), nil },
	)

	value, err := promptPassword(bufio.NewReader(strings.NewReader("unused")), os.Stdin, "SSH password: ")
	if err != nil {
		t.Fatalf("promptPassword() error = %v", err)
	}
	if value != "terminal-secret" {
		t.Fatalf("promptPassword() value = %q, want %q", value, "terminal-secret")
	}

	if got := outputBuffer.String(); got != "SSH password: \n" {
		t.Fatalf("unexpected prompt output: %q", got)
	}
}

func TestPromptPasswordTerminalReadError(t *testing.T) {
	outputBuffer, _ := captureWriters(t)
	stubPromptPasswordHooks(
		t,
		func(*os.File) bool { return true },
		func(*os.File) ([]byte, error) { return nil, errors.New("terminal read failed") },
	)

	_, err := promptPassword(bufio.NewReader(strings.NewReader("unused")), os.Stdin, "SSH password: ")
	if err == nil {
		t.Fatalf("expected promptPassword() error")
	}
	if !strings.Contains(err.Error(), "terminal read failed") {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := outputBuffer.String(); got != "SSH password: \n" {
		t.Fatalf("unexpected prompt output: %q", got)
	}
}

func TestPromptPasswordReturnsReaderErrorWhenNotTerminal(t *testing.T) {
	if isTerminal(os.Stdin) {
		t.Skip("stdin is a terminal; this test exercises non-interactive password input")
	}

	captureWriters(t)
	reader := bufio.NewReader(errReader{})

	_, err := promptPassword(reader, os.Stdin, "SSH password: ")
	if err == nil {
		t.Fatalf("expected promptPassword() error")
	}
	if !strings.Contains(err.Error(), "forced read failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPromptPasswordReturnsEOFWhenNotTerminalAndNoInput(t *testing.T) {
	captureWriters(t)
	stubPromptPasswordHooks(
		t,
		func(*os.File) bool { return false },
		func(*os.File) ([]byte, error) { return nil, nil },
	)

	reader := bufio.NewReader(strings.NewReader(""))
	_, err := promptPassword(reader, os.Stdin, "SSH password: ")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestFillMissingInputsPopulatesEmptyFields(t *testing.T) {
	if isTerminal(os.Stdin) {
		t.Skip("stdin is a terminal; this test depends on non-interactive reads")
	}

	captureWriters(t)
	reader := bufio.NewReader(strings.NewReader("deploy\nssh-pass\nhost1,host2\nssh-ed25519 AAAATEST\n"))
	programOptions := &options{}

	if err := fillMissingInputs(reader, programOptions); err != nil {
		t.Fatalf("fillMissingInputs() error = %v", err)
	}
	if programOptions.User != "deploy" {
		t.Fatalf("User = %q, want %q", programOptions.User, "deploy")
	}
	if programOptions.Password != "ssh-pass" {
		t.Fatalf("Password = %q, want %q", programOptions.Password, "ssh-pass")
	}
	if programOptions.Servers != "host1,host2" {
		t.Fatalf("Servers = %q, want %q", programOptions.Servers, "host1,host2")
	}
	if programOptions.KeyInput != "ssh-ed25519 AAAATEST" {
		t.Fatalf("KeyInput = %q, want %q", programOptions.KeyInput, "ssh-ed25519 AAAATEST")
	}
}

func TestFillMissingInputsPropagatesPromptError(t *testing.T) {
	captureWriters(t)
	reader := bufio.NewReader(errReader{})

	err := fillMissingInputs(reader, &options{})
	if err == nil {
		t.Fatalf("expected fillMissingInputs() error")
	}
	if !strings.Contains(err.Error(), "read SSH username") {
		t.Fatalf("expected field-context error, got %v", err)
	}
	if !strings.Contains(err.Error(), "forced read failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFillMissingInputsReturnsEOFForMissingRequiredInput(t *testing.T) {
	captureWriters(t)
	reader := bufio.NewReader(strings.NewReader(""))

	err := fillMissingInputs(reader, &options{})
	if err == nil {
		t.Fatalf("expected fillMissingInputs() EOF-derived error")
	}
	if !strings.Contains(err.Error(), "SSH username is required but input ended (EOF)") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFillMissingInputsSkipsAlreadySetFields(t *testing.T) {
	outputBuffer, _ := captureWriters(t)
	reader := bufio.NewReader(strings.NewReader(""))

	programOptions := &options{
		User:     "existing-user",
		Password: "existing-password",
		Servers:  "host01",
		KeyInput: "ssh-ed25519 AAAAEXISTING",
	}

	if err := fillMissingInputs(reader, programOptions); err != nil {
		t.Fatalf("fillMissingInputs() error = %v", err)
	}
	if outputBuffer.Len() != 0 {
		t.Fatalf("expected no prompts for pre-filled options, output=%q", outputBuffer.String())
	}
}

func TestValidateOptionsAdditionalErrorPaths(t *testing.T) {
	t.Run("invalid port", func(t *testing.T) {
		opts := &options{Port: 0, TimeoutSec: 10}
		err := validateOptions(opts)
		if err == nil || !strings.Contains(err.Error(), "port must be in range") {
			t.Fatalf("expected invalid port error, got %v", err)
		}
	})

	t.Run("invalid timeout", func(t *testing.T) {
		opts := &options{Port: 22, TimeoutSec: 0}
		err := validateOptions(opts)
		if err == nil || !strings.Contains(err.Error(), "timeout must be greater than zero") {
			t.Fatalf("expected invalid timeout error, got %v", err)
		}
	})

	t.Run("secret resolver failure", func(t *testing.T) {
		originalResolver := resolvePasswordFromSecretRef
		resolvePasswordFromSecretRef = func(string) (string, error) {
			return "", errors.New("secret backend unavailable")
		}
		t.Cleanup(func() { resolvePasswordFromSecretRef = originalResolver })

		opts := &options{Port: 22, TimeoutSec: 10, PasswordSecretRef: "bw://prod/ssh"}
		err := validateOptions(opts)
		if err == nil || !strings.Contains(err.Error(), "resolve password secret reference") {
			t.Fatalf("expected secret resolver error, got %v", err)
		}
	})

	t.Run("local provider requires password in non-interactive mode", func(t *testing.T) {
		stubPromptPasswordHooks(
			t,
			func(*os.File) bool { return false },
			func(*os.File) ([]byte, error) { return nil, errors.New("unexpected password read") },
		)
		t.Setenv("PASSWORD", "")

		opts := &options{Port: 22, TimeoutSec: 10, PasswordProvider: "local"}
		err := validateOptions(opts)
		if err == nil || !strings.Contains(err.Error(), "PASSWORD is required when PASSWORD_PROVIDER=local") {
			t.Fatalf("expected local non-interactive password error, got %v", err)
		}
	})

	t.Run("local provider uses PASSWORD value", func(t *testing.T) {
		t.Setenv("PASSWORD", "from-local-env")

		opts := &options{Port: 22, TimeoutSec: 10, PasswordProvider: "local"}
		err := validateOptions(opts)
		if err != nil {
			t.Fatalf("validate options: %v", err)
		}
		if opts.Password != "from-local-env" {
			t.Fatalf("opts.Password = %q, want %q", opts.Password, "from-local-env")
		}
	})
}

func TestTimestampedLineWriterWriteAndClose(t *testing.T) {
	var outputBuffer bytes.Buffer

	timestampWriter := newTimestampedLineWriter(&outputBuffer)
	timestampWriter.nowFunc = func() time.Time {
		return time.Date(2026, time.February, 19, 9, 10, 11, 0, time.UTC)
	}

	n, err := timestampWriter.Write([]byte("first line\nsecond line"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len("first line\nsecond line") {
		t.Fatalf("Write() bytes = %d, want %d", n, len("first line\nsecond line"))
	}
	if got := outputBuffer.String(); got != "[2026-02-19T09:10:11Z] first line\n" {
		t.Fatalf("unexpected partial output after Write(): %q", got)
	}

	if err := timestampWriter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	want := "[2026-02-19T09:10:11Z] first line\n[2026-02-19T09:10:11Z] second line"
	if got := outputBuffer.String(); got != want {
		t.Fatalf("final output = %q, want %q", got, want)
	}
}

func TestTimestampedLineWriterWriteError(t *testing.T) {
	timestampWriter := newTimestampedLineWriter(alwaysFailWriter{})
	timestampWriter.nowFunc = func() time.Time {
		return time.Date(2026, time.February, 19, 9, 10, 11, 0, time.UTC)
	}

	n, err := timestampWriter.Write([]byte("line\n"))
	if err == nil {
		t.Fatalf("expected write error")
	}
	if n != len("line\n") {
		t.Fatalf("Write() bytes = %d, want %d when write fails", n, len("line\n"))
	}
}

func TestTimestampedLineWriterCloseError(t *testing.T) {
	timestampWriter := newTimestampedLineWriter(alwaysFailWriter{})
	timestampWriter.pending = []byte("pending")

	err := timestampWriter.Close()
	if err == nil {
		t.Fatalf("expected Close() error")
	}
	if !strings.Contains(err.Error(), "forced write failure") {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestTimestampedLineWriterWriteLineLockedNewlineError(t *testing.T) {
	writer := &failOnSecondWrite{}
	timestampWriter := newTimestampedLineWriter(writer)
	timestampWriter.nowFunc = func() time.Time {
		return time.Date(2026, time.February, 19, 9, 10, 11, 0, time.UTC)
	}

	err := timestampWriter.writeLineLocked([]byte("line"), true)
	if err == nil {
		t.Fatalf("expected newline write error")
	}
	if !strings.Contains(err.Error(), "forced second-write failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTimestampedLineWriterCloseWithoutPendingData(t *testing.T) {
	var outputBuffer bytes.Buffer
	timestampWriter := newTimestampedLineWriter(&outputBuffer)

	if err := timestampWriter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if outputBuffer.Len() != 0 {
		t.Fatalf("unexpected output for empty close: %q", outputBuffer.String())
	}
}

func TestPromptLineTrimsAndHandlesEOF(t *testing.T) {
	outputBuffer, _ := captureWriters(t)

	reader := bufio.NewReader(strings.NewReader("  value without newline  "))
	value, err := promptLine(reader, "Enter value: ")
	if err != nil {
		t.Fatalf("promptLine() error = %v", err)
	}
	if value != "value without newline" {
		t.Fatalf("promptLine() value = %q, want %q", value, "value without newline")
	}
	if !strings.Contains(outputBuffer.String(), "Enter value: ") {
		t.Fatalf("expected prompt label in output, got %q", outputBuffer.String())
	}
}

func TestPromptLineReturnsReadError(t *testing.T) {
	captureWriters(t)
	reader := bufio.NewReader(errReader{})

	_, err := promptLine(reader, "Prompt: ")
	if err == nil {
		t.Fatalf("expected promptLine() error")
	}
	if !strings.Contains(err.Error(), "forced read failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPromptLineReturnsErrorForNilReader(t *testing.T) {
	captureWriters(t)

	_, err := promptLine(nil, "Prompt: ")
	if err == nil {
		t.Fatalf("expected nil-reader error")
	}
	if !strings.Contains(err.Error(), "input reader is nil") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPromptLineReturnsEOFWhenEmptyInput(t *testing.T) {
	captureWriters(t)
	reader := bufio.NewReader(strings.NewReader(""))

	_, err := promptLine(reader, "Prompt: ")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestOutputWritersAndCommandOutputWriter(t *testing.T) {
	outputBuffer, errorBuffer := captureWriters(t)

	outputPrint("A")
	outputPrintf("%s", "B")
	outputPrintln("C")
	errorPrintln("E")

	if got := outputBuffer.String(); got != "ABC\n" {
		t.Fatalf("standard output = %q, want %q", got, "ABC\n")
	}
	if got := errorBuffer.String(); got != "E\n" {
		t.Fatalf("standard error = %q, want %q", got, "E\n")
	}
	if commandOutputWriter() != standardErrorWriter {
		t.Fatalf("commandOutputWriter() did not return standardErrorWriter")
	}
}

func TestSetupRunLogFileCreatesLogAndRestoresWriters(t *testing.T) {
	originalOutput := standardOutputWriter
	originalError := standardErrorWriter
	t.Cleanup(func() {
		standardOutputWriter = originalOutput
		standardErrorWriter = originalError
	})

	executablePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}

	logName := "ssh-key-bootstrap-test-" + strings.ReplaceAll(t.Name(), "/", "-")
	logPath := filepath.Join(filepath.Dir(executablePath), logName+".log")
	_ = os.Remove(logPath)
	t.Cleanup(func() { _ = os.Remove(logPath) })

	cleanupRunLog, err := setupRunLogFile(logName)
	if err != nil {
		t.Skipf("setupRunLogFile() could not create log in this environment: %v", err)
	}

	outputPrintln("log-line-out")
	errorPrintln("log-line-err")
	cleanupRunLog()

	if standardOutputWriter != os.Stdout {
		t.Fatalf("standardOutputWriter not restored to os.Stdout")
	}
	if standardErrorWriter != os.Stderr {
		t.Fatalf("standardErrorWriter not restored to os.Stderr")
	}

	logBytes, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("read log file: %v", readErr)
	}
	logContent := string(logBytes)
	if !strings.Contains(logContent, "log-line-out") {
		t.Fatalf("log file missing stdout line: %q", logContent)
	}
	if !strings.Contains(logContent, "log-line-err") {
		t.Fatalf("log file missing stderr line: %q", logContent)
	}
}

func TestExpandHomePathMainHelpers(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir() error = %v", err)
	}

	_, err = expandHomePath("")
	if err == nil {
		t.Fatalf("expandHomePath(\"\") expected error")
	}

	got, err := expandHomePath("/tmp/config.env")
	if err != nil || got != "/tmp/config.env" {
		t.Fatalf("expandHomePath(unchanged) = (%q, %v), want (%q, nil)", got, err, "/tmp/config.env")
	}

	got, err = expandHomePath("~")
	if err != nil || got != home {
		t.Fatalf("expandHomePath(\"~\") = (%q, %v), want (%q, nil)", got, err, home)
	}

	got, err = expandHomePath("~/known_hosts")
	if err != nil {
		t.Fatalf("expandHomePath(\"~/known_hosts\") error = %v", err)
	}
	if got != filepath.Join(home, "known_hosts") {
		t.Fatalf("expandHomePath(\"~/known_hosts\") = %q, want %q", got, filepath.Join(home, "known_hosts"))
	}
}

func TestTerminalFDAndReadPasswordInvalidInput(t *testing.T) {
	fileDescriptor, ok := terminalFD(nil)
	if ok || fileDescriptor != 0 {
		t.Fatalf("terminalFD(nil) = (%d, %v), want (0, false)", fileDescriptor, ok)
	}

	tempFile, err := os.CreateTemp(t.TempDir(), "fd-test-*")
	if err != nil {
		t.Fatalf("os.CreateTemp() error = %v", err)
	}
	defer tempFile.Close()

	fileDescriptor, ok = terminalFD(tempFile)
	if !ok || fileDescriptor < 0 {
		t.Fatalf("terminalFD(tempFile) = (%d, %v), want valid descriptor", fileDescriptor, ok)
	}

	_, err = readPassword(nil)
	if err == nil || !strings.Contains(err.Error(), "invalid terminal file descriptor") {
		t.Fatalf("readPassword(nil) error = %v, want invalid descriptor error", err)
	}
}

func TestBuildSSHConfigInsecureMode(t *testing.T) {
	programOptions := &options{
		User:                  "deploy",
		Password:              "password",
		TimeoutSec:            5,
		InsecureIgnoreHostKey: true,
	}

	clientConfig, err := buildSSHConfig(programOptions)
	if err != nil {
		t.Fatalf("buildSSHConfig() error = %v", err)
	}
	if clientConfig.User != "deploy" {
		t.Fatalf("clientConfig.User = %q, want %q", clientConfig.User, "deploy")
	}
	if clientConfig.Timeout != 5*time.Second {
		t.Fatalf("clientConfig.Timeout = %s, want %s", clientConfig.Timeout, 5*time.Second)
	}

	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))
	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if err := clientConfig.HostKeyCallback("example.com:22", remoteAddress, hostPublicKey); err != nil {
		t.Fatalf("insecure host key callback should accept key, got %v", err)
	}
}

func TestBuildSSHConfigKnownHostsPathError(t *testing.T) {
	programOptions := &options{
		User:                  "deploy",
		Password:              "password",
		TimeoutSec:            5,
		InsecureIgnoreHostKey: false,
		KnownHosts:            "",
	}

	_, err := buildSSHConfig(programOptions)
	if err == nil {
		t.Fatalf("expected known_hosts path error")
	}
	if !strings.Contains(err.Error(), "resolve known_hosts path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPromptTrustUnknownHostNonInteractive(t *testing.T) {
	stubTrustPromptHooks(
		t,
		func(*os.File) bool { return false },
		func(*bufio.Reader, string) (string, error) { return "", nil },
		func(*bufio.Reader, string, time.Duration) (string, bool, error) { return "", false, nil },
	)

	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))
	trustHost, err := promptTrustUnknownHost("example.com:22", "/tmp/known_hosts", hostPublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !trustHost {
		t.Fatalf("expected default trustHost=true in non-interactive mode")
	}
}

func TestPromptTrustUnknownHostInteractiveYesAfterRetry(t *testing.T) {
	outputBuffer, _ := captureWriters(t)
	answers := []string{"maybe", "yes"}
	answerIndex := 0

	stubTrustPromptHooks(
		t,
		func(*os.File) bool { return true },
		func(_ *bufio.Reader, label string) (string, error) {
			if !strings.Contains(label, "Trust this host and add it to /tmp/known_hosts?") {
				t.Fatalf("unexpected prompt label: %q", label)
			}
			answer := answers[answerIndex]
			answerIndex++
			return answer, nil
		},
		func(reader *bufio.Reader, label string, _ time.Duration) (string, bool, error) {
			answer, err := promptLineForTrustPrompt(reader, label)
			return answer, false, err
		},
	)

	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))
	trustHost, err := promptTrustUnknownHost("example.com:22", "/tmp/known_hosts", hostPublicKey)
	if err != nil {
		t.Fatalf("promptTrustUnknownHost() error = %v", err)
	}
	if !trustHost {
		t.Fatalf("expected trustHost=true")
	}
	if answerIndex != 2 {
		t.Fatalf("prompt attempts = %d, want 2", answerIndex)
	}

	output := outputBuffer.String()
	if !strings.Contains(output, "can't be established") {
		t.Fatalf("missing host authenticity message: %q", output)
	}
	if !strings.Contains(output, "Please answer \"yes\" or \"no\".") {
		t.Fatalf("missing retry guidance: %q", output)
	}
}

func TestPromptTrustUnknownHostInteractiveNo(t *testing.T) {
	stubTrustPromptHooks(
		t,
		func(*os.File) bool { return true },
		func(*bufio.Reader, string) (string, error) { return "n", nil },
		func(reader *bufio.Reader, label string, _ time.Duration) (string, bool, error) {
			answer, err := promptLineForTrustPrompt(reader, label)
			return answer, false, err
		},
	)

	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))
	trustHost, err := promptTrustUnknownHost("example.com:22", "/tmp/known_hosts", hostPublicKey)
	if err != nil {
		t.Fatalf("promptTrustUnknownHost() error = %v", err)
	}
	if trustHost {
		t.Fatalf("expected trustHost=false")
	}
}

func TestPromptTrustUnknownHostInteractiveTimeoutDefaultsYes(t *testing.T) {
	outputBuffer, _ := captureWriters(t)

	stubTrustPromptHooks(
		t,
		func(*os.File) bool { return true },
		func(*bufio.Reader, string) (string, error) { return "", nil },
		func(*bufio.Reader, string, time.Duration) (string, bool, error) { return "", true, nil },
	)

	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))
	trustHost, err := promptTrustUnknownHost("example.com:22", "/tmp/known_hosts", hostPublicKey)
	if err != nil {
		t.Fatalf("promptTrustUnknownHost() error = %v", err)
	}
	if !trustHost {
		t.Fatalf("expected trustHost=true on prompt timeout")
	}
	if !strings.Contains(outputBuffer.String(), "default: yes") {
		t.Fatalf("expected timeout default output, got %q", outputBuffer.String())
	}
}

func TestPromptTrustUnknownHostPromptError(t *testing.T) {
	stubTrustPromptHooks(
		t,
		func(*os.File) bool { return true },
		func(*bufio.Reader, string) (string, error) { return "", errors.New("prompt failed") },
		func(reader *bufio.Reader, label string, _ time.Duration) (string, bool, error) {
			answer, err := promptLineForTrustPrompt(reader, label)
			return answer, false, err
		},
	)

	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))
	_, err := promptTrustUnknownHost("example.com:22", "/tmp/known_hosts", hostPublicKey)
	if err == nil {
		t.Fatalf("expected prompt error")
	}
	if !strings.Contains(err.Error(), "prompt failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func newInMemorySSHClient(
	t *testing.T,
	clientConfig *ssh.ClientConfig,
	sessionHandler func(command, stdin string) (stdout string, stderr string, exitStatus uint32),
) (*ssh.Client, func()) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)

	clientConn, serverConn, closeSocketPair := newSocketPair(t)
	serverDone := make(chan struct{})
	serverError := make(chan error, 1)

	go func() {
		defer close(serverDone)

		sshConnection, channels, requests, handshakeErr := ssh.NewServerConn(serverConn, serverConfig)
		if handshakeErr != nil {
			serverError <- handshakeErr
			return
		}
		defer sshConnection.Close()

		go ssh.DiscardRequests(requests)

		for newChannel := range channels {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
				continue
			}

			channel, channelRequests, channelErr := newChannel.Accept()
			if channelErr != nil {
				continue
			}

			go func(acceptedChannel ssh.Channel, requestsChannel <-chan *ssh.Request) {
				defer acceptedChannel.Close()
				for request := range requestsChannel {
					if request.Type != "exec" {
						if request.WantReply {
							_ = request.Reply(false, nil)
						}
						continue
					}

					var execRequest struct {
						Command string
					}
					if unmarshalErr := ssh.Unmarshal(request.Payload, &execRequest); unmarshalErr != nil {
						if request.WantReply {
							_ = request.Reply(false, nil)
						}
						return
					}
					if request.WantReply {
						_ = request.Reply(true, nil)
					}

					stdinReader := bufio.NewReader(acceptedChannel)
					stdinValue, readErr := stdinReader.ReadString('\n')
					if readErr != nil && !errors.Is(readErr, io.EOF) {
						stdinValue = ""
					}
					stdout, stderr, exitStatus := sessionHandler(execRequest.Command, stdinValue)
					if stdout != "" {
						_, _ = acceptedChannel.Write([]byte(stdout))
					}
					if stderr != "" {
						_, _ = acceptedChannel.Stderr().Write([]byte(stderr))
					}

					exitStatusPayload := struct {
						Status uint32
					}{Status: exitStatus}
					_, _ = acceptedChannel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusPayload))
					return
				}
			}(channel, channelRequests)
		}
	}()

	sshClientConnection, channels, requests, err := ssh.NewClientConn(clientConn, "in-memory", clientConfig)
	if err != nil {
		select {
		case serverErr := <-serverError:
			t.Fatalf("create in-memory ssh client failed: client=%v server=%v", err, serverErr)
		default:
			t.Fatalf("create in-memory ssh client failed: %v", err)
		}
	}
	client := ssh.NewClient(sshClientConnection, channels, requests)

	cleanupClient := func() {
		_ = client.Close()
		_ = serverConn.Close()
		closeSocketPair()
		<-serverDone
	}
	return client, cleanupClient
}

func newInMemorySSHClientRejectSession(t *testing.T, clientConfig *ssh.ClientConfig) (*ssh.Client, func()) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)

	clientConn, serverConn, closeSocketPair := newSocketPair(t)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)

		sshConnection, channels, requests, handshakeErr := ssh.NewServerConn(serverConn, serverConfig)
		if handshakeErr != nil {
			return
		}
		defer sshConnection.Close()

		go ssh.DiscardRequests(requests)
		for newChannel := range channels {
			_ = newChannel.Reject(ssh.Prohibited, "session channels disabled")
		}
	}()

	sshClientConnection, channels, requests, err := ssh.NewClientConn(clientConn, "in-memory", clientConfig)
	if err != nil {
		t.Fatalf("create in-memory ssh client failed: %v", err)
	}
	client := ssh.NewClient(sshClientConnection, channels, requests)
	cleanupClient := func() {
		_ = client.Close()
		_ = serverConn.Close()
		closeSocketPair()
		<-serverDone
	}
	return client, cleanupClient
}

func TestAddAuthorizedKeyWithStatusSuccess(t *testing.T) {
	var (
		capturedCommand string
		capturedStdin   string
	)

	clientConfig := &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	stubSSHDialHook(t, func(network, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
		if network != "tcp" {
			t.Fatalf("unexpected network: %q", network)
		}
		if address != "in-memory:22" {
			t.Fatalf("unexpected address: %q", address)
		}
		client, cleanupClient := newInMemorySSHClient(t, config, func(command, stdin string) (string, string, uint32) {
			capturedCommand = command
			capturedStdin = stdin
			return "", "", 0
		})
		t.Cleanup(cleanupClient)
		return client, nil
	})

	publicKey := strings.TrimSpace(generateTestKey(t))
	var logMessages []string
	err := addAuthorizedKeyWithStatus("in-memory:22", publicKey, clientConfig, func(format string, args ...any) {
		logMessages = append(logMessages, fmt.Sprintf(format, args...))
	})
	if err != nil {
		t.Fatalf("addAuthorizedKeyWithStatus() error = %v", err)
	}

	if capturedCommand != normalizeLF(addAuthorizedKeyScript) {
		t.Fatalf("unexpected remote command:\n%q", capturedCommand)
	}
	if capturedStdin != publicKey+"\n" {
		t.Fatalf("stdin payload = %q, want %q", capturedStdin, publicKey+"\n")
	}

	expectedLogs := []string{
		"Connecting over SSH...",
		"Connected. Opening remote session...",
		"Applying authorized_keys update...",
		"Remote command completed.",
	}
	if len(logMessages) != len(expectedLogs) {
		t.Fatalf("log count = %d, want %d (%v)", len(logMessages), len(expectedLogs), logMessages)
	}
	for index := range expectedLogs {
		if logMessages[index] != expectedLogs[index] {
			t.Fatalf("log[%d] = %q, want %q", index, logMessages[index], expectedLogs[index])
		}
	}
}

func TestAddAuthorizedKeyWithStatusCommandFailureIncludesOutput(t *testing.T) {
	clientConfig := &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	stubSSHDialHook(t, func(_, _ string, config *ssh.ClientConfig) (*ssh.Client, error) {
		client, cleanupClient := newInMemorySSHClient(t, config, func(command, stdin string) (string, string, uint32) {
			return "", "remote command failed", 1
		})
		t.Cleanup(cleanupClient)
		return client, nil
	})

	err := addAuthorizedKeyWithStatus("in-memory:22", strings.TrimSpace(generateTestKey(t)), clientConfig, nil)
	if err == nil {
		t.Fatalf("expected remote command failure")
	}
	if !strings.Contains(err.Error(), "remote command failed") {
		t.Fatalf("expected remote stderr in error, got %v", err)
	}
}

func TestAddAuthorizedKeyWithStatusCommandFailureWithoutOutput(t *testing.T) {
	clientConfig := &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	stubSSHDialHook(t, func(_, _ string, config *ssh.ClientConfig) (*ssh.Client, error) {
		client, cleanupClient := newInMemorySSHClient(t, config, func(command, stdin string) (string, string, uint32) {
			return "", "", 1
		})
		t.Cleanup(cleanupClient)
		return client, nil
	})

	err := addAuthorizedKeyWithStatus("in-memory:22", strings.TrimSpace(generateTestKey(t)), clientConfig, nil)
	if err == nil {
		t.Fatalf("expected remote command failure")
	}
	if strings.Contains(err.Error(), "remote command failed") {
		t.Fatalf("unexpected stderr wrapper for empty output: %v", err)
	}
}

func TestAddAuthorizedKeyWithStatusCreateSessionFailure(t *testing.T) {
	clientConfig := &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	stubSSHDialHook(t, func(_, _ string, config *ssh.ClientConfig) (*ssh.Client, error) {
		client, cleanupClient := newInMemorySSHClientRejectSession(t, config)
		t.Cleanup(cleanupClient)
		return client, nil
	})

	err := addAuthorizedKeyWithStatus("in-memory:22", strings.TrimSpace(generateTestKey(t)), clientConfig, nil)
	if err == nil {
		t.Fatalf("expected new session failure")
	}
	if !strings.Contains(err.Error(), "create session:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddAuthorizedKeyWithStatusDialFailure(t *testing.T) {
	clientConfig := &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         150 * time.Millisecond,
	}
	stubSSHDialHook(t, func(string, string, *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, errors.New("forced dial error")
	})

	var logMessages []string
	err := addAuthorizedKeyWithStatus("127.0.0.1:1", generateTestKey(t), clientConfig, func(format string, args ...any) {
		logMessages = append(logMessages, fmt.Sprintf(format, args...))
	})

	if err == nil {
		t.Fatalf("expected ssh dial failure")
	}
	if !strings.Contains(err.Error(), "ssh dial:") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(logMessages) != 1 || logMessages[0] != "Connecting over SSH..." {
		t.Fatalf("unexpected log messages: %v", logMessages)
	}
}

func TestConfigRuntimeIOWrappers(t *testing.T) {
	outputBuffer, _ := captureWriters(t)

	runtime := configRuntimeIO{inputReader: bufio.NewReader(strings.NewReader("  user-input  \n"))}
	value, err := runtime.PromptLine("Prompt: ")
	if err != nil {
		t.Fatalf("PromptLine() error = %v", err)
	}
	if value != "user-input" {
		t.Fatalf("PromptLine() value = %q, want %q", value, "user-input")
	}

	runtime.Println("line output")
	runtime.Printf("formatted=%d", 42)

	output := outputBuffer.String()
	if !strings.Contains(output, "Prompt: ") {
		t.Fatalf("prompt label missing from output: %q", output)
	}
	if !strings.Contains(output, "line output\n") {
		t.Fatalf("println output missing: %q", output)
	}
	if !strings.Contains(output, "formatted=42") {
		t.Fatalf("printf output missing: %q", output)
	}

	expectedInteractive := isTerminal(os.Stdin) && isTerminal(os.Stdout)
	if runtime.IsInteractive() != expectedInteractive {
		t.Fatalf("IsInteractive() = %v, want %v", runtime.IsInteractive(), expectedInteractive)
	}
}
