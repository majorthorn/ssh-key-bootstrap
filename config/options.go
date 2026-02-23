package config

type Options struct {
	Server            string // Single host input (host or host:port).
	Servers           string // Comma-separated host list input.
	User              string
	Password          string // #nosec G117 -- runtime-only credential container for user input and secret resolution
	PasswordSecretRef string
	PasswordProvider  string
	KeyInput          string
	EnvFile           string
	Port              int
	TimeoutSec        int
	// InsecureIgnoreHostKey disables SSH host key verification; unsafe for production (MITM risk).
	InsecureIgnoreHostKey bool
	KnownHosts            string
}
