package config

type Options struct {
	Server                string
	Servers               string
	User                  string
	Password              string // #nosec G117 -- runtime-only credential container for user input and secret resolution
	PasswordSecretRef     string
	KeyInput              string
	EnvFile               string
	Port                  int
	TimeoutSec            int
	InsecureIgnoreHostKey bool
	KnownHosts            string
}
