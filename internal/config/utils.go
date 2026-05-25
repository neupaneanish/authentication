package config

const (
	envDevelopment = "development"
	envProduction  = "production"
)

type Env struct {
	DatabaseURL  string
	ValkeyURL    string
	JWTKey       string
	TwoFactorKey string
	Issuer       string
	Port         string
	ServiceName  string
	Environment  string
	TelemetryURL string
}
