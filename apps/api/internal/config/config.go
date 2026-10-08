package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the validated runtime configuration for the API server.
type Config struct {
	ServiceName          string
	Version              string
	Env                  string
	Port                 string
	LogLevel             string
	DatabaseURL          string
	RedisURL             string
	BrowserWorkerURL     string
	CORSAllowedOrigins   []string
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	ShutdownGracePeriod  time.Duration
}

// LoadFromEnv reads environment variables with production-ready fallback defaults.
func LoadFromEnv() *Config {
	port := getEnv("PORT", "8080")
	if !strings.HasPrefix(port, ":") && !strings.Contains(port, ":") {
		port = ":" + port
	}

	corsOriginsStr := getEnv("CORS_ALLOWED_ORIGINS", "*")
	var corsOrigins []string
	for _, origin := range strings.Split(corsOriginsStr, ",") {
		trimmed := strings.TrimSpace(origin)
		if trimmed != "" {
			corsOrigins = append(corsOrigins, trimmed)
		}
	}

	readTimeoutSec := getEnvAsInt("READ_TIMEOUT_SECONDS", 15)
	writeTimeoutSec := getEnvAsInt("WRITE_TIMEOUT_SECONDS", 30)
	idleTimeoutSec := getEnvAsInt("IDLE_TIMEOUT_SECONDS", 60)

	return &Config{
		ServiceName:         "expose-api",
		Version:             "0.1.0",
		Env:                 getEnv("ENV", "development"),
		Port:                port,
		LogLevel:            strings.ToLower(getEnv("LOG_LEVEL", "info")),
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://expose:expose_secure_pass@localhost:5432/expose?sslmode=disable"),
		RedisURL:            getEnv("REDIS_URL", "redis://localhost:6379"),
		BrowserWorkerURL:    getEnv("BROWSER_WORKER_URL", "http://localhost:3001"),
		CORSAllowedOrigins:  corsOrigins,
		ReadTimeout:         time.Duration(readTimeoutSec) * time.Second,
		WriteTimeout:        time.Duration(writeTimeoutSec) * time.Second,
		IdleTimeout:         time.Duration(idleTimeoutSec) * time.Second,
		ShutdownGracePeriod: 10 * time.Second,
	}
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return defaultVal
}

func getEnvAsInt(key string, defaultVal int) int {
	valStr := getEnv(key, "")
	if valStr == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return defaultVal
	}
	return val
}
