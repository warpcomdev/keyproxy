package main

import (
	"flag"
	"log"
	"os"
	"strconv"
)

const (
	KEYSTONE                 = "https://auth.iotplatform.telefonica.com:15001"
	PODCONFIG                = "configs/pod.yaml"
	REALM                    = "KeyProxy Auth"
	POD_LIFETIME_MINUTE      = 120
	SESSION_LIFETIME_MINUTE  = 60
	GRACEFUL_SHUTDOWN_SECOND = 30
)

type Config struct {
	KeystoneURL      string
	PodConfig        string
	Realm            string
	ResourceFolder   string
	Port             int
	Namespace        string
	SigningKey       string
	PodLifetime      int
	SessionLifetime  int
	GracefulShutdown int
}

func GetConfig() *Config {
	config := &Config{}
	flag.StringVar(&config.KeystoneURL, "keystone", LookupEnvOrString("KEYPROXY_KEYSTONE", KEYSTONE), "Keystone URL")
	flag.StringVar(&config.PodConfig, "podconfig", LookupEnvOrString("KEYPROXY_PODCONFIG", PODCONFIG), "Path to pod config file")
	flag.StringVar(&config.Realm, "realm", LookupEnvOrString("KEYPROXY_REALM", REALM), "http service listen address")
	flag.StringVar(&config.ResourceFolder, "resources", LookupEnvOrString("KEYPROXY_RESOURCES", "resources"), "Path to static assets folder")
	flag.StringVar(&config.Namespace, "namespace", LookupEnvOrString("KEYPROXY_NAMESPACE", ""), "Kubernetes namespace")
	flag.StringVar(&config.SigningKey, "signingkey", LookupEnvOrString("KEYPROXY_SIGNINGKEY", ""), "Signing key for cookies")
	flag.IntVar(&config.Port, "port", LookupEnvOrInt("KEYPROXY_PORT", 8080), "TCP listen port")
	flag.IntVar(&config.PodLifetime, "podlifetime", LookupEnvOrInt("KEYPROXY_PODLIFETIME", 120), "Pod Lifetime (minutes)")
	flag.IntVar(&config.SessionLifetime, "sessionlifetime", LookupEnvOrInt("KEYPROXY_SESSIONLIFETIME", 60), "Session lifetime (minutes)")
	flag.IntVar(&config.GracefulShutdown, "shutdown", LookupEnvOrInt("KEYPROXY_SHUTDOWN", 30), "Graceful shutdown (seconds)")
	flag.Parse()

	if config.Port <= 1024 || config.Port > 65535 {
		panic("Port must be between 1024 and 65535")
	}
	if config.SigningKey != "" && len(config.SigningKey) < 32 {
		panic("Signing key must be at least 32 characters long")
	}
	if config.PodLifetime < 30 || config.PodLifetime > 28800 {
		panic("Pod lifetime must be between 30 and 28800 minutes")
	}
	if config.SessionLifetime < 10 || config.SessionLifetime > 120 {
		panic("Session lifetime must be between 10 and 120 minutes")
	}
	if config.GracefulShutdown < 5 || config.GracefulShutdown > 60 {
		panic("Graceful shutdown must be between 5 and 60 seconds")
	}
	return config
}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func LookupEnvOrInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalf("LookupEnvOrInt[%s]: %v", key, err)
		}
		return v
	}
	return defaultVal
}
