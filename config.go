package main

import (
	"flag"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	KEYSTONE                 = "https://auth-dev.iotplatform.telefonica.com:15001"
	PODCONFIG                = "configs/pod.yaml"
	PODPORT                  = 9390
	REDIRECT                 = "/editor"
	FORWARDEDPROTO           = ""
	POD_LIFETIME_MINUTE      = 120
	SESSION_LIFETIME_MINUTE  = 60
	GRACEFUL_SHUTDOWN_SECOND = 30
	KEYPROXY_LABEL_NAME      = "keyproxy/release"
	KEYPROXY_LABEL_VALUE     = "undefined"
)

type Config struct {
	KeystoneURL      string
	PodConfig        string
	Redirect         string
	AppScheme        string
	ProxyScheme      string
	StaticFolder     string
	TemplateFolder   string
	ForwardedProto   string
	Port             int
	PodPort          int
	Namespace        string
	SigningKey       string
	PodLifetime      int
	SessionLifetime  int
	GracefulShutdown int
	Threads          int
	Labels           map[string]string
	Devel            bool
}

func GetConfig() *Config {
	config := &Config{}
	flag.StringVar(&config.KeystoneURL, "keystone", LookupEnvOrString("KEYPROXY_KEYSTONE", KEYSTONE), "Keystone URL")
	flag.StringVar(&config.PodConfig, "podconfig", LookupEnvOrString("KEYPROXY_PODCONFIG", PODCONFIG), "Path to pod config file")
	flag.StringVar(&config.StaticFolder, "static", LookupEnvOrString("KEYPROXY_STATIC", "podstatic"), "Path to static assets folder")
	flag.StringVar(&config.TemplateFolder, "templates", LookupEnvOrString("KEYPROXY_TEMPLATES", "templates"), "Path to templates folder")
	flag.StringVar(&config.Namespace, "namespace", LookupEnvOrString("KEYPROXY_NAMESPACE", ""), "Kubernetes namespace")
	flag.StringVar(&config.SigningKey, "signingkey", LookupEnvOrString("KEYPROXY_SIGNINGKEY", ""), "Signing key for cookies")
	flag.StringVar(&config.Redirect, "redirect", LookupEnvOrString("KEYPROXY_REDIRECT", REDIRECT), "Redirect requests for '/' to this path")
	flag.StringVar(&config.ProxyScheme, "proxyscheme", LookupEnvOrString("KEYPROXY_PROXYSCHEME", ""), "Scheme (http/https) to use for redirects to the login page (defaults to forwardedProto or https)")
	flag.StringVar(&config.AppScheme, "appscheme", LookupEnvOrString("KEYPROXY_APPSCHEME", ""), "Scheme (http/https) to use for redirects to the app pages (defaults to forwardedProto or https)")
	flag.StringVar(&config.ForwardedProto, "forwardedproto", LookupEnvOrString("KEYPROXY_FORWARDEDPROTO", FORWARDEDPROTO), "Value for X-Forwarded-Proto header")
	var label string
	flag.StringVar(&label, "label", LookupEnvOrString("KEYPROXY_LABEL", KEYPROXY_LABEL_VALUE), "Value for 'keyproxy/release' label")
	flag.IntVar(&config.Port, "port", LookupEnvOrInt("KEYPROXY_PORT", 8080), "TCP listen port")
	flag.IntVar(&config.PodPort, "podport", LookupEnvOrInt("KEYPROXY_PODPORT", PODPORT), "Port the backend pod listens to")
	flag.IntVar(&config.PodLifetime, "podlifetime", LookupEnvOrInt("KEYPROXY_PODLIFETIME", 120), "Pod Lifetime (minutes)")
	flag.IntVar(&config.SessionLifetime, "sessionlifetime", LookupEnvOrInt("KEYPROXY_SESSIONLIFETIME", 60), "Session lifetime (minutes)")
	flag.IntVar(&config.GracefulShutdown, "shutdown", LookupEnvOrInt("KEYPROXY_SHUTDOWN", 30), "Graceful shutdown (seconds)")
	flag.IntVar(&config.Threads, "threads", LookupEnvOrInt("KEYPROXY_THREADS", 10), "Number of controller threads")
	flag.BoolVar(&config.Devel, "devel", LookupEnvOrBool("KEYPROXY_DEVEL"), "True to enable devel mode")
	flag.Parse()

	if config.ForwardedProto != "" && config.ForwardedProto != "http" && config.ForwardedProto != "https" {
		panic("ForwardedProto must be either empty, 'http' or 'https'")
	}
	if config.Port <= 1024 || config.Port > 65535 {
		panic("Port must be between 1024 and 65535")
	}
	if config.PodPort <= 0 || config.PodPort > 65535 {
		panic("Backend Pod port must be between 0 and 65535")
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
	if config.AppScheme != "" && config.AppScheme != "http" && config.AppScheme != "https" {
		panic("AppScheme must be either empty, 'http' or 'https'")
	}
	if config.AppScheme == "" {
		config.AppScheme = config.ForwardedProto
		if config.AppScheme == "" {
			config.AppScheme = "https"
		}
	}
	if config.ProxyScheme != "" && config.ProxyScheme != "http" && config.ProxyScheme != "https" {
		panic("ProxyScheme must be either empty, 'http' or 'https'")
	}
	if config.ProxyScheme == "" {
		config.ProxyScheme = config.ForwardedProto
		if config.ProxyScheme == "" {
			config.ProxyScheme = "https"
		}
	}
	if config.Threads <= 0 || config.Threads > 1000 {
		panic("Threads must be between 1 and 1000")
	}
	if len(label) < 4 || len(label) > 32 {
		panic("Label must be between 4 and 32 characters")
	}
	validLabel := regexp.MustCompile("^[a-zA-Z0-9\\-]+$")
	if !validLabel.Match([]byte(label)) {
		panic("Label must be include only alphanumeric characters and '-'")
	}
	config.Labels = make(map[string]string)
	config.Labels[KEYPROXY_LABEL_NAME] = label
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

func LookupEnvOrBool(key string) bool {
	if val, ok := os.LookupEnv(key); ok {
		for _, truish := range []string{"1", "y", "yes", "t", "true", "s", "si", "sí", "on"} {
			if strings.EqualFold(val, truish) {
				return true
			}
		}
	}
	return false
}
