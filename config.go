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
	KEYPROXY_KEYSTONE        = "https://auth-dev.iotplatform.telefonica.com:15001"
	KEYPROXY_PODCONFIG       = "configs/pod.yaml"
	KEYPROXY_STATIC          = "podstatic"
	KEYPROXY_TEMPLATES       = "templates"
	KEYPROXY_NAMESPACE       = ""
	KEYPROXY_REDIRECT        = "/editor"
	KEYPROXY_FORWARDEDPROTO  = "https"
	KEYPROXY_PORT            = 8080
	KEYPROXY_PODPORT         = 9390
	KEYPROXY_PROFILEPORT     = 6060
	KEYPROXY_PODLIFETIME     = 120
	KEYPROXY_SESSIONLIFETIME = 60
	KEYPROXY_REQUESTTIMEOUT  = 5
	KEYPROXY_IDLETIMEOUT     = 300
	KEYPROXY_SHUTDOWN        = 30
	KEYPROXY_THREADS         = 10
	KEYPROXY_LABEL           = "undefined"
	KEYPROXY_SIGNINGKEY      = ""
	KEYPROXY_OFFLINE         = ""
	KEYPROXY_CORS            = ""
	CUSTOM_LABEL_NAME        = "keyproxy/release"
)

type Config struct {
	KeystoneURL      string
	PodConfig        string
	Redirect         string
	StaticFolder     string
	TemplateFolder   string
	ForwardedProto   string
	Port             int
	PodPort          int
	PrefixPort       map[string]int
	ProfilePort      int
	Namespace        string
	SigningKey       string
	PodLifetime      int
	SessionLifetime  int
	RequestTimeout   int
	IdleTimeout      int
	GracefulShutdown int
	Threads          int
	Labels           map[string]string
	Cors             []string
	OfflineUsername  string
	OfflineDomain    string
	OfflinePassword  string
}

func GetConfig() *Config {
	config := &Config{}
	flag.StringVar(&config.KeystoneURL, "keystone", LookupEnvOrString("KEYPROXY_KEYSTONE", KEYPROXY_KEYSTONE), "Keystone URL")
	flag.StringVar(&config.PodConfig, "podconfig", LookupEnvOrString("KEYPROXY_PODCONFIG", KEYPROXY_PODCONFIG), "Path to pod config file")
	flag.StringVar(&config.StaticFolder, "static", LookupEnvOrString("KEYPROXY_STATIC", KEYPROXY_STATIC), "Path to static assets folder")
	flag.StringVar(&config.TemplateFolder, "templates", LookupEnvOrString("KEYPROXY_TEMPLATES", KEYPROXY_TEMPLATES), "Path to templates folder")
	flag.StringVar(&config.Namespace, "namespace", LookupEnvOrString("KEYPROXY_NAMESPACE", KEYPROXY_NAMESPACE), "Kubernetes namespace")
	flag.StringVar(&config.SigningKey, "signingkey", LookupEnvOrString("KEYPROXY_SIGNINGKEY", KEYPROXY_SIGNINGKEY), "Signing key for cookies")
	flag.StringVar(&config.Redirect, "redirect", LookupEnvOrString("KEYPROXY_REDIRECT", KEYPROXY_REDIRECT), "Redirect requests for '/' to this path")
	flag.StringVar(&config.ForwardedProto, "forwardedproto", LookupEnvOrString("KEYPROXY_FORWARDEDPROTO", KEYPROXY_FORWARDEDPROTO), "Value for X-Forwarded-Proto header")
	var label string
	flag.StringVar(&label, "label", LookupEnvOrString("KEYPROXY_LABEL", KEYPROXY_LABEL), "Value for 'keyproxy/release' label")
	flag.IntVar(&config.Port, "port", LookupEnvOrInt("KEYPROXY_PORT", KEYPROXY_PORT), "TCP listen port")
	flag.IntVar(&config.PodPort, "podport", LookupEnvOrInt("KEYPROXY_PODPORT", KEYPROXY_PODPORT), "Backend pod port to forward requests to, by default")
	flag.IntVar(&config.ProfilePort, "profileport", LookupEnvOrInt("KEYPROXY_PROFILEPORT", KEYPROXY_PROFILEPORT), "Port backend pod listens to")
	flag.IntVar(&config.PodLifetime, "podlifetime", LookupEnvOrInt("KEYPROXY_PODLIFETIME", KEYPROXY_PODLIFETIME), "Pod Lifetime (minutes)")
	flag.IntVar(&config.SessionLifetime, "sessionlifetime", LookupEnvOrInt("KEYPROXY_SESSIONLIFETIME", KEYPROXY_SESSIONLIFETIME), "Session lifetime (minutes)")
	flag.IntVar(&config.RequestTimeout, "requesttimeout", LookupEnvOrInt("KEYPROXY_REQUESTTIMEOUT", KEYPROXY_REQUESTTIMEOUT), "HTTP Request timeout (client or server) (seconds)")
	flag.IntVar(&config.IdleTimeout, "idletimeout", LookupEnvOrInt("KEYPROXY_IDLETIMEOUT", KEYPROXY_IDLETIMEOUT), "HTTP idle server timeout (seconds)")
	flag.IntVar(&config.GracefulShutdown, "shutdown", LookupEnvOrInt("KEYPROXY_SHUTDOWN", KEYPROXY_SHUTDOWN), "Graceful shutdown (seconds)")
	flag.IntVar(&config.Threads, "threads", LookupEnvOrInt("KEYPROXY_THREADS", KEYPROXY_THREADS), "Number of controller threads")
	var offline string
	flag.StringVar(&offline, "offline", LookupEnvOrString("KEYPROXY_OFFLINE", KEYPROXY_OFFLINE), "Offline mode credentials (`username@domain:password`) for testing")
	var cors string
	flag.StringVar(&cors, "cors", LookupEnvOrString("KEYPROXY_CORS", KEYPROXY_CORS), "Comma-separated list of allowed CORS origins")
	var prefixes string
	flag.StringVar(&prefixes, "prefixes", LookupEnvOrString("KEYPROXY_PREFIXES", ""), "Comma-separated list of url_prefix:port_number for additional ports the pod listens to")
	flag.Parse()

	if config.ForwardedProto != "http" && config.ForwardedProto != "https" {
		panic("ForwardedProto must be either 'http' or 'https'")
	}
	if config.Port <= 1024 || config.Port > 65535 {
		panic("Port must be between 1024 and 65535")
	}
	if config.ProfilePort <= 1024 || config.ProfilePort > 65535 {
		panic("ProfilePort must be between 1024 and 65535")
	}
	if config.Port == config.ProfilePort {
		panic("Port and ProfilePort must be different")
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
	if config.RequestTimeout < 1 || config.RequestTimeout > 30 {
		panic("Request timeout must be between 1 and 30 seconds")
	}
	if config.IdleTimeout < 2*config.RequestTimeout || config.IdleTimeout > 3600 {
		panic("Idle timeout must be between (2 * requesttimeout) and 3600 seconds")
	}
	if config.GracefulShutdown < 5 || config.GracefulShutdown > 60 {
		panic("Graceful shutdown must be between 5 and 60 seconds")
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
	config.Labels[CUSTOM_LABEL_NAME] = label
	origins := make([]string, 0, 8)
	if cors != "" {
		for _, origin := range strings.Split(cors, ",") {
			trimmed := strings.TrimSpace(origin)
			if trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
	}
	config.Cors = origins
	if offline != "" {
		var username, domain, password string
		if index := strings.Index(offline, "@"); index > 0 {
			username = strings.TrimSpace(offline[:index])
			offline = offline[index+1:]
			if index = strings.Index(offline, ":"); index > 0 {
				domain = strings.TrimSpace(offline[:index])
				password = strings.TrimSpace(offline[index+1:])
			}
		}
		if username == "" || domain == "" || password == "" {
			panic("Invalid offline credentials " + offline + ". Use `username@domain:password` format")
		}
		config.OfflineUsername = username
		config.OfflinePassword = password
		config.OfflineDomain = domain
	}
	config.PrefixPort = make(map[string]int)
	prefixes = strings.TrimSpace(prefixes)
	if prefixes != "" {
		for _, forward := range strings.Split(prefixes, ",") {
			parts := strings.Split(strings.TrimSpace(forward), ":")
			if len(parts) != 2 {
				panic("Invalid forward path:port specification " + forward)
			}
			path := strings.TrimSpace(parts[0])
			if path == "" {
				panic("Invalid path in path:port specification " + forward)
			}
			port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				panic("Invalid port number in path:port specification " + forward + ": " + err.Error())
			}
			config.PrefixPort[path] = port
		}
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
