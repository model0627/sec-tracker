package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config holds all configuration for the security agent
type Config struct {
	Server      ServerConfig      `json:"server"`
	Agent       AgentConfig       `json:"agent"`
	Monitoring  MonitoringConfig  `json:"monitoring"`
	Logging     LoggingConfig     `json:"logging"`
	LocalMode   bool              `json:"local_mode"`
	LocalOutput LocalOutputConfig `json:"local_output"`
}

// ServerConfig contains server connection settings
type ServerConfig struct {
	URL       string `json:"url"`
	APIKey    string `json:"api_key"`
	Timeout   string `json:"timeout"`
	RetryMax  int    `json:"retry_max"`
	BatchSize int    `json:"batch_size"`
}

// AgentConfig contains agent-specific settings
type AgentConfig struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	ReportInterval  string `json:"report_interval"`
	BufferSize      int    `json:"buffer_size"`
	MaxQueueSize    int    `json:"max_queue_size"`
	EnableTLS       bool   `json:"enable_tls"`
	CertPath        string `json:"cert_path"`
}

// MonitoringConfig defines what to monitor
type MonitoringConfig struct {
	SystemInfo      bool     `json:"system_info"`
	ProcessMonitor  bool     `json:"process_monitor"`
	FileMonitor     bool     `json:"file_monitor"`
	NetworkMonitor  bool     `json:"network_monitor"`
	AuthMonitor     bool     `json:"auth_monitor"`
	WatchPaths      []string `json:"watch_paths"`
	ScanInterval    string   `json:"scan_interval"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level      string `json:"level"`
	FilePath   string `json:"file_path"`
	MaxSize    int    `json:"max_size"`
	MaxBackups int    `json:"max_backups"`
	MaxAge     int    `json:"max_age"`
}

// LocalOutputConfig contains local output settings
type LocalOutputConfig struct {
	JSONFormat     bool `json:"json_format"`
	OneShot        bool `json:"one_shot"`
	ShowTimestamp  bool `json:"show_timestamp"`
	ShowColors     bool `json:"show_colors"`
	CompactOutput  bool `json:"compact_output"`
}

// ParsedConfig holds parsed configuration with proper types
type ParsedConfig struct {
	Server      ParsedServerConfig      
	Agent       ParsedAgentConfig       
	Monitoring  ParsedMonitoringConfig  
	Logging     LoggingConfig     
	LocalMode   bool              
	LocalOutput LocalOutputConfig 
}

// ParsedServerConfig contains server connection settings with parsed durations
type ParsedServerConfig struct {
	URL       string        
	APIKey    string        
	Timeout   time.Duration 
	RetryMax  int           
	BatchSize int           
}

// ParsedAgentConfig contains agent-specific settings with parsed durations
type ParsedAgentConfig struct {
	ID              string        
	Name            string        
	ReportInterval  time.Duration 
	BufferSize      int           
	MaxQueueSize    int           
	EnableTLS       bool          
	CertPath        string        
}

// ParsedMonitoringConfig defines what to monitor with parsed durations
type ParsedMonitoringConfig struct {
	SystemInfo      bool          
	ProcessMonitor  bool          
	FileMonitor     bool          
	NetworkMonitor  bool          
	AuthMonitor     bool          
	WatchPaths      []string      
	ScanInterval    time.Duration 
}

// Load reads configuration from file and parses duration fields
func Load(filename string) (*ParsedConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}

	// Parse duration fields
	parsed, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	// Set defaults if not specified
	setDefaults(parsed)
	
	return parsed, nil
}

// parseConfig converts string duration fields to time.Duration
func parseConfig(cfg *Config) (*ParsedConfig, error) {
	parsed := &ParsedConfig{
		Logging:     cfg.Logging,
		LocalMode:   cfg.LocalMode,
		LocalOutput: cfg.LocalOutput,
	}

	// Parse server config
	timeout, err := parseDuration(cfg.Server.Timeout, 30*time.Second)
	if err != nil {
		return nil, err
	}
	parsed.Server = ParsedServerConfig{
		URL:       cfg.Server.URL,
		APIKey:    cfg.Server.APIKey,
		Timeout:   timeout,
		RetryMax:  cfg.Server.RetryMax,
		BatchSize: cfg.Server.BatchSize,
	}

	// Parse agent config
	reportInterval, err := parseDuration(cfg.Agent.ReportInterval, 60*time.Second)
	if err != nil {
		return nil, err
	}
	parsed.Agent = ParsedAgentConfig{
		ID:              cfg.Agent.ID,
		Name:            cfg.Agent.Name,
		ReportInterval:  reportInterval,
		BufferSize:      cfg.Agent.BufferSize,
		MaxQueueSize:    cfg.Agent.MaxQueueSize,
		EnableTLS:       cfg.Agent.EnableTLS,
		CertPath:        cfg.Agent.CertPath,
	}

	// Parse monitoring config
	scanInterval, err := parseDuration(cfg.Monitoring.ScanInterval, 5*time.Second)
	if err != nil {
		return nil, err
	}
	parsed.Monitoring = ParsedMonitoringConfig{
		SystemInfo:      cfg.Monitoring.SystemInfo,
		ProcessMonitor:  cfg.Monitoring.ProcessMonitor,
		FileMonitor:     cfg.Monitoring.FileMonitor,
		NetworkMonitor:  cfg.Monitoring.NetworkMonitor,
		AuthMonitor:     cfg.Monitoring.AuthMonitor,
		WatchPaths:      cfg.Monitoring.WatchPaths,
		ScanInterval:    scanInterval,
	}

	return parsed, nil
}

// parseDuration parses a duration string, returns default if empty
func parseDuration(s string, defaultDur time.Duration) (time.Duration, error) {
	if s == "" {
		return defaultDur, nil
	}
	return time.ParseDuration(s)
}

// setDefaults applies default values to missing config fields
func setDefaults(cfg *ParsedConfig) {
	if cfg.Server.Timeout == 0 {
		cfg.Server.Timeout = 30 * time.Second
	}
	if cfg.Server.RetryMax == 0 {
		cfg.Server.RetryMax = 3
	}
	if cfg.Server.BatchSize == 0 {
		cfg.Server.BatchSize = 100
	}
	
	if cfg.Agent.ReportInterval == 0 {
		cfg.Agent.ReportInterval = 60 * time.Second
	}
	if cfg.Agent.BufferSize == 0 {
		cfg.Agent.BufferSize = 1000
	}
	if cfg.Agent.MaxQueueSize == 0 {
		cfg.Agent.MaxQueueSize = 10000
	}
	
	if cfg.Monitoring.ScanInterval == 0 {
		cfg.Monitoring.ScanInterval = 5 * time.Second
	}
	
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}

	// Local output defaults
	if cfg.LocalOutput.ShowTimestamp == false && cfg.LocalOutput.ShowColors == false {
		// Only set defaults if both are false (indicating they weren't set)
		cfg.LocalOutput.ShowTimestamp = true
		cfg.LocalOutput.ShowColors = true
	}
} 