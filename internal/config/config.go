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
	URL       string        `json:"url"`
	APIKey    string        `json:"api_key"`
	Timeout   time.Duration `json:"timeout"`
	RetryMax  int           `json:"retry_max"`
	BatchSize int           `json:"batch_size"`
}

// AgentConfig contains agent-specific settings
type AgentConfig struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	ReportInterval  time.Duration `json:"report_interval"`
	BufferSize      int           `json:"buffer_size"`
	MaxQueueSize    int           `json:"max_queue_size"`
	EnableTLS       bool          `json:"enable_tls"`
	CertPath        string        `json:"cert_path"`
}

// MonitoringConfig defines what to monitor
type MonitoringConfig struct {
	SystemInfo      bool          `json:"system_info"`
	ProcessMonitor  bool          `json:"process_monitor"`
	FileMonitor     bool          `json:"file_monitor"`
	NetworkMonitor  bool          `json:"network_monitor"`
	AuthMonitor     bool          `json:"auth_monitor"`
	WatchPaths      []string      `json:"watch_paths"`
	ScanInterval    time.Duration `json:"scan_interval"`
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

// Load reads configuration from file
func Load(filename string) (*Config, error) {
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

	// Set defaults if not specified
	setDefaults(config)
	
	return config, nil
}

// setDefaults applies default values to missing config fields
func setDefaults(cfg *Config) {
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