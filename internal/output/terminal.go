package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sec-tracker/internal/collector"
	"github.com/sec-tracker/internal/config"
	"github.com/sec-tracker/internal/monitor"
)

// Colors for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// TerminalOutputter handles terminal output for local mode
type TerminalOutputter struct {
	config     *config.ParsedConfig
	useColors  bool
	jsonFormat bool
}

// NewTerminalOutputter creates a new terminal outputter
func NewTerminalOutputter(cfg *config.ParsedConfig) *TerminalOutputter {
	return &TerminalOutputter{
		config:     cfg,
		useColors:  cfg.LocalOutput.ShowColors && isTerminal(),
		jsonFormat: cfg.LocalOutput.JSONFormat,
	}
}

// isTerminal checks if output is going to a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// colorize adds color to text if colors are enabled
func (t *TerminalOutputter) colorize(color, text string) string {
	if !t.useColors {
		return text
	}
	return color + text + ColorReset
}

// PrintSystemInfo outputs system information
func (t *TerminalOutputter) PrintSystemInfo(sysInfo *collector.SystemInfo) {
	if t.jsonFormat {
		t.printSystemInfoJSON(sysInfo)
		return
	}

	t.printSystemInfoHuman(sysInfo)
}

// printSystemInfoJSON outputs system info in JSON format
func (t *TerminalOutputter) printSystemInfoJSON(sysInfo *collector.SystemInfo) {
	data, err := json.MarshalIndent(sysInfo, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling system info: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

// printSystemInfoHuman outputs system info in human-readable format
func (t *TerminalOutputter) printSystemInfoHuman(sysInfo *collector.SystemInfo) {
	fmt.Printf("%s%s SYSTEM INFORMATION %s%s\n", 
		t.colorize(ColorBold, ""), 
		t.colorize(ColorBlue, "=="),
		t.colorize(ColorBlue, "=="),
		t.colorize(ColorReset, ""))
	
	if t.config.LocalOutput.ShowTimestamp {
		fmt.Printf("%s: %s\n", 
			t.colorize(ColorCyan, "Timestamp"),
			sysInfo.Timestamp.Format("2006-01-02 15:04:05"))
	}
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Hostname"), 
		t.colorize(ColorWhite, sysInfo.Hostname))
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "OS"), 
		t.colorize(ColorWhite, sysInfo.OS))
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Kernel"), 
		t.colorize(ColorWhite, sysInfo.Kernel))
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Architecture"), 
		t.colorize(ColorWhite, sysInfo.Architecture))

	// CPU Information
	fmt.Printf("\n%s%s CPU %s%s\n", 
		t.colorize(ColorBold, ""), 
		t.colorize(ColorGreen, "---"),
		t.colorize(ColorGreen, "---"),
		t.colorize(ColorReset, ""))
	
	fmt.Printf("%s: %d\n", 
		t.colorize(ColorCyan, "Cores"), 
		sysInfo.CPUInfo.Cores)
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Model"), 
		t.colorize(ColorWhite, sysInfo.CPUInfo.ModelName))
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Usage"), 
		t.getUsageColor(sysInfo.CPUInfo.UsagePercent, fmt.Sprintf("%.1f%%", sysInfo.CPUInfo.UsagePercent)))

	// Memory Information
	fmt.Printf("\n%s%s MEMORY %s%s\n", 
		t.colorize(ColorBold, ""), 
		t.colorize(ColorGreen, "---"),
		t.colorize(ColorGreen, "---"),
		t.colorize(ColorReset, ""))
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Total"), 
		t.colorize(ColorWhite, formatBytes(sysInfo.MemoryInfo.Total)))
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Available"), 
		t.colorize(ColorWhite, formatBytes(sysInfo.MemoryInfo.Available)))
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Used"), 
		t.colorize(ColorWhite, formatBytes(sysInfo.MemoryInfo.Used)))
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Usage"), 
		t.getUsageColor(sysInfo.MemoryInfo.UsagePercent, fmt.Sprintf("%.1f%%", sysInfo.MemoryInfo.UsagePercent)))

	// System Status
	fmt.Printf("\n%s%s STATUS %s%s\n", 
		t.colorize(ColorBold, ""), 
		t.colorize(ColorGreen, "---"),
		t.colorize(ColorGreen, "---"),
		t.colorize(ColorReset, ""))
	
	fmt.Printf("%s: %s\n", 
		t.colorize(ColorCyan, "Uptime"), 
		t.colorize(ColorWhite, formatDuration(sysInfo.Uptime)))
	
	fmt.Printf("%s: %.2f %.2f %.2f\n", 
		t.colorize(ColorCyan, "Load Average"), 
		sysInfo.LoadAverage.Load1,
		sysInfo.LoadAverage.Load5,
		sysInfo.LoadAverage.Load15)

	fmt.Println(strings.Repeat("-", 50))
}

// PrintEvent outputs a security event
func (t *TerminalOutputter) PrintEvent(event monitor.Event) {
	if t.jsonFormat {
		t.printEventJSON(event)
		return
	}

	t.printEventHuman(event)
}

// printEventJSON outputs event in JSON format
func (t *TerminalOutputter) printEventJSON(event monitor.Event) {
	data, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling event: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

// printEventHuman outputs event in human-readable format
func (t *TerminalOutputter) printEventHuman(event monitor.Event) {
	// Event header with severity color
	severityColor := t.getSeverityColor(event.Severity)
	
	if t.config.LocalOutput.CompactOutput {
		// Compact format
		timestamp := ""
		if t.config.LocalOutput.ShowTimestamp {
			timestamp = event.Timestamp.Format("15:04:05") + " "
		}
		
		fmt.Printf("%s[%s] %s: %s%s\n",
			timestamp,
			t.colorize(severityColor, strings.ToUpper(string(event.Type))),
			t.colorize(severityColor, strings.ToUpper(event.Severity)),
			event.Message,
			t.colorize(ColorReset, ""))
	} else {
		// Detailed format
		fmt.Printf("\n%s%s EVENT %s%s\n", 
			t.colorize(ColorBold, ""), 
			t.colorize(severityColor, ">>>"),
			t.colorize(severityColor, "<<<"),
			t.colorize(ColorReset, ""))
		
		if t.config.LocalOutput.ShowTimestamp {
			fmt.Printf("%s: %s\n", 
				t.colorize(ColorCyan, "Time"),
				event.Timestamp.Format("2006-01-02 15:04:05"))
		}
		
		fmt.Printf("%s: %s\n", 
			t.colorize(ColorCyan, "Type"), 
			t.colorize(ColorWhite, string(event.Type)))
		
		fmt.Printf("%s: %s\n", 
			t.colorize(ColorCyan, "Severity"), 
			t.colorize(severityColor, event.Severity))
		
		fmt.Printf("%s: %s\n", 
			t.colorize(ColorCyan, "Source"), 
			t.colorize(ColorWhite, event.Source))
		
		fmt.Printf("%s: %s\n", 
			t.colorize(ColorCyan, "Message"), 
			t.colorize(ColorWhite, event.Message))
		
		// Print detailed event information based on type
		t.printEventDetails(event)
		
		fmt.Println(strings.Repeat("-", 40))
	}
}

// printEventDetails prints type-specific event details
func (t *TerminalOutputter) printEventDetails(event monitor.Event) {
	switch event.Type {
	case monitor.EventTypeProcess:
		if procEvent, ok := event.Details["process_event"].(map[string]interface{}); ok {
			fmt.Printf("%s: PID=%v, PPID=%v, User=%v, Command=%v\n",
				t.colorize(ColorCyan, "Details"),
				procEvent["pid"], procEvent["ppid"], 
				procEvent["user"], procEvent["command"])
		}
	case monitor.EventTypeFile:
		if fileEvent, ok := event.Details["file_event"].(map[string]interface{}); ok {
			fmt.Printf("%s: Path=%v, Action=%v, Size=%v\n",
				t.colorize(ColorCyan, "Details"),
				fileEvent["path"], fileEvent["action"], fileEvent["size"])
		}
	case monitor.EventTypeAuth:
		if authEvent, ok := event.Details["auth_event"].(map[string]interface{}); ok {
			fmt.Printf("%s: User=%v, Action=%v, Success=%v\n",
				t.colorize(ColorCyan, "Details"),
				authEvent["user"], authEvent["action"], authEvent["success"])
		}
	}
}

// getSeverityColor returns color based on severity
func (t *TerminalOutputter) getSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return ColorRed
	case "warning":
		return ColorYellow
	case "info":
		return ColorGreen
	case "error":
		return ColorRed
	default:
		return ColorWhite
	}
}

// getUsageColor returns color based on usage percentage
func (t *TerminalOutputter) getUsageColor(percentage float64, text string) string {
	if percentage >= 90 {
		return t.colorize(ColorRed, text)
	} else if percentage >= 70 {
		return t.colorize(ColorYellow, text)
	}
	return t.colorize(ColorGreen, text)
}

// formatBytes converts bytes to human readable format
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

// formatDuration converts time.Duration to human readable format
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// PrintSummary prints a summary line
func (t *TerminalOutputter) PrintSummary(message string) {
	if t.jsonFormat {
		summary := map[string]interface{}{
			"timestamp": time.Now(),
			"type":      "summary",
			"message":   message,
		}
		data, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("\n%s%s%s\n", 
			t.colorize(ColorBold+ColorBlue, ">>> "),
			t.colorize(ColorBlue, message),
			t.colorize(ColorReset, ""))
	}
} 