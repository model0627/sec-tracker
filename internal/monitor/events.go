package monitor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// EventType represents the type of security event
type EventType string

const (
	EventTypeProcess      EventType = "process"
	EventTypeFile         EventType = "file"
	EventTypeNetwork      EventType = "network"
	EventTypeAuth         EventType = "auth"
	EventTypeSystemChange EventType = "system_change"
)

// Event represents a security event
type Event struct {
	ID          string                 `json:"id"`
	Type        EventType              `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`
	Message     string                 `json:"message"`
	Severity    string                 `json:"severity"`
	Details     map[string]interface{} `json:"details"`
	AgentID     string                 `json:"agent_id"`
}

// ProcessEvent represents a process-related event
type ProcessEvent struct {
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	Command   string `json:"command"`
	User      string `json:"user"`
	Action    string `json:"action"` // started, stopped, elevated
}

// FileEvent represents a file system event
type FileEvent struct {
	Path      string `json:"path"`
	Action    string `json:"action"` // create, modify, delete, access
	User      string `json:"user"`
	Size      int64  `json:"size"`
	Mode      string `json:"mode"`
}

// NetworkEvent represents a network event
type NetworkEvent struct {
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	LocalPort   int    `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
	State       string `json:"state"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
}

// AuthEvent represents an authentication event
type AuthEvent struct {
	User      string `json:"user"`
	Action    string `json:"action"` // login, logout, failed_login, sudo
	Source    string `json:"source"`
	Terminal  string `json:"terminal"`
	Success   bool   `json:"success"`
}

// Monitor manages all event monitoring
type Monitor struct {
	eventChan   chan Event
	agentID     string
	watchPaths  []string
	fileWatcher *fsnotify.Watcher
	lastProcScan time.Time
	procMap     map[int]ProcessInfo
}

// ProcessInfo holds process information
type ProcessInfo struct {
	PID     int
	PPID    int
	Command string
	User    string
}

// NewMonitor creates a new monitor instance
func NewMonitor(agentID string, watchPaths []string) (*Monitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	return &Monitor{
		eventChan:   make(chan Event, 1000),
		agentID:     agentID,
		watchPaths:  watchPaths,
		fileWatcher: watcher,
		procMap:     make(map[int]ProcessInfo),
	}, nil
}

// Start begins monitoring for events
func (m *Monitor) Start(ctx context.Context) error {
	// Start file monitoring
	go m.monitorFiles(ctx)
	
	// Start process monitoring
	go m.monitorProcesses(ctx)
	
	// Start network monitoring
	go m.monitorNetwork(ctx)
	
	// Start auth log monitoring
	go m.monitorAuth(ctx)

	// Add watch paths for file monitoring
	for _, path := range m.watchPaths {
		if err := m.fileWatcher.Add(path); err != nil {
			return fmt.Errorf("failed to add watch path %s: %w", path, err)
		}
	}

	return nil
}

// Events returns the event channel
func (m *Monitor) Events() <-chan Event {
	return m.eventChan
}

// Close stops monitoring and cleans up resources
func (m *Monitor) Close() error {
	close(m.eventChan)
	return m.fileWatcher.Close()
}

// monitorFiles monitors file system events
func (m *Monitor) monitorFiles(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-m.fileWatcher.Events:
			if !ok {
				return
			}
			m.handleFileEvent(event)
		case err, ok := <-m.fileWatcher.Errors:
			if !ok {
				return
			}
			m.sendEvent(Event{
				ID:        m.generateEventID(),
				Type:      EventTypeFile,
				Timestamp: time.Now(),
				Source:    "file_monitor",
				Message:   fmt.Sprintf("File watcher error: %v", err),
				Severity:  "error",
				AgentID:   m.agentID,
			})
		}
	}
}

// handleFileEvent processes file system events
func (m *Monitor) handleFileEvent(event fsnotify.Event) {
	action := ""
	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		action = "create"
	case event.Op&fsnotify.Write == fsnotify.Write:
		action = "modify"
	case event.Op&fsnotify.Remove == fsnotify.Remove:
		action = "delete"
	case event.Op&fsnotify.Rename == fsnotify.Rename:
		action = "rename"
	case event.Op&fsnotify.Chmod == fsnotify.Chmod:
		action = "chmod"
	}

	if action == "" {
		return
	}

	fileInfo, err := os.Stat(event.Name)
	var size int64
	var mode string
	if err == nil {
		size = fileInfo.Size()
		mode = fileInfo.Mode().String()
	}

	fileEvent := FileEvent{
		Path:   event.Name,
		Action: action,
		Size:   size,
		Mode:   mode,
	}

	m.sendEvent(Event{
		ID:        m.generateEventID(),
		Type:      EventTypeFile,
		Timestamp: time.Now(),
		Source:    "file_monitor",
		Message:   fmt.Sprintf("File %s: %s", action, event.Name),
		Severity:  m.getSeverityForFileEvent(action, event.Name),
		Details:   map[string]interface{}{"file_event": fileEvent},
		AgentID:   m.agentID,
	})
}

// monitorProcesses monitors process creation and termination
func (m *Monitor) monitorProcesses(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scanProcesses()
		}
	}
}

// scanProcesses scans /proc for process changes
func (m *Monitor) scanProcesses() {
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return
	}

	currentProcs := make(map[int]ProcessInfo)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		procInfo, err := m.getProcessInfo(pid)
		if err != nil {
			continue
		}

		currentProcs[pid] = procInfo

		// Check for new processes
		if _, exists := m.procMap[pid]; !exists {
			m.handleProcessEvent(procInfo, "started")
		}
	}

	// Check for terminated processes
	for pid, procInfo := range m.procMap {
		if _, exists := currentProcs[pid]; !exists {
			m.handleProcessEvent(procInfo, "stopped")
		}
	}

	m.procMap = currentProcs
}

// getProcessInfo retrieves process information from /proc/[pid]/
func (m *Monitor) getProcessInfo(pid int) (ProcessInfo, error) {
	info := ProcessInfo{PID: pid}

	// Read /proc/[pid]/stat for basic info
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	statContent, err := os.ReadFile(statPath)
	if err != nil {
		return info, err
	}

	fields := strings.Fields(string(statContent))
	if len(fields) >= 4 {
		info.PPID, _ = strconv.Atoi(fields[3])
	}

	// Read /proc/[pid]/comm for command name
	commPath := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	commContent, err := os.ReadFile(commPath)
	if err == nil {
		info.Command = strings.TrimSpace(string(commContent))
	}

	// Read /proc/[pid]/status for user info
	statusPath := filepath.Join("/proc", strconv.Itoa(pid), "status")
	statusContent, err := os.ReadFile(statusPath)
	if err == nil {
		lines := strings.Split(string(statusContent), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					uid, _ := strconv.Atoi(fields[1])
					info.User = m.getUserFromUID(uid)
				}
				break
			}
		}
	}

	return info, nil
}

// getUserFromUID converts UID to username (simplified)
func (m *Monitor) getUserFromUID(uid int) string {
	// In production, you'd parse /etc/passwd or use system calls
	if uid == 0 {
		return "root"
	}
	return fmt.Sprintf("uid:%d", uid)
}

// handleProcessEvent sends process events
func (m *Monitor) handleProcessEvent(proc ProcessInfo, action string) {
	procEvent := ProcessEvent{
		PID:     proc.PID,
		PPID:    proc.PPID,
		Command: proc.Command,
		User:    proc.User,
		Action:  action,
	}

	severity := "info"
	if proc.User == "root" || strings.Contains(proc.Command, "sudo") {
		severity = "warning"
	}

	m.sendEvent(Event{
		ID:        m.generateEventID(),
		Type:      EventTypeProcess,
		Timestamp: time.Now(),
		Source:    "process_monitor",
		Message:   fmt.Sprintf("Process %s: %s (PID: %d)", action, proc.Command, proc.PID),
		Severity:  severity,
		Details:   map[string]interface{}{"process_event": procEvent},
		AgentID:   m.agentID,
	})
}

// monitorNetwork monitors network connections
func (m *Monitor) monitorNetwork(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Simplified network monitoring
			// In production, you'd parse /proc/net/tcp, /proc/net/udp
			// and use netlink sockets for real-time monitoring
		}
	}
}

// monitorAuth monitors authentication events from system logs
func (m *Monitor) monitorAuth(ctx context.Context) {
	// Monitor auth.log for authentication events
	authLogPath := "/var/log/auth.log"
	
	// This is a simplified implementation
	// In production, you'd use inotify to tail the log file
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scanAuthLog(authLogPath)
		}
	}
}

// scanAuthLog scans authentication log for events
func (m *Monitor) scanAuthLog(logPath string) {
	file, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if authEvent := m.parseAuthLogLine(line); authEvent != nil {
			m.sendEvent(Event{
				ID:        m.generateEventID(),
				Type:      EventTypeAuth,
				Timestamp: time.Now(),
				Source:    "auth_monitor",
				Message:   fmt.Sprintf("Auth event: %s by %s", authEvent.Action, authEvent.User),
				Severity:  m.getSeverityForAuthEvent(*authEvent),
				Details:   map[string]interface{}{"auth_event": *authEvent},
				AgentID:   m.agentID,
			})
		}
	}
}

// parseAuthLogLine parses authentication log lines
func (m *Monitor) parseAuthLogLine(line string) *AuthEvent {
	// Simplified parsing - in production you'd have more sophisticated parsing
	if strings.Contains(line, "sudo:") && strings.Contains(line, "COMMAND=") {
		return &AuthEvent{
			Action:  "sudo",
			Success: !strings.Contains(line, "FAILED"),
		}
	}
	
	if strings.Contains(line, "sshd") && strings.Contains(line, "Accepted") {
		return &AuthEvent{
			Action:  "ssh_login",
			Success: true,
		}
	}
	
	if strings.Contains(line, "sshd") && strings.Contains(line, "Failed") {
		return &AuthEvent{
			Action:  "ssh_login",
			Success: false,
		}
	}
	
	return nil
}

// sendEvent sends an event to the event channel
func (m *Monitor) sendEvent(event Event) {
	select {
	case m.eventChan <- event:
	default:
		// Channel is full, drop the event or handle overflow
	}
}

// generateEventID generates a unique event ID
func (m *Monitor) generateEventID() string {
	return fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), len(m.eventChan))
}

// getSeverityForFileEvent determines severity for file events
func (m *Monitor) getSeverityForFileEvent(action, path string) string {
	// Critical paths
	criticalPaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
	}
	
	for _, critPath := range criticalPaths {
		if strings.HasPrefix(path, critPath) {
			return "critical"
		}
	}
	
	if action == "delete" {
		return "warning"
	}
	
	return "info"
}

// getSeverityForAuthEvent determines severity for auth events
func (m *Monitor) getSeverityForAuthEvent(event AuthEvent) string {
	if !event.Success {
		return "warning"
	}
	
	if event.Action == "sudo" {
		return "warning"
	}
	
	return "info"
} 