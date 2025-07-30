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

	// Filter out unimportant file events
	if m.shouldFilterFileEvent(event.Name, action) {
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

// shouldFilterFileEvent determines if a file event should be filtered out
func (m *Monitor) shouldFilterFileEvent(path, action string) bool {
	// Filter out temporary files and common noise
	if strings.Contains(path, "/.") ||
	   strings.HasSuffix(path, "~") ||
	   strings.HasSuffix(path, ".tmp") ||
	   strings.HasSuffix(path, ".swp") ||
	   strings.HasSuffix(path, ".lock") ||
	   strings.Contains(path, "/tmp/") ||
	   strings.Contains(path, "/.cache/") ||
	   strings.Contains(path, "/.local/") {
		return true
	}
	
	// Filter out log file modifications (too noisy)
	if action == "modify" && (
		strings.Contains(path, "/var/log/") ||
		strings.HasSuffix(path, ".log")) {
		return true
	}
	
	// Only monitor critical files in /etc
	if strings.HasPrefix(path, "/etc/") {
		criticalFiles := []string{
			"/etc/passwd", "/etc/shadow", "/etc/group",
			"/etc/sudoers", "/etc/hosts", "/etc/fstab",
			"/etc/ssh/", "/etc/crontab", "/etc/profile",
			"/etc/bashrc", "/etc/environment",
		}
		
		isCritical := false
		for _, critical := range criticalFiles {
			if strings.HasPrefix(path, critical) {
				isCritical = true
				break
			}
		}
		
		if !isCritical {
			return true
		}
	}
	
	return false
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

		// Skip if this process should be filtered out
		if m.shouldFilterProcess(procInfo) {
			continue
		}

		currentProcs[pid] = procInfo

		// Check for new processes
		if _, exists := m.procMap[pid]; !exists {
			m.handleProcessEvent(procInfo, "started")
		}
	}

	// Check for terminated processes (only for tracked processes)
	for pid, procInfo := range m.procMap {
		if _, exists := currentProcs[pid]; !exists {
			// Only report termination for important processes
			if m.isImportantProcess(procInfo) {
				m.handleProcessEvent(procInfo, "stopped")
			}
		}
	}

	m.procMap = currentProcs
}

// shouldFilterProcess determines if a process should be filtered out
func (m *Monitor) shouldFilterProcess(proc ProcessInfo) bool {
	command := strings.ToLower(proc.Command)
	
	// Filter out common system processes that create noise
	noiseProcesses := []string{
		"kworker", "ksoftirqd", "migration", "rcu_", "watchdog",
		"systemd", "init", "kernel", "kthread", "irq/",
		"dbus", "NetworkManager", "systemd-", "avahi-daemon",
		"rsyslog", "cron", "getty", "dhclient", "ntpd",
		"polkitd", "accounts-daemon", "packagekit", "udisks",
		"colord", "bluetooth", "cups", "pulseaudio",
		"gnome-", "unity-", "compiz", "Xorg", "lightdm",
		"postgres", "mysqld", "apache2", "nginx", "node",
		"python3 -u /usr/bin/", "python /usr/bin/",
		"/snap/", "snap-confine", "snapd",
	}
	
	for _, noise := range noiseProcesses {
		if strings.Contains(command, noise) {
			return true
		}
	}
	
	// Filter out very short-lived or trivial commands
	trivialCommands := []string{
		"ls", "ps", "cat", "echo", "pwd", "whoami", "id",
		"which", "whereis", "man", "help", "history",
		"clear", "reset", "tput", "stty", "uptime",
		"date", "cal", "bc", "wc", "head", "tail",
		"grep", "sed", "awk", "sort", "uniq", "cut",
		"tr", "tee", "less", "more", "vi", "nano",
		"sleep", "true", "false", "test", "expr",
	}
	
	// Only filter if it's a simple command without arguments
	commandParts := strings.Fields(command)
	if len(commandParts) == 1 {
		for _, trivial := range trivialCommands {
			if commandParts[0] == trivial || 
			   strings.HasSuffix(commandParts[0], "/"+trivial) {
				return true
			}
		}
	}
	
	// Filter out processes with very short runtime (likely completed already)
	if proc.PID == 0 {
		return true
	}
	
	return false
}

// isImportantProcess determines if a process termination should be reported
func (m *Monitor) isImportantProcess(proc ProcessInfo) bool {
	command := strings.ToLower(proc.Command)
	
	// Important processes whose termination should be reported
	importantProcesses := []string{
		"sshd", "ssh", "sudo", "su", "systemctl",
		"service", "mount", "umount", "crontab",
		"iptables", "ufw", "passwd", "useradd", "userdel",
		"docker", "kubectl", "git", "curl", "wget",
		"nc", "netcat", "nmap", "tcpdump", "wireshark",
	}
	
	for _, important := range importantProcesses {
		if strings.Contains(command, important) {
			return true
		}
	}
	
	// Processes running as root (except system processes)
	if proc.User == "root" && !m.isSystemProcess(command) {
		return true
	}
	
	return false
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

	// Read /proc/[pid]/cmdline for full command line arguments
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	cmdlineContent, err := os.ReadFile(cmdlinePath)
	if err == nil {
		// cmdline is null-separated, convert to space-separated
		cmdline := string(cmdlineContent)
		cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if cmdline != "" {
			info.Command = cmdline
		}
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
	message := fmt.Sprintf("Process %s: %s (PID: %d)", action, proc.Command, proc.PID)
	
	// Enhanced security analysis
	if action == "started" {
		severity = m.analyzeProcessSecurity(proc)
		
		// Special handling for shell commands
		if m.isShellProcess(proc.Command) {
			severity = m.analyzeShellCommand(proc)
			message = fmt.Sprintf("Shell command executed: %s by %s (PID: %d)", 
				m.extractShellCommand(proc.Command), proc.User, proc.PID)
		}
		
		// Check for SSH-related processes
		if m.isSSHRelated(proc.Command) {
			severity = "warning"
			message = fmt.Sprintf("SSH activity: %s by %s (PID: %d)", 
				proc.Command, proc.User, proc.PID)
		}
		
		// Check for system administration commands
		if m.isSystemAdminCommand(proc.Command) {
			severity = "warning"
			message = fmt.Sprintf("System admin command: %s by %s (PID: %d)", 
				proc.Command, proc.User, proc.PID)
		}
	}

	// Add command details to event
	details := map[string]interface{}{
		"process_event": procEvent,
		"command_type": m.categorizeCommand(proc.Command),
		"risk_level":   m.getRiskLevel(proc.Command),
	}

	m.sendEvent(Event{
		ID:        m.generateEventID(),
		Type:      EventTypeProcess,
		Timestamp: time.Now(),
		Source:    "process_monitor",
		Message:   message,
		Severity:  severity,
		Details:   details,
		AgentID:   m.agentID,
	})
}

// analyzeProcessSecurity determines security level of a process
func (m *Monitor) analyzeProcessSecurity(proc ProcessInfo) string {
	command := strings.ToLower(proc.Command)
	
	// Critical security commands
	criticalCommands := []string{
		"sudo", "su", "passwd", "useradd", "userdel", "usermod",
		"chmod +s", "chown root", "mount", "umount",
		"iptables", "ufw", "firewall", "systemctl",
		"service", "crontab", "at", "nc", "netcat",
		"nmap", "tcpdump", "wireshark", "john", "hashcat",
	}
	
	for _, cmd := range criticalCommands {
		if strings.Contains(command, cmd) {
			return "critical"
		}
	}
	
	// Warning level commands
	warningCommands := []string{
		"ssh", "scp", "rsync", "wget", "curl",
		"git clone", "docker", "kubectl", "aws",
		"rm -rf", "dd if=", "fdisk", "parted",
		"ps aux", "netstat", "ss", "lsof",
	}
	
	for _, cmd := range warningCommands {
		if strings.Contains(command, cmd) {
			return "warning"
		}
	}
	
	// Check if running as root
	if proc.User == "root" && !m.isSystemProcess(command) {
		return "warning"
	}
	
	return "info"
}

// isShellProcess checks if the process is a shell
func (m *Monitor) isShellProcess(command string) bool {
	command = strings.ToLower(command)
	shells := []string{"bash", "zsh", "sh", "fish", "csh", "tcsh", "ksh"}
	
	for _, shell := range shells {
		// Check if command starts with shell name
		if strings.HasPrefix(command, shell+" ") || 
		   strings.HasPrefix(command, "/bin/"+shell+" ") ||
		   strings.HasPrefix(command, "/usr/bin/"+shell+" ") {
			return true
		}
	}
	return false
}

// analyzeShellCommand analyzes shell commands for security
func (m *Monitor) analyzeShellCommand(proc ProcessInfo) string {
	command := strings.ToLower(proc.Command)
	
	// Check for potentially dangerous shell patterns
	dangerousPatterns := []string{
		"rm -rf /", ":(){ :|:& };:", "curl.*|sh", "wget.*|sh",
		"base64.*|sh", "echo.*|sh", "cat /etc/passwd", "cat /etc/shadow",
		"history -c", "unset HISTFILE", "export HISTSIZE=0",
		"> ~/.bash_history", "shred", "wipe",
	}
	
	for _, pattern := range dangerousPatterns {
		if strings.Contains(command, pattern) {
			return "critical"
		}
	}
	
	// Check for file manipulation
	if strings.Contains(command, "rm ") || strings.Contains(command, "mv ") ||
	   strings.Contains(command, "cp ") || strings.Contains(command, "chmod ") {
		return "warning"
	}
	
	// Check for network activity
	if strings.Contains(command, "curl ") || strings.Contains(command, "wget ") ||
	   strings.Contains(command, "ssh ") || strings.Contains(command, "scp ") {
		return "warning"
	}
	
	return "info"
}

// extractShellCommand extracts the actual command from shell process
func (m *Monitor) extractShellCommand(command string) string {
	// Extract command after -c flag
	if strings.Contains(command, " -c ") {
		parts := strings.Split(command, " -c ")
		if len(parts) > 1 {
			return strings.Trim(parts[1], "\"'")
		}
	}
	
	// Extract last part if it's a direct command
	parts := strings.Fields(command)
	if len(parts) > 1 {
		return strings.Join(parts[1:], " ")
	}
	
	return command
}

// isSSHRelated checks if command is SSH-related
func (m *Monitor) isSSHRelated(command string) bool {
	command = strings.ToLower(command)
	sshCommands := []string{"sshd", "ssh", "scp", "sftp", "ssh-keygen", "ssh-add", "ssh-agent"}
	
	for _, cmd := range sshCommands {
		if strings.Contains(command, cmd) {
			return true
		}
	}
	return false
}

// isSystemAdminCommand checks if command is system administration related
func (m *Monitor) isSystemAdminCommand(command string) bool {
	command = strings.ToLower(command)
	adminCommands := []string{
		"systemctl", "service", "chkconfig", "update-rc.d",
		"apt", "yum", "dnf", "pacman", "zypper",
		"mount", "umount", "fdisk", "parted", "lvm",
		"iptables", "ufw", "firewall-cmd", "fail2ban",
		"crontab", "at", "anacron",
	}
	
	for _, cmd := range adminCommands {
		if strings.Contains(command, cmd) {
			return true
		}
	}
	return false
}

// isSystemProcess checks if it's a system process
func (m *Monitor) isSystemProcess(command string) bool {
	systemProcesses := []string{
		"kernel", "kthread", "migration", "ksoftirqd", "watchdog",
		"systemd", "init", "kworker", "rcu_", "irq/", "getty",
	}
	
	for _, proc := range systemProcesses {
		if strings.Contains(command, proc) {
			return true
		}
	}
	return false
}

// categorizeCommand categorizes the command type
func (m *Monitor) categorizeCommand(command string) string {
	command = strings.ToLower(command)
	
	if m.isShellProcess(command) {
		return "shell_command"
	}
	if m.isSSHRelated(command) {
		return "ssh_activity"
	}
	if m.isSystemAdminCommand(command) {
		return "system_admin"
	}
	if strings.Contains(command, "docker") || strings.Contains(command, "kubectl") {
		return "container"
	}
	if strings.Contains(command, "git") {
		return "version_control"
	}
	if strings.Contains(command, "curl") || strings.Contains(command, "wget") {
		return "network"
	}
	if strings.Contains(command, "vim") || strings.Contains(command, "nano") || strings.Contains(command, "emacs") {
		return "text_editor"
	}
	
	return "general"
}

// getRiskLevel determines risk level of command
func (m *Monitor) getRiskLevel(command string) string {
	command = strings.ToLower(command)
	
	// High risk patterns
	highRisk := []string{
		"rm -rf", "dd if=", ":(){ :|:& };:", "curl.*|sh", "wget.*|sh",
		"chmod +s", "chown root", "/etc/passwd", "/etc/shadow",
		"iptables -F", "ufw disable", "systemctl stop firewall",
	}
	
	for _, pattern := range highRisk {
		if strings.Contains(command, pattern) {
			return "high"
		}
	}
	
	// Medium risk patterns
	mediumRisk := []string{
		"sudo", "su", "ssh", "scp", "mount", "systemctl",
		"service", "crontab", "chmod", "chown", "passwd",
	}
	
	for _, pattern := range mediumRisk {
		if strings.Contains(command, pattern) {
			return "medium"
		}
	}
	
	return "low"
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