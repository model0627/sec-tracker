package agent

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/sec-tracker/internal/collector"
	"github.com/sec-tracker/internal/config"
	"github.com/sec-tracker/internal/monitor"
	"github.com/sec-tracker/internal/output"
	"github.com/sec-tracker/internal/sender"
)

// Agent represents the main security monitoring agent
type Agent struct {
	config          *config.Config
	systemCollector *collector.SystemCollector
	monitor         *monitor.Monitor
	client          *sender.Client
	terminalOutput  *output.TerminalOutputter
	
	// Event processing
	eventBuffer     []monitor.Event
	eventBufferMutex sync.RWMutex
	
	// Status tracking
	status          AgentStatus
	lastHeartbeat   time.Time
	metrics         AgentMetrics
}

// AgentStatus represents the current status of the agent
type AgentStatus string

const (
	StatusStarting AgentStatus = "starting"
	StatusRunning  AgentStatus = "running"
	StatusStopping AgentStatus = "stopping"
	StatusStopped  AgentStatus = "stopped"
	StatusError    AgentStatus = "error"
)

// AgentMetrics tracks agent performance
type AgentMetrics struct {
	StartTime       time.Time `json:"start_time"`
	EventsProcessed int64     `json:"events_processed"`
	ReportsGenerated int64    `json:"reports_generated"`
	LastSystemScan  time.Time `json:"last_system_scan"`
	LastEventSent   time.Time `json:"last_event_sent"`
	MemoryUsage     uint64    `json:"memory_usage"`
	CPUUsage        float64   `json:"cpu_usage"`
}

// New creates a new agent instance
func New(cfg *config.Config) (*Agent, error) {
	// Create system collector
	sysCollector := collector.NewSystemCollector()
	
	// Create monitor
	monitor, err := monitor.NewMonitor(cfg.Agent.ID, cfg.Monitoring.WatchPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to create monitor: %w", err)
	}
	
	agent := &Agent{
		config:          cfg,
		systemCollector: sysCollector,
		monitor:         monitor,
		eventBuffer:     make([]monitor.Event, 0),
		status:          StatusStopped,
		metrics: AgentMetrics{
			StartTime: time.Now(),
		},
	}

	// Create appropriate output handler
	if cfg.LocalMode {
		agent.terminalOutput = output.NewTerminalOutputter(cfg)
	} else {
		// Create communication client for server mode
		agent.client = sender.NewClient(cfg)
	}
	
	return agent, nil
}

// Start begins agent operations
func (a *Agent) Start(ctx context.Context) error {
	a.status = StatusStarting
	
	if a.config.LocalMode {
		return a.startLocalMode(ctx)
	} else {
		return a.startServerMode(ctx)
	}
}

// startLocalMode runs the agent in local terminal output mode
func (a *Agent) startLocalMode(ctx context.Context) error {
	a.status = StatusRunning
	a.metrics.StartTime = time.Now()

	// For one-shot mode, just collect and display system info once
	if a.config.LocalOutput.OneShot {
		return a.runOneShot()
	}

	// For continuous mode, start monitoring
	return a.runContinuous(ctx)
}

// runOneShot performs a single system scan and exits
func (a *Agent) runOneShot() error {
	a.terminalOutput.PrintSummary("Collecting system information...")
	
	sysInfo, err := a.systemCollector.Collect()
	if err != nil {
		return fmt.Errorf("failed to collect system info: %w", err)
	}
	
	a.terminalOutput.PrintSystemInfo(sysInfo)
	a.metrics.ReportsGenerated++
	
	a.terminalOutput.PrintSummary("System scan completed")
	return nil
}

// runContinuous runs continuous monitoring with terminal output
func (a *Agent) runContinuous(ctx context.Context) error {
	// Start monitoring
	if err := a.monitor.Start(ctx); err != nil {
		a.status = StatusError
		return fmt.Errorf("failed to start monitor: %w", err)
	}

	var wg sync.WaitGroup
	
	// System information collection loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.localSystemInfoLoop(ctx)
	}()
	
	// Event processing loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.localEventProcessingLoop(ctx)
	}()
	
	// Metrics collection loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.localMetricsLoop(ctx)
	}()
	
	// Wait for context cancellation
	<-ctx.Done()
	
	// Graceful shutdown
	a.status = StatusStopping
	
	// Stop monitoring
	if err := a.monitor.Close(); err != nil {
		fmt.Printf("Error closing monitor: %v\n", err)
	}
	
	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		a.terminalOutput.PrintSummary("Monitoring stopped gracefully")
	case <-time.After(5 * time.Second):
		a.terminalOutput.PrintSummary("Timeout waiting for shutdown")
	}
	
	a.status = StatusStopped
	return nil
}

// localSystemInfoLoop periodically collects and displays system information
func (a *Agent) localSystemInfoLoop(ctx context.Context) {
	// Show initial system info
	a.collectAndDisplaySystemInfo()
	
	// Then show periodically (less frequent in local mode)
	ticker := time.NewTicker(a.config.Agent.ReportInterval * 10) // Every 10 minutes by default
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.collectAndDisplaySystemInfo()
		}
	}
}

// collectAndDisplaySystemInfo collects current system information and displays it
func (a *Agent) collectAndDisplaySystemInfo() {
	sysInfo, err := a.systemCollector.Collect()
	if err != nil {
		fmt.Printf("Failed to collect system info: %v\n", err)
		return
	}
	
	a.metrics.LastSystemScan = time.Now()
	a.terminalOutput.PrintSystemInfo(sysInfo)
	a.metrics.ReportsGenerated++
}

// localEventProcessingLoop processes security events and displays them
func (a *Agent) localEventProcessingLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-a.monitor.Events():
			a.terminalOutput.PrintEvent(event)
			a.metrics.EventsProcessed++
		}
	}
}

// localMetricsLoop displays periodic metrics in local mode
func (a *Agent) localMetricsLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute * 5) // Show metrics every 5 minutes
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.displayMetrics()
		}
	}
}

// displayMetrics shows current agent metrics
func (a *Agent) displayMetrics() {
	if !a.config.LocalOutput.CompactOutput {
		uptime := time.Since(a.metrics.StartTime)
		message := fmt.Sprintf("Agent Metrics - Uptime: %s, Events: %d, Reports: %d", 
			formatDuration(uptime), a.metrics.EventsProcessed, a.metrics.ReportsGenerated)
		a.terminalOutput.PrintSummary(message)
	}
}

// startServerMode runs the agent in server communication mode
func (a *Agent) startServerMode(ctx context.Context) error {
	log.Printf("Starting Security Tracker Agent (ID: %s)", a.config.Agent.ID)
	
	// Start communication client
	if err := a.client.Start(ctx); err != nil {
		a.status = StatusError
		return fmt.Errorf("failed to start client: %w", err)
	}
	
	// Perform initial health check
	if err := a.client.HealthCheck(); err != nil {
		log.Printf("Warning: Initial health check failed: %v", err)
	}
	
	// Start monitoring
	if err := a.monitor.Start(ctx); err != nil {
		a.status = StatusError
		return fmt.Errorf("failed to start monitor: %w", err)
	}
	
	a.status = StatusRunning
	a.metrics.StartTime = time.Now()
	
	// Start main loops
	var wg sync.WaitGroup
	
	// System information collection loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.systemInfoLoop(ctx)
	}()
	
	// Event processing loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.eventProcessingLoop(ctx)
	}()
	
	// Health check loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.healthCheckLoop(ctx)
	}()
	
	// Metrics collection loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.metricsLoop(ctx)
	}()
	
	log.Println("Agent started successfully")
	
	// Wait for context cancellation
	<-ctx.Done()
	
	// Graceful shutdown
	a.status = StatusStopping
	log.Println("Shutting down agent...")
	
	// Stop monitoring
	if err := a.monitor.Close(); err != nil {
		log.Printf("Error closing monitor: %v", err)
	}
	
	// Flush remaining events
	a.flushEvents()
	
	// Close client
	if err := a.client.Close(); err != nil {
		log.Printf("Error closing client: %v", err)
	}
	
	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		log.Println("Agent stopped gracefully")
	case <-time.After(10 * time.Second):
		log.Println("Timeout waiting for agent shutdown")
	}
	
	a.status = StatusStopped
	return nil
}

// systemInfoLoop periodically collects and sends system information
func (a *Agent) systemInfoLoop(ctx context.Context) {
	// Send initial system info immediately
	a.collectAndSendSystemInfo()
	
	// Then send periodically
	ticker := time.NewTicker(a.config.Agent.ReportInterval * 5) // Less frequent than events
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.collectAndSendSystemInfo()
		}
	}
}

// collectAndSendSystemInfo collects current system information and sends it
func (a *Agent) collectAndSendSystemInfo() {
	sysInfo, err := a.systemCollector.Collect()
	if err != nil {
		log.Printf("Failed to collect system info: %v", err)
		return
	}
	
	a.metrics.LastSystemScan = time.Now()
	
	if err := a.client.SendSystemInfo(sysInfo); err != nil {
		log.Printf("Failed to send system info: %v", err)
		return
	}
	
	a.metrics.ReportsGenerated++
	log.Printf("System information sent successfully")
}

// eventProcessingLoop processes security events from the monitor
func (a *Agent) eventProcessingLoop(ctx context.Context) {
	// Buffer events and send in batches
	batchTicker := time.NewTicker(time.Second * 10) // Send events every 10 seconds
	defer batchTicker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
			
		case event := <-a.monitor.Events():
			a.addEventToBuffer(event)
			
		case <-batchTicker.C:
			a.sendBufferedEvents()
		}
	}
}

// addEventToBuffer adds an event to the buffer
func (a *Agent) addEventToBuffer(event monitor.Event) {
	a.eventBufferMutex.Lock()
	defer a.eventBufferMutex.Unlock()
	
	a.eventBuffer = append(a.eventBuffer, event)
	a.metrics.EventsProcessed++
	
	// If buffer is getting full, force send
	if len(a.eventBuffer) >= a.config.Agent.BufferSize {
		go a.sendBufferedEvents()
	}
}

// sendBufferedEvents sends all buffered events
func (a *Agent) sendBufferedEvents() {
	a.eventBufferMutex.Lock()
	if len(a.eventBuffer) == 0 {
		a.eventBufferMutex.Unlock()
		return
	}
	
	events := make([]monitor.Event, len(a.eventBuffer))
	copy(events, a.eventBuffer)
	a.eventBuffer = a.eventBuffer[:0] // Clear buffer
	a.eventBufferMutex.Unlock()
	
	if err := a.client.SendEvents(events); err != nil {
		log.Printf("Failed to send %d events: %v", len(events), err)
		
		// Re-add events to buffer on failure (with limit)
		a.eventBufferMutex.Lock()
		if len(a.eventBuffer) < a.config.Agent.MaxQueueSize/2 {
			a.eventBuffer = append(a.eventBuffer, events...)
		}
		a.eventBufferMutex.Unlock()
		return
	}
	
	a.metrics.LastEventSent = time.Now()
	log.Printf("Successfully sent %d events", len(events))
}

// flushEvents sends any remaining events during shutdown
func (a *Agent) flushEvents() {
	a.eventBufferMutex.Lock()
	if len(a.eventBuffer) == 0 {
		a.eventBufferMutex.Unlock()
		return
	}
	
	events := make([]monitor.Event, len(a.eventBuffer))
	copy(events, a.eventBuffer)
	a.eventBuffer = a.eventBuffer[:0]
	a.eventBufferMutex.Unlock()
	
	log.Printf("Flushing %d remaining events", len(events))
	if err := a.client.SendEvents(events); err != nil {
		log.Printf("Failed to flush events: %v", err)
	}
}

// healthCheckLoop periodically performs health checks
func (a *Agent) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute * 5) // Health check every 5 minutes
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.client.HealthCheck(); err != nil {
				log.Printf("Health check failed: %v", err)
			} else {
				a.lastHeartbeat = time.Now()
			}
		}
	}
}

// metricsLoop collects agent metrics
func (a *Agent) metricsLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute) // Update metrics every minute
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.updateMetrics()
		}
	}
}

// updateMetrics updates agent performance metrics
func (a *Agent) updateMetrics() {
	// This is simplified - in production you'd collect actual memory/CPU stats
	a.eventBufferMutex.RLock()
	bufferSize := len(a.eventBuffer)
	a.eventBufferMutex.RUnlock()
	
	log.Printf("Agent metrics - Events buffered: %d, Total processed: %d, Reports sent: %d", 
		bufferSize, a.metrics.EventsProcessed, a.metrics.ReportsGenerated)
}

// GetStatus returns the current agent status
func (a *Agent) GetStatus() AgentStatus {
	return a.status
}

// GetMetrics returns agent performance metrics
func (a *Agent) GetMetrics() AgentMetrics {
	a.eventBufferMutex.RLock()
	defer a.eventBufferMutex.RUnlock()
	
	metrics := a.metrics
	// Add current buffer size to the metrics
	return metrics
}

// GetConfig returns the agent configuration
func (a *Agent) GetConfig() *config.Config {
	return a.config
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