package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sec-tracker/internal/collector"
	"github.com/sec-tracker/internal/config"
	"github.com/sec-tracker/internal/monitor"
)

// Payload represents data sent to the management server
type Payload struct {
	AgentID     string                `json:"agent_id"`
	Timestamp   time.Time             `json:"timestamp"`
	Type        string                `json:"type"`
	SystemInfo  *collector.SystemInfo `json:"system_info,omitempty"`
	Events      []monitor.Event       `json:"events,omitempty"`
	Checksum    string                `json:"checksum,omitempty"`
}

// Response represents server response
type Response struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// Client handles communication with the management server
type Client struct {
	config     *config.ParsedConfig
	httpClient *http.Client
	queue      []Payload
	queueMutex sync.RWMutex
	retryQueue chan Payload
	metrics    ClientMetrics
}

// ClientMetrics tracks client performance
type ClientMetrics struct {
	TotalSent     int64 `json:"total_sent"`
	TotalFailed   int64 `json:"total_failed"`
	QueueSize     int   `json:"queue_size"`
	LastSent      time.Time `json:"last_sent"`
	LastError     string    `json:"last_error"`
}

// NewClient creates a new communication client
func NewClient(cfg *config.ParsedConfig) *Client {
	// Configure HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.Agent.EnableTLS,
		},
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Server.Timeout,
	}

	return &Client{
		config:     cfg,
		httpClient: httpClient,
		queue:      make([]Payload, 0),
		retryQueue: make(chan Payload, cfg.Agent.MaxQueueSize),
	}
}

// Start begins the client operations
func (c *Client) Start(ctx context.Context) error {
	// Start retry handler
	go c.handleRetries(ctx)
	
	// Start batch sender
	go c.processBatches(ctx)
	
	return nil
}

// SendSystemInfo sends system information to the server
func (c *Client) SendSystemInfo(sysInfo *collector.SystemInfo) error {
	payload := Payload{
		AgentID:    c.config.Agent.ID,
		Timestamp:  time.Now(),
		Type:       "system_info",
		SystemInfo: sysInfo,
	}

	return c.enqueuePayload(payload)
}

// SendEvents sends security events to the server
func (c *Client) SendEvents(events []monitor.Event) error {
	if len(events) == 0 {
		return nil
	}

	payload := Payload{
		AgentID:   c.config.Agent.ID,
		Timestamp: time.Now(),
		Type:      "events",
		Events:    events,
	}

	return c.enqueuePayload(payload)
}

// enqueuePayload adds a payload to the send queue
func (c *Client) enqueuePayload(payload Payload) error {
	c.queueMutex.Lock()
	defer c.queueMutex.Unlock()

	// Check queue size limit
	if len(c.queue) >= c.config.Agent.MaxQueueSize {
		// Remove oldest payload to make room
		c.queue = c.queue[1:]
		c.metrics.TotalFailed++
	}

	c.queue = append(c.queue, payload)
	c.metrics.QueueSize = len(c.queue)
	
	return nil
}

// processBatches processes queued payloads in batches
func (c *Client) processBatches(ctx context.Context) {
	ticker := time.NewTicker(c.config.Agent.ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Send remaining items before shutdown
			c.flushQueue()
			return
		case <-ticker.C:
			c.processBatch()
		}
	}
}

// processBatch processes a batch of payloads
func (c *Client) processBatch() {
	c.queueMutex.Lock()
	if len(c.queue) == 0 {
		c.queueMutex.Unlock()
		return
	}

	// Get batch
	batchSize := c.config.Server.BatchSize
	if len(c.queue) < batchSize {
		batchSize = len(c.queue)
	}

	batch := make([]Payload, batchSize)
	copy(batch, c.queue[:batchSize])
	c.queue = c.queue[batchSize:]
	c.metrics.QueueSize = len(c.queue)
	c.queueMutex.Unlock()

	// Send batch
	if err := c.sendBatch(batch); err != nil {
		// Re-queue failed items
		for _, payload := range batch {
			select {
			case c.retryQueue <- payload:
			default:
				// Retry queue is full, drop payload
				c.metrics.TotalFailed++
			}
		}
		c.metrics.LastError = err.Error()
	} else {
		c.metrics.TotalSent += int64(len(batch))
		c.metrics.LastSent = time.Now()
	}
}

// sendBatch sends a batch of payloads to the server
func (c *Client) sendBatch(batch []Payload) error {
	// Prepare request body
	requestData := map[string]interface{}{
		"agent_id":  c.config.Agent.ID,
		"timestamp": time.Now(),
		"payloads":  batch,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", c.config.Server.URL+"/api/v1/agent/data", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("SecTracker-Agent/%s", c.config.Agent.ID))
	
	if c.config.Server.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Server.APIKey)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("server rejected request: %s", response.Message)
	}

	return nil
}

// handleRetries handles retry logic for failed requests
func (c *Client) handleRetries(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-c.retryQueue:
			c.retryPayload(payload)
		case <-ticker.C:
			// Periodic retry of stuck items
			c.processRetryQueue()
		}
	}
}

// retryPayload attempts to resend a failed payload
func (c *Client) retryPayload(payload Payload) {
	var err error
	
	for attempt := 1; attempt <= c.config.Server.RetryMax; attempt++ {
		if err = c.sendBatch([]Payload{payload}); err == nil {
			c.metrics.TotalSent++
			c.metrics.LastSent = time.Now()
			return
		}

		// Wait before retry (exponential backoff)
		waitTime := time.Duration(attempt*attempt) * time.Second
		time.Sleep(waitTime)
	}

	// All retries failed
	c.metrics.TotalFailed++
	c.metrics.LastError = fmt.Sprintf("retry failed after %d attempts: %v", c.config.Server.RetryMax, err)
}

// processRetryQueue processes items in retry queue
func (c *Client) processRetryQueue() {
	for {
		select {
		case payload := <-c.retryQueue:
			go c.retryPayload(payload)
		default:
			return
		}
	}
}

// flushQueue sends all remaining items in queue
func (c *Client) flushQueue() {
	c.queueMutex.Lock()
	remaining := make([]Payload, len(c.queue))
	copy(remaining, c.queue)
	c.queue = c.queue[:0]
	c.metrics.QueueSize = 0
	c.queueMutex.Unlock()

	if len(remaining) > 0 {
		if err := c.sendBatch(remaining); err != nil {
			c.metrics.TotalFailed += int64(len(remaining))
			c.metrics.LastError = fmt.Sprintf("flush failed: %v", err)
		} else {
			c.metrics.TotalSent += int64(len(remaining))
			c.metrics.LastSent = time.Now()
		}
	}
}

// GetMetrics returns client performance metrics
func (c *Client) GetMetrics() ClientMetrics {
	c.queueMutex.RLock()
	defer c.queueMutex.RUnlock()
	
	metrics := c.metrics
	metrics.QueueSize = len(c.queue)
	return metrics
}

// HealthCheck performs a health check against the server
func (c *Client) HealthCheck() error {
	healthData := map[string]interface{}{
		"agent_id":  c.config.Agent.ID,
		"timestamp": time.Now(),
		"status":    "healthy",
		"metrics":   c.GetMetrics(),
	}

	jsonData, err := json.Marshal(healthData)
	if err != nil {
		return fmt.Errorf("failed to marshal health check: %w", err)
	}

	req, err := http.NewRequest("POST", c.config.Server.URL+"/api/v1/agent/health", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.Server.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Server.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Close gracefully shuts down the client
func (c *Client) Close() error {
	// Flush remaining items
	c.flushQueue()
	
	// Close HTTP client
	c.httpClient.CloseIdleConnections()
	
	return nil
} 