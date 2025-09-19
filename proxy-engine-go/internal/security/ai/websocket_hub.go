package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

// ThreatMonitoringHub manages WebSocket connections for real-time threat monitoring
type ThreatMonitoringHub struct {
	clients         map[*Client]bool
	broadcast       chan *ThreatEvent
	register        chan *Client
	unregister      chan *Client
	threatDetector  AIThreatDetector
	eventBuffer     []*ThreatEvent
	config          *HubConfig
	stats           *HubStats
	logger          *logrus.Logger
	mu              sync.RWMutex
}

// Client represents a WebSocket client connection
type Client struct {
	hub        *ThreatMonitoringHub
	conn       *websocket.Conn
	send       chan *ThreatEvent
	id         string
	userID     string
	filters    *EventFilters
	lastSeen   time.Time
	connected  time.Time
	metadata   map[string]interface{}
}

// HubConfig holds configuration for the threat monitoring hub
type HubConfig struct {
	MaxClients          int           `json:"max_clients"`
	EventBufferSize     int           `json:"event_buffer_size"`
	ClientBufferSize    int           `json:"client_buffer_size"`
	PingInterval        time.Duration `json:"ping_interval"`
	PongTimeout         time.Duration `json:"pong_timeout"`
	WriteTimeout        time.Duration `json:"write_timeout"`
	ReadTimeout         time.Duration `json:"read_timeout"`
	MaxMessageSize      int64         `json:"max_message_size"`
	EnableCompression   bool          `json:"enable_compression"`
	EnableEventHistory  bool          `json:"enable_event_history"`
	EventHistorySize    int           `json:"event_history_size"`
	RateLimitPerSecond  int           `json:"rate_limit_per_second"`
}

// HubStats tracks hub statistics
type HubStats struct {
	TotalConnections    int64                    `json:"total_connections"`
	ActiveConnections   int                      `json:"active_connections"`
	EventsSent          int64                    `json:"events_sent"`
	EventsFiltered      int64                    `json:"events_filtered"`
	MessagesSent        int64                    `json:"messages_sent"`
	MessagesReceived    int64                    `json:"messages_received"`
	ConnectionErrors    int64                    `json:"connection_errors"`
	EventsByType        map[ThreatEventType]int64 `json:"events_by_type"`
	ClientsByUserID     map[string]int           `json:"clients_by_user_id"`
	LastUpdated         time.Time                `json:"last_updated"`
}

// ThreatEvent represents a real-time threat event
type ThreatEvent struct {
	ID          string                 `json:"id"`
	Type        ThreatEventType        `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    ThreatLevel            `json:"severity"`
	Source      string                 `json:"source"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	Tags        []string               `json:"tags,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	IP          string                 `json:"ip,omitempty"`
	URL         string                 `json:"url,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
}

// ThreatEventType defines types of threat events
type ThreatEventType string

const (
	EventTypeThreatDetected     ThreatEventType = "threat_detected"
	EventTypeAnomalyDetected    ThreatEventType = "anomaly_detected"
	EventTypeRateLimitExceeded  ThreatEventType = "rate_limit_exceeded"
	EventTypeModelUpdated       ThreatEventType = "model_updated"
	EventTypeFeedbackReceived   ThreatEventType = "feedback_received"
	EventTypeEmergencyActivated ThreatEventType = "emergency_activated"
	EventTypeSystemAlert        ThreatEventType = "system_alert"
	EventTypeHealthCheck        ThreatEventType = "health_check"
)

// EventFilters defines filters for event subscriptions
type EventFilters struct {
	EventTypes     []ThreatEventType `json:"event_types,omitempty"`
	SeverityLevels []ThreatLevel     `json:"severity_levels,omitempty"`
	Sources        []string          `json:"sources,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	UserIDs        []string          `json:"user_ids,omitempty"`
	IPAddresses    []string          `json:"ip_addresses,omitempty"`
	MinSeverity    ThreatLevel       `json:"min_severity,omitempty"`
	MaxEvents      int               `json:"max_events,omitempty"`
}

// WebSocket message types
type MessageType string

const (
	MessageTypeSubscribe   MessageType = "subscribe"
	MessageTypeUnsubscribe MessageType = "unsubscribe"
	MessageTypeEvent       MessageType = "event"
	MessageTypePing        MessageType = "ping"
	MessageTypePong        MessageType = "pong"
	MessageTypeError       MessageType = "error"
	MessageTypeStatus      MessageType = "status"
)

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type      MessageType            `json:"type"`
	Data      interface{}            `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	ID        string                 `json:"id,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// SubscriptionRequest represents a subscription request
type SubscriptionRequest struct {
	Filters  *EventFilters `json:"filters,omitempty"`
	History  bool          `json:"history,omitempty"`
	UserID   string        `json:"user_id,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
}

// NewThreatMonitoringHub creates a new threat monitoring hub
func NewThreatMonitoringHub(threatDetector AIThreatDetector, logger *logrus.Logger) *ThreatMonitoringHub {
	hub := &ThreatMonitoringHub{
		clients:        make(map[*Client]bool),
		broadcast:      make(chan *ThreatEvent, 256),
		register:       make(chan *Client),
		unregister:     make(chan *Client),
		threatDetector: threatDetector,
		eventBuffer:    make([]*ThreatEvent, 0),
		config:         getDefaultHubConfig(),
		stats:          getDefaultHubStats(),
		logger:         logger,
	}
	
	return hub
}

// Run starts the hub's main loop
func (h *ThreatMonitoringHub) Run(ctx context.Context) {
	ticker := time.NewTicker(h.config.PingInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			h.logger.Info("Threat monitoring hub shutting down")
			return
			
		case client := <-h.register:
			h.registerClient(client)
			
		case client := <-h.unregister:
			h.unregisterClient(client)
			
		case event := <-h.broadcast:
			h.broadcastEvent(event)
			
		case <-ticker.C:
			h.pingClients()
		}
	}
}

// HandleWebSocket handles WebSocket connections
func (h *ThreatMonitoringHub) HandleWebSocket(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Errorf("WebSocket upgrade failed: %v", err)
		h.mu.Lock()
		h.stats.ConnectionErrors++
		h.mu.Unlock()
		return
	}
	
	client := &Client{
		hub:       h,
		conn:      conn,
		send:      make(chan *ThreatEvent, h.config.ClientBufferSize),
		id:        generateClientID(),
		userID:    c.Query("user_id"),
		filters:   &EventFilters{},
		lastSeen:  time.Now(),
		connected: time.Now(),
		metadata:  make(map[string]interface{}),
	}
	
	// Configure WebSocket connection
	conn.SetReadLimit(h.config.MaxMessageSize)
	conn.SetReadDeadline(time.Now().Add(h.config.ReadTimeout))
	conn.SetPongHandler(func(string) error {
		client.lastSeen = time.Now()
		conn.SetReadDeadline(time.Now().Add(h.config.ReadTimeout))
		return nil
	})
	
	h.register <- client
	
	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

// BroadcastThreatEvent broadcasts a threat event to all subscribed clients
func (h *ThreatMonitoringHub) BroadcastThreatEvent(event *ThreatEvent) {
	select {
	case h.broadcast <- event:
		// Event queued for broadcast
	default:
		h.logger.Warn("Broadcast channel full, dropping event")
	}
}

// CreateThreatEvent creates a threat event from analysis result
func (h *ThreatMonitoringHub) CreateThreatEvent(result *ThreatAnalysisResult) *ThreatEvent {
	event := &ThreatEvent{
		ID:          generateEventID(),
		Type:        EventTypeThreatDetected,
		Timestamp:   result.Timestamp,
		Severity:    result.ThreatLevel,
		Source:      "ai_threat_detector",
		RequestID:   result.RequestID,
		Data: map[string]interface{}{
			"is_threat":    result.IsThreat,
			"threat_type":  result.ThreatType,
			"confidence":   result.Confidence,
			"reasons":      result.Reasons,
			"ml_predictions": result.MLPredictions,
		},
	}
	
	if result.IsThreat {
		event.Title = fmt.Sprintf("Threat Detected: %s", result.ThreatType)
		event.Description = fmt.Sprintf("Threat level %s with confidence %.2f", result.ThreatLevel, result.Confidence)
		event.Tags = []string{"threat", string(result.ThreatType), string(result.ThreatLevel)}
	} else {
		event.Title = "Request Analyzed"
		event.Description = "No threat detected"
		event.Tags = []string{"analysis", "safe"}
		event.Severity = ThreatLevelNone
	}
	
	return event
}

// CreateAnomalyEvent creates an anomaly event from behavioral analysis
func (h *ThreatMonitoringHub) CreateAnomalyEvent(subject string, analysis *BehaviorAnalysis) *ThreatEvent {
	event := &ThreatEvent{
		ID:        generateEventID(),
		Type:      EventTypeAnomalyDetected,
		Timestamp: time.Now(),
		Severity:  h.calculateAnomalySeverity(analysis.AnomalyScore),
		Source:    "behavioral_analyzer",
		Title:     "Behavioral Anomaly Detected",
		Description: fmt.Sprintf("Anomalous behavior detected for %s (score: %.2f)", subject, analysis.AnomalyScore),
		Tags:      []string{"anomaly", "behavior"},
		Data: map[string]interface{}{
			"subject":        subject,
			"anomaly_score":  analysis.AnomalyScore,
			"anomaly_reasons": analysis.AnomalyReasons,
			"profile_data":   analysis.ProfileData,
		},
	}
	
	return event
}

// CreateRateLimitEvent creates a rate limit event
func (h *ThreatMonitoringHub) CreateRateLimitEvent(userID, ip string, reason string) *ThreatEvent {
	event := &ThreatEvent{
		ID:          generateEventID(),
		Type:        EventTypeRateLimitExceeded,
		Timestamp:   time.Now(),
		Severity:    ThreatLevelMedium,
		Source:      "rate_limiter",
		Title:       "Rate Limit Exceeded",
		Description: fmt.Sprintf("Rate limit exceeded: %s", reason),
		Tags:        []string{"rate_limit", "blocked"},
		UserID:      userID,
		IP:          ip,
		Data: map[string]interface{}{
			"reason": reason,
		},
	}
	
	return event
}

// CreateSystemEvent creates a system event
func (h *ThreatMonitoringHub) CreateSystemEvent(eventType ThreatEventType, title, description string, data map[string]interface{}) *ThreatEvent {
	event := &ThreatEvent{
		ID:          generateEventID(),
		Type:        eventType,
		Timestamp:   time.Now(),
		Severity:    ThreatLevelLow,
		Source:      "system",
		Title:       title,
		Description: description,
		Tags:        []string{"system"},
		Data:        data,
	}
	
	return event
}

// Client methods

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	
	for {
		var msg WebSocketMessage
		err := c.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.hub.logger.Errorf("WebSocket error: %v", err)
			}
			break
		}
		
		c.hub.mu.Lock()
		c.hub.stats.MessagesReceived++
		c.hub.mu.Unlock()
		
		c.handleMessage(&msg)
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(c.hub.config.PingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	
	for {
		select {
		case event, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(c.hub.config.WriteTimeout))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			
			if c.shouldSendEvent(event) {
				msg := &WebSocketMessage{
					Type:      MessageTypeEvent,
					Data:      event,
					Timestamp: time.Now(),
					ID:        event.ID,
				}
				
				if err := c.conn.WriteJSON(msg); err != nil {
					c.hub.logger.Errorf("WebSocket write error: %v", err)
					return
				}
				
				c.hub.mu.Lock()
				c.hub.stats.MessagesSent++
				c.hub.stats.EventsSent++
				c.hub.stats.EventsByType[event.Type]++
				c.hub.mu.Unlock()
			} else {
				c.hub.mu.Lock()
				c.hub.stats.EventsFiltered++
				c.hub.mu.Unlock()
			}
			
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(c.hub.config.WriteTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) handleMessage(msg *WebSocketMessage) {
	switch msg.Type {
	case MessageTypeSubscribe:
		c.handleSubscription(msg)
	case MessageTypeUnsubscribe:
		c.handleUnsubscription(msg)
	case MessageTypePong:
		c.lastSeen = time.Now()
	default:
		c.sendError("Unknown message type")
	}
}

func (c *Client) handleSubscription(msg *WebSocketMessage) {
	var req SubscriptionRequest
	if data, ok := msg.Data.(map[string]interface{}); ok {
		jsonData, _ := json.Marshal(data)
		json.Unmarshal(jsonData, &req)
	}
	
	// Update client filters
	if req.Filters != nil {
		c.filters = req.Filters
	}
	
	// Update client metadata
	if req.UserID != "" {
		c.userID = req.UserID
	}
	if req.Metadata != nil {
		for k, v := range req.Metadata {
			c.metadata[k] = v
		}
	}
	
	// Send historical events if requested
	if req.History && c.hub.config.EnableEventHistory {
		c.sendHistoricalEvents()
	}
	
	c.sendStatus("Subscription updated successfully")
}

func (c *Client) handleUnsubscription(msg *WebSocketMessage) {
	// Reset filters to default (no filtering)
	c.filters = &EventFilters{}
	c.sendStatus("Unsubscribed from all events")
}

func (c *Client) shouldSendEvent(event *ThreatEvent) bool {
	if c.filters == nil {
		return true
	}
	
	// Check event types
	if len(c.filters.EventTypes) > 0 {
		found := false
		for _, eventType := range c.filters.EventTypes {
			if event.Type == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check severity levels
	if len(c.filters.SeverityLevels) > 0 {
		found := false
		for _, severity := range c.filters.SeverityLevels {
			if event.Severity == severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check minimum severity
	if c.filters.MinSeverity != "" {
		if !c.meetsSeverityThreshold(event.Severity, c.filters.MinSeverity) {
			return false
		}
	}
	
	// Check sources
	if len(c.filters.Sources) > 0 {
		found := false
		for _, source := range c.filters.Sources {
			if event.Source == source {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check user IDs
	if len(c.filters.UserIDs) > 0 && event.UserID != "" {
		found := false
		for _, userID := range c.filters.UserIDs {
			if event.UserID == userID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check IP addresses
	if len(c.filters.IPAddresses) > 0 && event.IP != "" {
		found := false
		for _, ip := range c.filters.IPAddresses {
			if event.IP == ip {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check tags
	if len(c.filters.Tags) > 0 {
		found := false
		for _, filterTag := range c.filters.Tags {
			for _, eventTag := range event.Tags {
				if eventTag == filterTag {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}
	
	return true
}

func (c *Client) meetsSeverityThreshold(eventSeverity, minSeverity ThreatLevel) bool {
	severityOrder := map[ThreatLevel]int{
		ThreatLevelNone:     0,
		ThreatLevelLow:      1,
		ThreatLevelMedium:   2,
		ThreatLevelHigh:     3,
		ThreatLevelCritical: 4,
	}
	
	return severityOrder[eventSeverity] >= severityOrder[minSeverity]
}

func (c *Client) sendHistoricalEvents() {
	c.hub.mu.RLock()
	events := make([]*ThreatEvent, len(c.hub.eventBuffer))
	copy(events, c.hub.eventBuffer)
	c.hub.mu.RUnlock()
	
	for _, event := range events {
		if c.shouldSendEvent(event) {
			select {
			case c.send <- event:
			default:
				// Client buffer full, skip historical event
			}
		}
	}
}

func (c *Client) sendError(message string) {
	msg := &WebSocketMessage{
		Type:      MessageTypeError,
		Error:     message,
		Timestamp: time.Now(),
	}
	
	select {
	case <-time.After(c.hub.config.WriteTimeout):
		// Timeout
	default:
		c.conn.WriteJSON(msg)
	}
}

func (c *Client) sendStatus(message string) {
	msg := &WebSocketMessage{
		Type:      MessageTypeStatus,
		Data:      map[string]string{"message": message},
		Timestamp: time.Now(),
	}
	
	select {
	case <-time.After(c.hub.config.WriteTimeout):
		// Timeout
	default:
		c.conn.WriteJSON(msg)
	}
}

// Hub methods

func (h *ThreatMonitoringHub) registerClient(client *Client) {
	if len(h.clients) >= h.config.MaxClients {
		client.sendError("Maximum number of clients reached")
		client.conn.Close()
		return
	}
	
	h.mu.Lock()
	h.clients[client] = true
	h.stats.TotalConnections++
	h.stats.ActiveConnections = len(h.clients)
	if client.userID != "" {
		h.stats.ClientsByUserID[client.userID]++
	}
	h.mu.Unlock()
	
	h.logger.Infof("Client connected: %s (user: %s)", client.id, client.userID)
	
	// Send welcome message
	client.sendStatus("Connected to threat monitoring hub")
}

func (h *ThreatMonitoringHub) unregisterClient(client *Client) {
	h.mu.Lock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		close(client.send)
		h.stats.ActiveConnections = len(h.clients)
		if client.userID != "" {
			h.stats.ClientsByUserID[client.userID]--
			if h.stats.ClientsByUserID[client.userID] <= 0 {
				delete(h.stats.ClientsByUserID, client.userID)
			}
		}
	}
	h.mu.Unlock()
	
	h.logger.Infof("Client disconnected: %s (user: %s)", client.id, client.userID)
}

func (h *ThreatMonitoringHub) broadcastEvent(event *ThreatEvent) {
	// Add to event buffer if history is enabled
	if h.config.EnableEventHistory {
		h.mu.Lock()
		h.eventBuffer = append(h.eventBuffer, event)
		if len(h.eventBuffer) > h.config.EventHistorySize {
			h.eventBuffer = h.eventBuffer[1:]
		}
		h.mu.Unlock()
	}
	
	// Broadcast to all clients
	for client := range h.clients {
		select {
		case client.send <- event:
		default:
			// Client buffer full, close connection
			h.unregisterClient(client)
		}
	}
}

func (h *ThreatMonitoringHub) pingClients() {
	now := time.Now()
	for client := range h.clients {
		if now.Sub(client.lastSeen) > h.config.PongTimeout {
			h.unregisterClient(client)
		}
	}
}

func (h *ThreatMonitoringHub) calculateAnomalySeverity(score float64) ThreatLevel {
	if score >= 0.9 {
		return ThreatLevelCritical
	} else if score >= 0.7 {
		return ThreatLevelHigh
	} else if score >= 0.5 {
		return ThreatLevelMedium
	} else if score >= 0.3 {
		return ThreatLevelLow
	}
	return ThreatLevelNone
}

// Configuration and statistics methods

func (h *ThreatMonitoringHub) GetStats() *HubStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	statsCopy := *h.stats
	statsCopy.EventsByType = make(map[ThreatEventType]int64)
	statsCopy.ClientsByUserID = make(map[string]int)
	
	for k, v := range h.stats.EventsByType {
		statsCopy.EventsByType[k] = v
	}
	for k, v := range h.stats.ClientsByUserID {
		statsCopy.ClientsByUserID[k] = v
	}
	
	statsCopy.LastUpdated = time.Now()
	return &statsCopy
}

func (h *ThreatMonitoringHub) GetConfig() *HubConfig {
	configCopy := *h.config
	return &configCopy
}

func (h *ThreatMonitoringHub) SetConfig(config *HubConfig) {
	h.config = config
	h.logger.Info("Updated threat monitoring hub configuration")
}

// Helper functions

func generateClientID() string {
	return fmt.Sprintf("client-%d", time.Now().UnixNano())
}

func generateEventID() string {
	return fmt.Sprintf("event-%d", time.Now().UnixNano())
}

// Default configurations

func getDefaultHubConfig() *HubConfig {
	return &HubConfig{
		MaxClients:         1000,
		EventBufferSize:    256,
		ClientBufferSize:   256,
		PingInterval:       54 * time.Second,
		PongTimeout:        60 * time.Second,
		WriteTimeout:       10 * time.Second,
		ReadTimeout:        60 * time.Second,
		MaxMessageSize:     512,
		EnableCompression:  true,
		EnableEventHistory: true,
		EventHistorySize:   1000,
		RateLimitPerSecond: 100,
	}
}

func getDefaultHubStats() *HubStats {
	return &HubStats{
		EventsByType:    make(map[ThreatEventType]int64),
		ClientsByUserID: make(map[string]int),
		LastUpdated:     time.Now(),
	}
}