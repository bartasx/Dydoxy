package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestHub() (*ThreatMonitoringHub, *gin.Engine) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	threatDetector := &MockAIThreatDetector{}
	hub := NewThreatMonitoringHub(threatDetector, logger)
	
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ws", hub.HandleWebSocket)
	
	return hub, router
}

func TestThreatMonitoringHub_Creation(t *testing.T) {
	logger := logrus.New()
	threatDetector := &MockAIThreatDetector{}
	
	hub := NewThreatMonitoringHub(threatDetector, logger)
	
	assert.NotNil(t, hub)
	assert.NotNil(t, hub.clients)
	assert.NotNil(t, hub.broadcast)
	assert.NotNil(t, hub.register)
	assert.NotNil(t, hub.unregister)
	assert.NotNil(t, hub.config)
	assert.NotNil(t, hub.stats)
	assert.Equal(t, 0, len(hub.clients))
}

func TestThreatMonitoringHub_WebSocketConnection(t *testing.T) {
	hub, router := setupTestHub()
	
	// Start hub in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	
	// Create test server
	server := httptest.NewServer(router)
	defer server.Close()
	
	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	
	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()
	
	// Wait for connection to be registered
	time.Sleep(100 * time.Millisecond)
	
	// Check that client was registered
	stats := hub.GetStats()
	assert.Equal(t, 1, stats.ActiveConnections)
	assert.Equal(t, int64(1), stats.TotalConnections)
}

func TestThreatMonitoringHub_EventBroadcast(t *testing.T) {
	hub, router := setupTestHub()
	
	// Start hub in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	
	// Create test server
	server := httptest.NewServer(router)
	defer server.Close()
	
	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	
	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()
	
	// Wait for connection to be registered
	time.Sleep(100 * time.Millisecond)
	
	// Create and broadcast a threat event
	event := &ThreatEvent{
		ID:          "test-event-1",
		Type:        EventTypeThreatDetected,
		Timestamp:   time.Now(),
		Severity:    ThreatLevelHigh,
		Source:      "test",
		Title:       "Test Threat",
		Description: "Test threat description",
		Tags:        []string{"test", "threat"},
	}
	
	hub.BroadcastThreatEvent(event)
	
	// Read message from WebSocket
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var msg WebSocketMessage
	err = conn.ReadJSON(&msg)
	require.NoError(t, err)
	
	assert.Equal(t, MessageTypeEvent, msg.Type)
	assert.NotNil(t, msg.Data)
	
	// Verify event data
	eventData, ok := msg.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "test-event-1", eventData["id"])
	assert.Equal(t, string(EventTypeThreatDetected), eventData["type"])
	assert.Equal(t, string(ThreatLevelHigh), eventData["severity"])
}

func TestThreatMonitoringHub_EventFiltering(t *testing.T) {
	hub, router := setupTestHub()
	
	// Start hub in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	
	// Create test server
	server := httptest.NewServer(router)
	defer server.Close()
	
	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	
	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()
	
	// Wait for connection to be registered
	time.Sleep(100 * time.Millisecond)
	
	// Send subscription message with filters
	subscriptionReq := SubscriptionRequest{
		Filters: &EventFilters{
			EventTypes:     []ThreatEventType{EventTypeThreatDetected},
			SeverityLevels: []ThreatLevel{ThreatLevelHigh, ThreatLevelCritical},
		},
	}
	
	subscribeMsg := WebSocketMessage{
		Type:      MessageTypeSubscribe,
		Data:      subscriptionReq,
		Timestamp: time.Now(),
	}
	
	err = conn.WriteJSON(subscribeMsg)
	require.NoError(t, err)
	
	// Wait for subscription to be processed
	time.Sleep(100 * time.Millisecond)
	
	// Broadcast events with different severities
	events := []*ThreatEvent{
		{
			ID:       "event-1",
			Type:     EventTypeThreatDetected,
			Severity: ThreatLevelLow, // Should be filtered out
			Source:   "test",
		},
		{
			ID:       "event-2",
			Type:     EventTypeThreatDetected,
			Severity: ThreatLevelHigh, // Should pass filter
			Source:   "test",
		},
		{
			ID:       "event-3",
			Type:     EventTypeAnomalyDetected, // Should be filtered out
			Severity: ThreatLevelHigh,
			Source:   "test",
		},
	}
	
	for _, event := range events {
		hub.BroadcastThreatEvent(event)
	}
	
	// Read messages from WebSocket
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	
	receivedEvents := 0
	for {
		var msg WebSocketMessage
		err = conn.ReadJSON(&msg)
		if err != nil {
			break // Timeout or connection closed
		}
		
		if msg.Type == MessageTypeEvent {
			receivedEvents++
			eventData := msg.Data.(map[string]interface{})
			// Should only receive event-2
			assert.Equal(t, "event-2", eventData["id"])
		}
	}
	
	// Should have received only 1 event (event-2)
	assert.Equal(t, 1, receivedEvents)
}

func TestThreatMonitoringHub_CreateThreatEvent(t *testing.T) {
	hub, _ := setupTestHub()
	
	result := &ThreatAnalysisResult{
		RequestID:   "test-req-123",
		IsThreat:    true,
		ThreatType:  ThreatTypeMalware,
		ThreatLevel: ThreatLevelHigh,
		Confidence:  0.9,
		Reasons:     []string{"Malicious payload detected"},
		Timestamp:   time.Now(),
	}
	
	event := hub.CreateThreatEvent(result)
	
	assert.NotEmpty(t, event.ID)
	assert.Equal(t, EventTypeThreatDetected, event.Type)
	assert.Equal(t, ThreatLevelHigh, event.Severity)
	assert.Equal(t, "ai_threat_detector", event.Source)
	assert.Equal(t, "test-req-123", event.RequestID)
	assert.Contains(t, event.Title, "Threat Detected")
	assert.Contains(t, event.Tags, "threat")
	assert.Contains(t, event.Tags, string(ThreatTypeMalware))
	
	// Check data
	assert.Equal(t, true, event.Data["is_threat"])
	assert.Equal(t, ThreatTypeMalware, event.Data["threat_type"])
	assert.Equal(t, 0.9, event.Data["confidence"])
}

func TestThreatMonitoringHub_CreateAnomalyEvent(t *testing.T) {
	hub, _ := setupTestHub()
	
	analysis := &BehaviorAnalysis{
		Subject:         "user:123",
		IsAnomalous:     true,
		AnomalyScore:    0.8,
		AnomalyReasons:  []string{"Unusual request frequency"},
		ProfileData:     map[string]interface{}{"avg_requests": 10.5},
		Timestamp:       time.Now(),
	}
	
	event := hub.CreateAnomalyEvent("user:123", analysis)
	
	assert.NotEmpty(t, event.ID)
	assert.Equal(t, EventTypeAnomalyDetected, event.Type)
	assert.Equal(t, ThreatLevelHigh, event.Severity) // 0.8 score should be high
	assert.Equal(t, "behavioral_analyzer", event.Source)
	assert.Contains(t, event.Title, "Behavioral Anomaly")
	assert.Contains(t, event.Tags, "anomaly")
	assert.Contains(t, event.Tags, "behavior")
	
	// Check data
	assert.Equal(t, "user:123", event.Data["subject"])
	assert.Equal(t, 0.8, event.Data["anomaly_score"])
	assert.Contains(t, event.Data["anomaly_reasons"], "Unusual request frequency")
}

func TestThreatMonitoringHub_CreateRateLimitEvent(t *testing.T) {
	hub, _ := setupTestHub()
	
	event := hub.CreateRateLimitEvent("user123", "192.168.1.1", "Too many requests")
	
	assert.NotEmpty(t, event.ID)
	assert.Equal(t, EventTypeRateLimitExceeded, event.Type)
	assert.Equal(t, ThreatLevelMedium, event.Severity)
	assert.Equal(t, "rate_limiter", event.Source)
	assert.Equal(t, "user123", event.UserID)
	assert.Equal(t, "192.168.1.1", event.IP)
	assert.Contains(t, event.Title, "Rate Limit Exceeded")
	assert.Contains(t, event.Tags, "rate_limit")
	assert.Equal(t, "Too many requests", event.Data["reason"])
}

func TestThreatMonitoringHub_EventHistory(t *testing.T) {
	hub, router := setupTestHub()
	
	// Enable event history
	config := hub.GetConfig()
	config.EnableEventHistory = true
	config.EventHistorySize = 5
	hub.SetConfig(config)
	
	// Start hub in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	
	// Broadcast some events before connecting
	for i := 0; i < 3; i++ {
		event := &ThreatEvent{
			ID:        fmt.Sprintf("historical-event-%d", i),
			Type:      EventTypeThreatDetected,
			Timestamp: time.Now(),
			Severity:  ThreatLevelLow,
			Source:    "test",
			Title:     fmt.Sprintf("Historical Event %d", i),
		}
		hub.BroadcastThreatEvent(event)
	}
	
	// Wait for events to be processed
	time.Sleep(100 * time.Millisecond)
	
	// Create test server
	server := httptest.NewServer(router)
	defer server.Close()
	
	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	
	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()
	
	// Wait for connection to be registered
	time.Sleep(100 * time.Millisecond)
	
	// Send subscription message requesting history
	subscriptionReq := SubscriptionRequest{
		History: true,
	}
	
	subscribeMsg := WebSocketMessage{
		Type:      MessageTypeSubscribe,
		Data:      subscriptionReq,
		Timestamp: time.Now(),
	}
	
	err = conn.WriteJSON(subscribeMsg)
	require.NoError(t, err)
	
	// Read historical events
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	
	historicalEvents := 0
	for {
		var msg WebSocketMessage
		err = conn.ReadJSON(&msg)
		if err != nil {
			break // Timeout
		}
		
		if msg.Type == MessageTypeEvent {
			eventData := msg.Data.(map[string]interface{})
			if strings.Contains(eventData["id"].(string), "historical-event") {
				historicalEvents++
			}
		}
	}
	
	// Should have received all 3 historical events
	assert.Equal(t, 3, historicalEvents)
}

func TestThreatMonitoringHub_ClientFilters(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	hub := NewThreatMonitoringHub(&MockAIThreatDetector{}, logger)
	
	client := &Client{
		hub: hub,
		filters: &EventFilters{
			EventTypes:     []ThreatEventType{EventTypeThreatDetected},
			SeverityLevels: []ThreatLevel{ThreatLevelHigh},
			Sources:        []string{"ai_threat_detector"},
			Tags:           []string{"malware"},
			MinSeverity:    ThreatLevelMedium,
		},
	}
	
	tests := []struct {
		name     string
		event    *ThreatEvent
		expected bool
	}{
		{
			name: "matching event",
			event: &ThreatEvent{
				Type:     EventTypeThreatDetected,
				Severity: ThreatLevelHigh,
				Source:   "ai_threat_detector",
				Tags:     []string{"malware", "threat"},
			},
			expected: true,
		},
		{
			name: "wrong event type",
			event: &ThreatEvent{
				Type:     EventTypeAnomalyDetected,
				Severity: ThreatLevelHigh,
				Source:   "ai_threat_detector",
				Tags:     []string{"malware"},
			},
			expected: false,
		},
		{
			name: "wrong severity",
			event: &ThreatEvent{
				Type:     EventTypeThreatDetected,
				Severity: ThreatLevelLow,
				Source:   "ai_threat_detector",
				Tags:     []string{"malware"},
			},
			expected: false,
		},
		{
			name: "below minimum severity",
			event: &ThreatEvent{
				Type:     EventTypeThreatDetected,
				Severity: ThreatLevelLow, // Below ThreatLevelMedium
				Source:   "ai_threat_detector",
				Tags:     []string{"malware"},
			},
			expected: false,
		},
		{
			name: "wrong source",
			event: &ThreatEvent{
				Type:     EventTypeThreatDetected,
				Severity: ThreatLevelHigh,
				Source:   "other_source",
				Tags:     []string{"malware"},
			},
			expected: false,
		},
		{
			name: "missing tag",
			event: &ThreatEvent{
				Type:     EventTypeThreatDetected,
				Severity: ThreatLevelHigh,
				Source:   "ai_threat_detector",
				Tags:     []string{"phishing"}, // No "malware" tag
			},
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.shouldSendEvent(tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestThreatMonitoringHub_Statistics(t *testing.T) {
	hub, _ := setupTestHub()
	
	// Initial stats
	stats := hub.GetStats()
	assert.Equal(t, 0, stats.ActiveConnections)
	assert.Equal(t, int64(0), stats.TotalConnections)
	assert.Equal(t, int64(0), stats.EventsSent)
	
	// Simulate client registration
	client := &Client{
		id:     "test-client",
		userID: "user123",
	}
	
	hub.registerClient(client)
	
	stats = hub.GetStats()
	assert.Equal(t, 1, stats.ActiveConnections)
	assert.Equal(t, int64(1), stats.TotalConnections)
	assert.Equal(t, 1, stats.ClientsByUserID["user123"])
	
	// Simulate client unregistration
	hub.unregisterClient(client)
	
	stats = hub.GetStats()
	assert.Equal(t, 0, stats.ActiveConnections)
	assert.Equal(t, int64(1), stats.TotalConnections) // Total doesn't decrease
	assert.Equal(t, 0, len(stats.ClientsByUserID))
}

func TestThreatMonitoringHub_Configuration(t *testing.T) {
	hub, _ := setupTestHub()
	
	// Test default configuration
	config := hub.GetConfig()
	assert.Equal(t, 1000, config.MaxClients)
	assert.Equal(t, 256, config.EventBufferSize)
	assert.True(t, config.EnableEventHistory)
	
	// Test configuration update
	newConfig := &HubConfig{
		MaxClients:         500,
		EventBufferSize:    128,
		ClientBufferSize:   64,
		EnableEventHistory: false,
		EventHistorySize:   100,
	}
	
	hub.SetConfig(newConfig)
	updatedConfig := hub.GetConfig()
	
	assert.Equal(t, 500, updatedConfig.MaxClients)
	assert.Equal(t, 128, updatedConfig.EventBufferSize)
	assert.Equal(t, 64, updatedConfig.ClientBufferSize)
	assert.False(t, updatedConfig.EnableEventHistory)
	assert.Equal(t, 100, updatedConfig.EventHistorySize)
}

func TestThreatMonitoringHub_SeverityCalculation(t *testing.T) {
	hub, _ := setupTestHub()
	
	tests := []struct {
		score    float64
		expected ThreatLevel
	}{
		{0.95, ThreatLevelCritical},
		{0.8, ThreatLevelHigh},
		{0.6, ThreatLevelMedium},
		{0.4, ThreatLevelLow},
		{0.2, ThreatLevelNone},
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("score_%.2f", tt.score), func(t *testing.T) {
			severity := hub.calculateAnomalySeverity(tt.score)
			assert.Equal(t, tt.expected, severity)
		})
	}
}