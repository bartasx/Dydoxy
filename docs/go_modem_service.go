package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/gorilla/websocket"
    "github.com/knq/hilink"
    "github.com/robfig/cron/v3"
)

// ModemManager handles all modem operations
type ModemManager struct {
    modems     map[string]*ManagedModem
    clients    map[*websocket.Conn]bool
    broadcast  chan ModemUpdate
    upgrader   websocket.Upgrader
    scheduler  *cron.Cron
    mu         sync.RWMutex
}

type ManagedModem struct {
    ID              string            `json:"id"`
    Name            string            `json:"name"`
    Model           string            `json:"model"`
    IPAddress       string            `json:"ipAddress"`
    IsOnline        bool              `json:"isOnline"`
    LastSeen        time.Time         `json:"lastSeen"`
    Client          *hilink.Client    `json:"-"`
    Config          ModemConfig       `json:"config"`
    Stats           ModemStats        `json:"stats"`
    NetworkInfo     NetworkInfo       `json:"networkInfo"`
    DeviceInfo      DeviceInfo        `json:"deviceInfo"`
    TrafficHistory  []TrafficPoint    `json:"trafficHistory"`
    RotationTicker  *time.Ticker      `json:"-"`
    mu              sync.RWMutex      `json:"-"`
}

type ModemConfig struct {
    AutoRotateIP     bool          `json:"autoRotateIP"`
    RotationInterval time.Duration `json:"rotationInterval"`
    MonthlyLimitGB   int64         `json:"monthlyLimitGB"`
    AlertThresholds  Thresholds    `json:"alertThresholds"`
}

type ModemStats struct {
    SignalStrength      int    `json:"signalStrength"`
    CurrentIP          string `json:"currentIP"`
    MonthlyUsed        int64  `json:"monthlyUsed"`
    MonthlyLimit       int64  `json:"monthlyLimit"`
    ActiveConnections  int    `json:"activeConnections"`
    UptimeSeconds      int64  `json:"uptimeSeconds"`
    CurrentSpeedDown   int64  `json:"currentSpeedDown"`
    CurrentSpeedUp     int64  `json:"currentSpeedUp"`
    Temperature        int    `json:"temperature"`
    BatteryLevel       int    `json:"batteryLevel"`
}

type NetworkInfo struct {
    NetworkType string `json:"networkType"`
    Operator    string `json:"operator"`
    CellID      string `json:"cellId"`
    LAC         string `json:"lac"`
    Band        string `json:"band"`
    RSRP        int    `json:"rsrp"`
    RSRQ        int    `json:"rsrq"`
    SINR        int    `json:"sinr"`
}

type DeviceInfo struct {
    IMEI            string `json:"imei"`
    IMSI            string `json:"imsi"`
    FirmwareVersion string `json:"firmwareVersion"`
    HardwareVersion string `json:"hardwareVersion"`
    SerialNumber    string `json:"serialNumber"`
    Model           string `json:"model"`
}

type TrafficPoint struct {
    Timestamp   time.Time `json:"timestamp"`
    DownloadMB  float64   `json:"downloadMB"`
    UploadMB    float64   `json:"uploadMB"`
    SpeedDown   int64     `json:"speedDown"`
    SpeedUp     int64     `json:"speedUp"`
}

type Thresholds struct {
    SignalStrengthWarning int   `json:"signalStrengthWarning"`
    DataUsageWarning      int64 `json:"dataUsageWarning"`
    TemperatureWarning    int   `json:"temperatureWarning"`
}

type ModemUpdate struct {
    Type   string      `json:"type"`
    ModemID string     `json:"modemId"`
    Data   interface{} `json:"data"`
}

type SMSRequest struct {
    PhoneNumber string `json:"phoneNumber"`
    Message     string `json:"message"`
}

type SMSResponse struct {
    Success   bool   `json:"success"`
    MessageID string `json:"messageId,omitempty"`
    Error     string `json:"error,omitempty"`
}

func NewModemManager() *ModemManager {
    return &ModemManager{
        modems:    make(map[string]*ManagedModem),
        clients:   make(map[*websocket.Conn]bool),
        broadcast: make(chan ModemUpdate, 100),
        upgrader: websocket.Upgrader{
            CheckOrigin: func(r *http.Request) bool { return true },
        },
        scheduler: cron.New(cron.WithSeconds()),
    }
}

func (mm *ModemManager) Start() {
    // Start WebSocket handler
    go mm.handleWebSocketConnections()
    
    // Start broadcast handler
    go mm.handleBroadcast()
    
    // Start periodic updates
    go mm.startPeriodicUpdates()
    
    // Start auto-rotation scheduler
    mm.scheduler.Start()
    
    log.Println("Modem Manager started successfully")
}

func (mm *ModemManager) AddModem(id, name, model, ipAddress string, config ModemConfig) error {
    mm.mu.Lock()
    defer mm.mu.Unlock()

    client := hilink.NewClientURL(fmt.Sprintf("http://%s", ipAddress))
    
    modem := &ManagedModem{
        ID:        id,
        Name:      name,
        Model:     model,
        IPAddress: ipAddress,
        Client:    client,
        Config:    config,
        IsOnline:  false,
        LastSeen:  time.Now(),
        TrafficHistory: make([]TrafficPoint, 0, 288), // 24 hours of 5-minute intervals
    }

    // Test connection
    if err := modem.testConnection(); err != nil {
        return fmt.Errorf("failed to connect to modem: %w", err)
    }

    mm.modems[id] = modem
    
    // Setup auto-rotation if enabled
    if config.AutoRotateIP {
        mm.setupAutoRotation(modem)
    }

    // Initial data collection
    go mm.updateModemData(modem)

    log.Printf("Added modem: %s (%s)", name, ipAddress)
    return nil
}

func (mm *ModemManager) RemoveModem(id string) error {
    mm.mu.Lock()
    defer mm.mu.Unlock()

    modem, exists := mm.modems[id]
    if !exists {
        return fmt.Errorf("modem not found: %s", id)
    }

    // Stop rotation ticker
    if modem.RotationTicker != nil {
        modem.RotationTicker.Stop()
    }

    delete(mm.modems, id)
    
    mm.broadcast <- ModemUpdate{
        Type:   "modem_removed",
        ModemID: id,
        Data:   nil,
    }

    log.Printf("Removed modem: %s", modem.Name)
    return nil
}

func (mm *ModemManager) RotateIP(modemID string) error {
    mm.mu.RLock()
    modem, exists := mm.modems[modemID]
    mm.mu.RUnlock()

    if !exists {
        return fmt.Errorf("modem not found: %s", modemID)
    }

    return mm.rotateModemIP(modem)
}

func (mm *ModemManager) RotateAllIPs() error {
    mm.mu.RLock()
    modems := make([]*ManagedModem, 0, len(mm.modems))
    for _, modem := range mm.modems {
        if modem.IsOnline {
            modems = append(modems, modem)
        }
    }
    mm.mu.RUnlock()

    var wg sync.WaitGroup
    errors := make(chan error, len(modems))

    for _, modem := range modems {
        wg.Add(1)
        go func(m *ManagedModem) {
            defer wg.Done()
            if err := mm.rotateModemIP(m); err != nil {
                errors <- fmt.Errorf("failed to rotate IP for %s: %w", m.Name, err)
            }
        }(modem)
    }

    wg.Wait()
    close(errors)

    var allErrors []error
    for err := range errors {
        allErrors = append(allErrors, err)
    }

    if len(allErrors) > 0 {
        return fmt.Errorf("rotation errors: %v", allErrors)
    }

    log.Printf("Successfully rotated IPs for %d modems", len(modems))
    return nil
}

func (mm *ModemManager) SendSMS(modemID string, request SMSRequest) (*SMSResponse, error) {
    mm.mu.RLock()
    modem, exists := mm.modems[modemID]
    mm.mu.RUnlock()

    if !exists {
        return nil, fmt.Errorf("modem not found: %s", modemID)
    }

    if !modem.IsOnline {
        return &SMSResponse{
            Success: false,
            Error:   "modem is offline",
        }, nil
    }

    // Send SMS via Hilink API
    messageID, err := modem.Client.SendSMS(request.PhoneNumber, request.Message)
    if err != nil {
        return &SMSResponse{
            Success: false,
            Error:   err.Error(),
        }, nil
    }

    log.Printf("SMS sent from %s to %s: %s", modem.Name, request.PhoneNumber, request.Message)
    
    return &SMSResponse{
        Success:   true,
        MessageID: messageID,
    }, nil
}

func (mm *ModemManager) RebootModem(modemID string) error {
    mm.mu.RLock()
    modem, exists := mm.modems[modemID]
    mm.mu.RUnlock()

    if !exists {
        return fmt.Errorf("modem not found: %s", modemID)
    }

    if !modem.IsOnline {
        return fmt.Errorf("modem is offline")
    }

    // Reboot via Hilink API
    if err := modem.Client.Reboot(); err != nil {
        return fmt.Errorf("failed to reboot modem: %w", err)
    }

    modem.IsOnline = false
    
    mm.broadcast <- ModemUpdate{
        Type:   "modem_rebooted",
        ModemID: modemID,
        Data:   modem,
    }

    log.Printf("Rebooted modem: %s", modem.Name)
    
    // Wait for modem to come back online
    go mm.waitForModemRecovery(modem)
    
    return nil
}

func (mm *ModemManager) GetModemStats(modemID string) (*ManagedModem, error) {
    mm.mu.RLock()
    defer mm.mu.RUnlock()

    modem, exists := mm.modems[modemID]
    if !exists {
        return nil, fmt.Errorf("modem not found: %s", modemID)
    }

    return modem, nil
}

func (mm *ModemManager) GetAllModems() []*ManagedModem {
    mm.mu.RLock()
    defer mm.mu.RUnlock()

    modems := make([]*ManagedModem, 0, len(mm.modems))
    for _, modem := range mm.modems {
        modems = append(modems, modem)
    }

    return modems
}

func (mm *ModemManager) rotateModemIP(modem *ManagedModem) error {
    modem.mu.Lock()
    defer modem.mu.Unlock()

    if !modem.IsOnline {
        return fmt.Errorf("modem is offline")
    }

    oldIP := modem.Stats.CurrentIP

    // Disconnect and reconnect to get new IP
    if err := modem.Client.Disconnect(); err != nil {
        return fmt.Errorf("failed to disconnect: %w", err)
    }

    // Wait a moment before reconnecting
    time.Sleep(5 * time.Second)

    if err := modem.Client.Connect(); err != nil {
        return fmt.Errorf("failed to reconnect: %w", err)
    }

    // Wait for new IP assignment
    time.Sleep(10 * time.Second)

    // Get new IP
    status, err := modem.Client.Status()
    if err != nil {
        return fmt.Errorf("failed to get new IP: %w", err)
    }

    modem.Stats.CurrentIP = status.WanIPAddress

    mm.broadcast <- ModemUpdate{
        Type:   "ip_rotated",
        ModemID: modem.ID,
        Data: map[string]string{
            "oldIP": oldIP,
            "newIP": modem.Stats.CurrentIP,
        },
    }

    log.Printf("Rotated IP for %s: %s -> %s", modem.Name, oldIP, modem.Stats.CurrentIP)
    return nil
}

func (mm *ModemManager) updateModemData(modem *ManagedModem) {
    modem.mu.Lock()
    defer modem.mu.Unlock()

    // Test connection
    if err := modem.testConnection(); err != nil {
        if modem.IsOnline {
            modem.IsOnline = false
            mm.broadcast <- ModemUpdate{
                Type:   "modem_offline",
                ModemID: modem.ID,
                Data:   modem,
            }
        }
        return
    }

    if !modem.IsOnline {
        modem.IsOnline = true
        mm.broadcast <- ModemUpdate{
            Type:   "modem_online",
            ModemID: modem.ID,
            Data:   modem,
        }
    }

    modem.LastSeen = time.Now()

    // Update basic status
    mm.updateBasicStats(modem)
    
    // Update network info
    mm.updateNetworkInfo(modem)
    
    // Update device info (less frequently)
    if time.Since(modem.LastSeen) > 5*time.Minute {
        mm.updateDeviceInfo(modem)
    }
    
    // Update traffic history
    mm.updateTrafficHistory(modem)
    
    // Check thresholds and send alerts
    mm.checkThresholds(modem)

    mm.broadcast <- ModemUpdate{
        Type:   "modem_updated",
        ModemID: modem.ID,
        Data:   modem,
    }
}

func (mm *ModemManager) updateBasicStats(modem *ManagedModem) {
    status, err := modem.Client.Status()
    if err != nil {
        log.Printf("Failed to get status for %s: %v", modem.Name, err)
        return
    }

    trafficStats, err := modem.Client.TrafficStatistics()
    if err != nil {
        log.Printf("Failed to get traffic stats for %s: %v", modem.Name, err)
        return
    }

    modem.Stats.SignalStrength = status.SignalStrength
    modem.Stats.CurrentIP = status.WanIPAddress
    modem.Stats.MonthlyUsed = parseTrafficValue(trafficStats.MonthDownload)
    modem.Stats.MonthlyLimit = int64(modem.Config.MonthlyLimitGB) * 1024 * 1024 * 1024
    modem.Stats.CurrentSpeedDown = parseTrafficValue(trafficStats.CurrentDownloadRate)
    modem.Stats.CurrentSpeedUp = parseTrafficValue(trafficStats.CurrentUploadRate)
    
    // Get active connections count (this might need custom implementation)
    modem.Stats.ActiveConnections = mm.getActiveConnections(modem)
}

func (mm *ModemManager) updateNetworkInfo(modem *ManagedModem) {
    status, err := modem.Client.Status()
    if err != nil {
        return
    }

    modem.NetworkInfo.NetworkType = status.NetworkType
    modem.NetworkInfo.Operator = status.CurrentNetworkType

    // Get additional network details if available
    if networkInfo, err := modem.Client.NetworkInfo(); err == nil {
        modem.NetworkInfo.CellID = networkInfo.CellID
        modem.NetworkInfo.LAC = networkInfo.LAC
        modem.NetworkInfo.RSRP = networkInfo.RSRP
        modem.NetworkInfo.RSRQ = networkInfo.RSRQ
        modem.NetworkInfo.SINR = networkInfo.SINR
    }
}

func (mm *ModemManager) updateDeviceInfo(modem *ManagedModem) {
    deviceInfo, err := modem.Client.DeviceInformation()
    if err != nil {
        return
    }

    modem.DeviceInfo.IMEI = deviceInfo.IMEI
    modem.DeviceInfo.IMSI = deviceInfo.IMSI
    modem.DeviceInfo.SerialNumber = deviceInfo.SerialNumber
    modem.DeviceInfo.HardwareVersion = deviceInfo.HardwareVersion
    modem.DeviceInfo.FirmwareVersion = deviceInfo.SoftwareVersion
    modem.DeviceInfo.Model = deviceInfo.DeviceName

    // Get battery and temperature info if available
    if batteryInfo, err := modem.Client.BatteryInfo(); err == nil {
        modem.Stats.BatteryLevel = batteryInfo.BatteryLevel
        modem.Stats.Temperature = batteryInfo.Temperature
    }
}

func (mm *ModemManager) updateTrafficHistory(modem *ManagedModem) {
    now := time.Now()
    point := TrafficPoint{
        Timestamp:  now,
        DownloadMB: float64(modem.Stats.MonthlyUsed) / 1024 / 1024,
        UploadMB:   0, // Add upload tracking if needed
        SpeedDown:  modem.Stats.CurrentSpeedDown,
        SpeedUp:    modem.Stats.CurrentSpeedUp,
    }

    modem.TrafficHistory = append(modem.TrafficHistory, point)
    
    // Keep only last 288 points (24 hours of 5-minute intervals)
    if len(modem.TrafficHistory) > 288 {
        modem.TrafficHistory = modem.TrafficHistory[1:]
    }
}

func (mm *ModemManager) checkThresholds(modem *ManagedModem) {
    // Check signal strength
    if modem.Stats.SignalStrength < modem.Config.AlertThresholds.SignalStrengthWarning {
        mm.sendAlert(modem, "warning", "Low Signal Strength", 
            fmt.Sprintf("Signal strength is %d dBm", modem.Stats.SignalStrength))
    }

    // Check data usage
    usagePercent := float64(modem.Stats.MonthlyUsed) / float64(modem.Stats.MonthlyLimit) * 100
    if usagePercent > 80 {
        mm.sendAlert(modem, "warning", "High Data Usage", 
            fmt.Sprintf("Data usage is %.1f%% of monthly limit", usagePercent))
    }

    // Check temperature
    if modem.Stats.Temperature > modem.Config.AlertThresholds.TemperatureWarning {
        mm.sendAlert(modem, "warning", "High Temperature", 
            fmt.Sprintf("Temperature is %d°C", modem.Stats.Temperature))
    }
}

func (mm *ModemManager) sendAlert(modem *ManagedModem, severity, title, message string) {
    alert := map[string]interface{}{
        "severity":  severity,
        "title":     title,
        "message":   message,
        "modemId":   modem.ID,
        "modemName": modem.Name,
        "timestamp": time.Now(),
    }

    mm.broadcast <- ModemUpdate{
        Type:   "alert",
        ModemID: modem.ID,
        Data:   alert,
    }
}

func (mm *ModemManager) setupAutoRotation(modem *ManagedModem) {
    if modem.RotationTicker != nil {
        modem.RotationTicker.Stop()
    }

    interval := modem.Config.RotationInterval
    if interval == 0 {
        interval = 1 * time.Hour // Default 1 hour
    }

    modem.RotationTicker = time.NewTicker(interval)
    
    go func() {
        for range modem.RotationTicker.C {
            if modem.IsOnline {
                if err := mm.rotateModemIP(modem); err != nil {
                    log.Printf("Auto-rotation failed for %s: %v", modem.Name, err)
                    mm.sendAlert(modem, "error", "Auto-rotation Failed", err.Error())
                }
            }
        }
    }()
}

func (mm *ModemManager) waitForModemRecovery(modem *ManagedModem) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    timeout := time.After(5 * time.Minute)
    
    for {
        select {
        case <-ticker.C:
            if err := modem.testConnection(); err == nil {
                modem.IsOnline = true
                mm.broadcast <- ModemUpdate{
                    Type:   "modem_recovered",
                    ModemID: modem.ID,
                    Data:   modem,
                }
                log.Printf("Modem recovered: %s", modem.Name)
                return
            }
        case <-timeout:
            log.Printf("Modem recovery timeout: %s", modem.Name)
            mm.sendAlert(modem, "error", "Recovery Timeout", 
                "Modem failed to recover after reboot")
            return
        }
    }
}

func (mm *ModemManager) startPeriodicUpdates() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        mm.mu.RLock()
        modems := make([]*ManagedModem, 0, len(mm.modems))
        for _, modem := range mm.modems {
            modems = append(modems, modem)
        }
        mm.mu.RUnlock()

        for _, modem := range modems {
            go mm.updateModemData(modem)
        }
    }
}

func (mm *ModemManager) handleWebSocketConnections() {
    http.HandleFunc("/ws/modems", func(w http.ResponseWriter, r *http.Request) {
        conn, err := mm.upgrader.Upgrade(w, r, nil)
        if err != nil {
            log.Printf("WebSocket upgrade error: %v", err)
            return
        }
        defer conn.Close()

        mm.clients[conn] = true
        defer delete(mm.clients, conn)

        // Send initial data
        initialData := map[string]interface{}{
            "type": "initial_data",
            "data": mm.GetAllModems(),
        }
        conn.WriteJSON(initialData)

        // Keep connection alive
        for {
            _, _, err := conn.ReadMessage()
            if err != nil {
                break
            }
        }
    })
}

func (mm *ModemManager) handleBroadcast() {
    for update := range mm.broadcast {
        for client := range mm.clients {
            err := client.WriteJSON(update)
            if err != nil {
                client.Close()
                delete(mm.clients, client)
            }
        }
    }
}

// HTTP Handlers
func (mm *ModemManager) SetupRoutes(r *gin.Engine) {
    api := r.Group("/api/modems")
    
    api.GET("/", mm.getAllModemsHandler)
    api.GET("/:id", mm.getModemHandler)
    api.POST("/", mm.addModemHandler)
    api.DELETE("/:id", mm.removeModemHandler)
    api.POST("/:id/rotate-ip", mm.rotateIPHandler)
    api.POST("/rotate-all-ips", mm.rotateAllIPsHandler)
    api.POST("/:id/sms", mm.sendSMSHandler)
    api.POST("/:id/reboot", mm.rebootModemHandler)
    api.GET("/:id/traffic-history", mm.getTrafficHistoryHandler)
}

func (mm *ModemManager) getAllModemsHandler(c *gin.Context) {
    modems := mm.GetAllModems()
    c.JSON(http.StatusOK, gin.H{"modems": modems})
}

func (mm *ModemManager) getModemHandler(c *gin.Context) {
    id := c.Param("id")
    modem, err := mm.GetModemStats(id)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, modem)
}

func (mm *ModemManager) addModemHandler(c *gin.Context) {
    var request struct {
        Name      string      `json:"name" binding:"required"`
        Model     string      `json:"model" binding:"required"`
        IPAddress string      `json:"ipAddress" binding:"required"`
        Config    ModemConfig `json:"config"`
    }

    if err := c.ShouldBindJSON(&request); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    id := fmt.Sprintf("modem_%d", time.Now().Unix())
    
    if err := mm.AddModem(id, request.Name, request.Model, request.IPAddress, request.Config); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusCreated, gin.H{
        "id":      id,
        "message": "Modem added successfully",
    })
}

func (mm *ModemManager) removeModemHandler(c *gin.Context) {
    id := c.Param("id")
    if err := mm.RemoveModem(id); err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Modem removed successfully"})
}

func (mm *ModemManager) rotateIPHandler(c *gin.Context) {
    id := c.Param("id")
    if err := mm.RotateIP(id); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "IP rotation initiated"})
}

func (mm *ModemManager) rotateAllIPsHandler(c *gin.Context) {
    if err := mm.RotateAllIPs(); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "All IPs rotation initiated"})
}

func (mm *ModemManager) sendSMSHandler(c *gin.Context) {
    id := c.Param("id")
    
    var request SMSRequest
    if err := c.ShouldBindJSON(&request); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    response, err := mm.SendSMS(id, request)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    if response.Success {
        c.JSON(http.StatusOK, response)
    } else {
        c.JSON(http.StatusBadRequest, response)
    }
}

func (mm *ModemManager) rebootModemHandler(c *gin.Context) {
    id := c.Param("id")
    if err := mm.RebootModem(id); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Modem reboot initiated"})
}

func (mm *ModemManager) getTrafficHistoryHandler(c *gin.Context) {
    id := c.Param("id")
    modem, err := mm.GetModemStats(id)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"traffic_history": modem.TrafficHistory})
}

// Utility functions
func (m *ManagedModem) testConnection() error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Test basic connectivity
    _, err := m.Client.DeviceInformationCtx(ctx)
    return err
}

func parseTrafficValue(value string) int64 {
    // Parse traffic values like "1.23 GB" to bytes
    // This is a simplified version - implement proper parsing
    if value == "" {
        return 0
    }
    // Implementation would parse the actual format returned by the modem
    return 0
}

func (mm *ModemManager) getActiveConnections(modem *ManagedModem) int {
    // This would need to be implemented based on your proxy server
    // It should return the number of active connections using this modem
    return 0
}

func main() {
    manager := NewModemManager()
    manager.Start()

    r := gin.Default()
    manager.SetupRoutes(r)

    // Add CORS middleware
    r.Use(func(c *gin.Context) {
        c.Header("Access-Control-Allow-Origin", "*")
        c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        
        c.Next()
    })

    log.Println("Modem management service starting on :8080")
    log.Fatal(r.Run(":8080"))
}