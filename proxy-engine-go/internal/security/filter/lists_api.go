package filter

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ListsAPI provides REST API endpoints for blacklist/whitelist management
type ListsAPI struct {
	manager ListManager
	logger  *logrus.Logger
}

// NewListsAPI creates a new lists API
func NewListsAPI(manager ListManager, logger *logrus.Logger) *ListsAPI {
	return &ListsAPI{
		manager: manager,
		logger:  logger,
	}
}

// RegisterRoutes registers API routes with Gin router
func (api *ListsAPI) RegisterRoutes(r *gin.RouterGroup) {
	// List entries management
	r.GET("/entries", api.SearchEntries)
	r.POST("/entries", api.CreateEntry)
	r.GET("/entries/:id", api.GetEntry)
	r.PUT("/entries/:id", api.UpdateEntry)
	r.DELETE("/entries/:id", api.DeleteEntry)
	
	// Bulk operations
	r.POST("/entries/bulk", api.BulkOperation)
	r.POST("/entries/import", api.ImportEntries)
	r.GET("/entries/export", api.ExportEntries)
	
	// List checking
	r.POST("/check", api.CheckValue)
	r.GET("/stats", api.GetStats)
	
	// Maintenance
	r.POST("/cleanup", api.CleanupExpired)
	r.POST("/sync", api.SyncThreatFeeds)
}

// CreateEntryRequest represents a request to create a new list entry
type CreateEntryRequest struct {
	Value     string            `json:"value" binding:"required"`
	Type      ListType          `json:"type" binding:"required"`
	Category  string            `json:"category"`
	Source    string            `json:"source"`
	Reason    string            `json:"reason"`
	Enabled   bool              `json:"enabled"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateEntryRequest represents a request to update a list entry
type UpdateEntryRequest struct {
	Value     string            `json:"value"`
	Category  string            `json:"category"`
	Source    string            `json:"source"`
	Reason    string            `json:"reason"`
	Enabled   *bool             `json:"enabled"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ImportEntriesRequest represents a request to import entries
type ImportEntriesRequest struct {
	Type     ListType     `json:"type" binding:"required"`
	Category ListCategory `json:"category" binding:"required"`
	Source   ListSource   `json:"source" binding:"required"`
	Entries  []string     `json:"entries" binding:"required"`
}

// CheckValueRequest represents a request to check a value
type CheckValueRequest struct {
	Value string `json:"value" binding:"required"`
}

// SearchEntries searches for list entries
func (api *ListsAPI) SearchEntries(c *gin.Context) {
	query := &ListSearchQuery{}
	
	// Parse query parameters
	if typeStr := c.Query("type"); typeStr != "" {
		if typeInt, err := strconv.Atoi(typeStr); err == nil {
			listType := ListType(typeInt)
			query.Type = &listType
		}
	}
	
	if category := c.Query("category"); category != "" {
		cat := ListCategory(category)
		query.Category = &cat
	}
	
	if source := c.Query("source"); source != "" {
		src := ListSource(source)
		query.Source = &src
	}
	
	if value := c.Query("value"); value != "" {
		query.Value = value
	}
	
	if enabledStr := c.Query("enabled"); enabledStr != "" {
		if enabled, err := strconv.ParseBool(enabledStr); err == nil {
			query.Enabled = &enabled
		}
	}
	
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			query.Limit = limit
		}
	}
	
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			query.Offset = offset
		}
	}
	
	query.SortBy = c.Query("sort_by")
	query.SortOrder = c.Query("sort_order")
	
	entries, total, err := api.manager.SearchEntries(c.Request.Context(), query)
	if err != nil {
		api.logger.Errorf("Failed to search entries: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search entries"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"total":   total,
		"limit":   query.Limit,
		"offset":  query.Offset,
	})
}

// CreateEntry creates a new list entry
func (api *ListsAPI) CreateEntry(c *gin.Context) {
	var req CreateEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	entry := &ListEntry{
		ID:        uuid.New().String(),
		Value:     req.Value,
		Type:      req.Type,
		Category:  req.Category,
		Source:    req.Source,
		Reason:    req.Reason,
		Enabled:   req.Enabled,
		ExpiresAt: req.ExpiresAt,
		Metadata:  req.Metadata,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	if err := api.manager.AddEntry(c.Request.Context(), entry); err != nil {
		api.logger.Errorf("Failed to create entry: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create entry"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "Entry created successfully",
		"entry":   entry,
	})
}

// GetEntry retrieves a specific entry by ID
func (api *ListsAPI) GetEntry(c *gin.Context) {
	entryID := c.Param("id")
	
	entry, err := api.manager.GetEntry(c.Request.Context(), entryID)
	if err != nil {
		api.logger.Errorf("Failed to get entry: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Entry not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"entry": entry})
}

// UpdateEntry updates an existing list entry
func (api *ListsAPI) UpdateEntry(c *gin.Context) {
	entryID := c.Param("id")
	
	var req UpdateEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Get existing entry
	entry, err := api.manager.GetEntry(c.Request.Context(), entryID)
	if err != nil {
		api.logger.Errorf("Failed to get entry: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Entry not found"})
		return
	}
	
	// Update fields
	if req.Value != "" {
		entry.Value = req.Value
	}
	if req.Category != "" {
		entry.Category = req.Category
	}
	if req.Source != "" {
		entry.Source = req.Source
	}
	if req.Reason != "" {
		entry.Reason = req.Reason
	}
	if req.Enabled != nil {
		entry.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		entry.ExpiresAt = req.ExpiresAt
	}
	if req.Metadata != nil {
		entry.Metadata = req.Metadata
	}
	
	entry.UpdatedAt = time.Now()
	
	if err := api.manager.UpdateEntry(c.Request.Context(), entry); err != nil {
		api.logger.Errorf("Failed to update entry: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update entry"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Entry updated successfully",
		"entry":   entry,
	})
}

// DeleteEntry deletes a list entry
func (api *ListsAPI) DeleteEntry(c *gin.Context) {
	entryID := c.Param("id")
	
	if err := api.manager.RemoveEntry(c.Request.Context(), entryID); err != nil {
		api.logger.Errorf("Failed to delete entry: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete entry"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Entry deleted successfully"})
}

// BulkOperation performs bulk operations on list entries
func (api *ListsAPI) BulkOperation(c *gin.Context) {
	var operation BulkOperation
	if err := c.ShouldBindJSON(&operation); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	result, err := api.manager.BulkOperation(c.Request.Context(), &operation)
	if err != nil {
		api.logger.Errorf("Failed to perform bulk operation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to perform bulk operation"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Bulk operation completed",
		"result":  result,
	})
}

// ImportEntries imports entries from various sources
func (api *ListsAPI) ImportEntries(c *gin.Context) {
	var req ImportEntriesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	result, err := api.manager.ImportEntries(c.Request.Context(), req.Type, req.Source, req.Entries, req.Category)
	if err != nil {
		api.logger.Errorf("Failed to import entries: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to import entries"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Entries imported successfully",
		"result":  result,
	})
}

// ExportEntries exports entries in specified format
func (api *ListsAPI) ExportEntries(c *gin.Context) {
	query := &ListSearchQuery{}
	
	// Parse query parameters (similar to SearchEntries)
	if typeStr := c.Query("type"); typeStr != "" {
		if typeInt, err := strconv.Atoi(typeStr); err == nil {
			listType := ListType(typeInt)
			query.Type = &listType
		}
	}
	
	if category := c.Query("category"); category != "" {
		cat := ListCategory(category)
		query.Category = &cat
	}
	
	format := ExportFormat(c.Query("format"))
	if format == "" {
		format = FormatJSON
	}
	
	// Set appropriate content type
	switch format {
	case FormatJSON:
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", "attachment; filename=lists.json")
	case FormatCSV:
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=lists.csv")
	case FormatTXT:
		c.Header("Content-Type", "text/plain")
		c.Header("Content-Disposition", "attachment; filename=lists.txt")
	}
	
	if err := api.manager.ExportEntries(c.Request.Context(), query, format, c.Writer); err != nil {
		api.logger.Errorf("Failed to export entries: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export entries"})
		return
	}
}

// CheckValue checks if a value exists in blacklist or whitelist
func (api *ListsAPI) CheckValue(c *gin.Context) {
	var req CheckValueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	result, err := api.manager.CheckValue(c.Request.Context(), req.Value)
	if err != nil {
		api.logger.Errorf("Failed to check value: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check value"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"value":  req.Value,
		"result": result,
	})
}

// GetStats returns statistics about lists
func (api *ListsAPI) GetStats(c *gin.Context) {
	stats, err := api.manager.GetStats(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to get stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get stats"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// CleanupExpired removes expired entries
func (api *ListsAPI) CleanupExpired(c *gin.Context) {
	count, err := api.manager.CleanupExpired(c.Request.Context())
	if err != nil {
		api.logger.Errorf("Failed to cleanup expired entries: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cleanup expired entries"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Cleanup completed",
		"removed": count,
	})
}

// SyncThreatFeeds synchronizes with external threat intelligence feeds
func (api *ListsAPI) SyncThreatFeeds(c *gin.Context) {
	if err := api.manager.SyncWithThreatFeeds(c.Request.Context()); err != nil {
		api.logger.Errorf("Failed to sync threat feeds: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sync threat feeds"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Threat feeds synchronized successfully"})
}