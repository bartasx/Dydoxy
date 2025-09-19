package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/dydoxy/proxy-engine-go/internal/common/config"
	"github.com/dydoxy/proxy-engine-go/internal/common/logging"
	"github.com/dydoxy/proxy-engine-go/internal/modem/pool"
)

type ModemAPI struct {
	manager *pool.Manager
}

func main() {
	cfg := config.Load()
	logger := logging.NewLogger(cfg.LogLevel)
	
	manager := pool.NewManager(logger)
	api := &ModemAPI{manager: manager}
	
	r := gin.Default()
	
	v1 := r.Group("/api/v1/modems")
	{
		v1.POST("/", api.addModem)
		v1.GET("/", api.listModems)
		v1.POST("/:id/rotate", api.rotateIP)
		v1.GET("/:id/status", api.getStatus)
	}
	
	logger.Info("Modem manager starting on :8081")
	r.Run(":8081")
}

type AddModemRequest struct {
	Name      string `json:"name" binding:"required"`
	IPAddress string `json:"ip_address" binding:"required"`
}

func (api *ModemAPI) addModem(c *gin.Context) {
	var req AddModemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	id := api.manager.AddModem(req.Name, req.IPAddress)
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (api *ModemAPI) listModems(c *gin.Context) {
	// Implementation would list all modems
	c.JSON(http.StatusOK, gin.H{"modems": []string{}})
}

func (api *ModemAPI) rotateIP(c *gin.Context) {
	id := c.Param("id")
	if err := api.manager.RotateIP(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (api *ModemAPI) getStatus(c *gin.Context) {
	// Implementation would get modem status
	c.JSON(http.StatusOK, gin.H{"status": "online"})
}