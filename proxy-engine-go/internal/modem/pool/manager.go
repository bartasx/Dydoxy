package pool

import (
	"sync"
	"time"

	"github.com/dydoxy/proxy-engine-go/internal/modem/huawei"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type Manager struct {
	modems   map[string]*Modem
	strategy RotationStrategy
	logger   *logrus.Logger
	mu       sync.RWMutex
}

type Modem struct {
	ID       string
	Name     string
	Client   *huawei.Client
	IsOnline bool
	LastUsed time.Time
}

type RotationStrategy string

const (
	RoundRobin RotationStrategy = "round_robin"
	LeastUsed  RotationStrategy = "least_used"
	Random     RotationStrategy = "random"
)

func NewManager(logger *logrus.Logger) *Manager {
	return &Manager{
		modems:   make(map[string]*Modem),
		strategy: RoundRobin,
		logger:   logger,
	}
}

func (m *Manager) AddModem(name, ipAddress string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := uuid.New().String()
	modem := &Modem{
		ID:       id,
		Name:     name,
		Client:   huawei.NewClient(ipAddress),
		IsOnline: false,
		LastUsed: time.Now(),
	}

	// Test connection
	if _, err := modem.Client.GetStatus(); err == nil {
		modem.IsOnline = true
	}

	m.modems[id] = modem
	m.logger.Infof("Added modem %s (%s)", name, id)
	return id
}

func (m *Manager) GetNextModem() *Modem {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var selected *Modem
	
	switch m.strategy {
	case LeastUsed:
		var oldest time.Time = time.Now()
		for _, modem := range m.modems {
			if modem.IsOnline && modem.LastUsed.Before(oldest) {
				oldest = modem.LastUsed
				selected = modem
			}
		}
	default: // RoundRobin
		for _, modem := range m.modems {
			if modem.IsOnline {
				selected = modem
				break
			}
		}
	}

	if selected != nil {
		selected.LastUsed = time.Now()
	}

	return selected
}

func (m *Manager) RotateIP(modemID string) error {
	m.mu.RLock()
	modem, exists := m.modems[modemID]
	m.mu.RUnlock()

	if !exists {
		return ErrModemNotFound
	}

	if err := modem.Client.Disconnect(); err != nil {
		return err
	}

	time.Sleep(5 * time.Second)

	if err := modem.Client.Connect(); err != nil {
		return err
	}

	m.logger.Infof("Rotated IP for modem %s", modemID)
	return nil
}

import "fmt"

var ErrModemNotFound = fmt.Errorf("modem not found")