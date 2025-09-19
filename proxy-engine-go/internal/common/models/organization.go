package models

import (
	"time"
	"github.com/google/uuid"
)

type Organization struct {
	ID        uuid.UUID              `json:"id" db:"id"`
	Name      string                 `json:"name" db:"name"`
	PlanType  string                 `json:"plan_type" db:"plan_type"`
	Settings  map[string]interface{} `json:"settings" db:"settings"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}

type User struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	OrganizationID uuid.UUID              `json:"organization_id" db:"organization_id"`
	Email          string                 `json:"email" db:"email"`
	PasswordHash   string                 `json:"password_hash" db:"password_hash"`
	Role           string                 `json:"role" db:"role"`
	IsActive       bool                   `json:"is_active" db:"is_active"`
	Limits         map[string]interface{} `json:"limits" db:"limits"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" db:"updated_at"`
}

type ProxyServer struct {
	ID        uuid.UUID              `json:"id" db:"id"`
	Name      string                 `json:"name" db:"name"`
	Type      string                 `json:"type" db:"type"`
	Endpoint  string                 `json:"endpoint" db:"endpoint"`
	Status    string                 `json:"status" db:"status"`
	Location  string                 `json:"location" db:"location"`
	Specs     map[string]interface{} `json:"specs" db:"specs"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}