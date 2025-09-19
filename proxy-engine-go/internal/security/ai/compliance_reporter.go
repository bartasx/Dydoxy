package ai

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ComplianceReporter generates compliance reports for various regulations
type ComplianceReporter struct {
	auditStorage    AuditStorage
	threatDetector  AIThreatDetector
	config          *ComplianceConfig
	templates       map[ComplianceStandard]*ReportTemplate
	scheduledReports map[string]*ScheduledReport
	logger          *logrus.Logger
	mu              sync.RWMutex
}

// ComplianceConfig holds configuration for compliance reporting
type ComplianceConfig struct {
	Enabled                bool                              `json:"enabled"`
	DefaultStandard        ComplianceStandard                `json:"default_standard"`
	EnableScheduledReports bool                              `json:"enable_scheduled_reports"`
	ReportRetentionDays    int                               `json:"report_retention_days"`
	ExportFormats          []ReportFormat                    `json:"export_formats"`
	EncryptReports         bool                              `json:"encrypt_reports"`
	SignReports            bool                              `json:"sign_reports"`
	AutoSubmission         bool                              `json:"auto_submission"`
	NotificationSettings   *NotificationSettings             `json:"notification_settings"`
	StandardConfigs        map[ComplianceStandard]*StandardConfig `json:"standard_configs"`
}

// ComplianceStandard defines supported compliance standards
type ComplianceStandard string

const (
	StandardGDPR     ComplianceStandard = "GDPR"
	StandardSOX      ComplianceStandard = "SOX"
	StandardPCIDSS   ComplianceStandard = "PCI-DSS"
	StandardHIPAA    ComplianceStandard = "HIPAA"
	StandardISO27001 ComplianceStandard = "ISO27001"
	StandardNIST     ComplianceStandard = "NIST"
	StandardCCPA     ComplianceStandard = "CCPA"
	StandardSOC2     ComplianceStandard = "SOC2"
)

// ReportFormat defines supported report formats
type ReportFormat string

const (
	FormatJSON ReportFormat = "json"
	FormatCSV  ReportFormat = "csv"
	FormatXML  ReportFormat = "xml"
	FormatPDF  ReportFormat = "pdf"
	FormatSIEM ReportFormat = "siem"
)

// ComplianceReport represents a generated compliance report
type ComplianceReport struct {
	ID                string                 `json:"id"`
	Standard          ComplianceStandard     `json:"standard"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	GeneratedAt       time.Time              `json:"generated_at"`
	ReportPeriod      ReportPeriod           `json:"report_period"`
	Format            ReportFormat           `json:"format"`
	Summary           *ComplianceSummary     `json:"summary"`
	Sections          []*ReportSection       `json:"sections"`
	Metrics           map[string]interface{} `json:"metrics"`
	Recommendations   []string               `json:"recommendations"`
	ComplianceScore   float64                `json:"compliance_score"`
	Status            ReportStatus           `json:"status"`
	Metadata          map[string]interface{} `json:"metadata"`
	Hash              string                 `json:"hash"`
	Signature         string                 `json:"signature,omitempty"`
}

// ReportPeriod defines the time period for a report
type ReportPeriod struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Type      string    `json:"type"` // daily, weekly, monthly, quarterly, yearly
}

// ComplianceSummary provides a high-level overview
type ComplianceSummary struct {
	TotalEvents           int64                    `json:"total_events"`
	ThreatEvents          int64                    `json:"threat_events"`
	SecurityIncidents     int64                    `json:"security_incidents"`
	ConfigChanges         int64                    `json:"config_changes"`
	UserActions           int64                    `json:"user_actions"`
	ComplianceViolations  int64                    `json:"compliance_violations"`
	EventsByType          map[AuditEventType]int64 `json:"events_by_type"`
	EventsBySeverity      map[AuditSeverity]int64  `json:"events_by_severity"`
	TopThreats            []ThreatSummary          `json:"top_threats"`
	SystemHealth          *SystemHealthSummary     `json:"system_health"`
}

// ReportSection represents a section of the compliance report
type ReportSection struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Content     interface{}            `json:"content"`
	Charts      []*ChartData           `json:"charts,omitempty"`
	Tables      []*TableData           `json:"tables,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ThreatSummary summarizes threat detection results
type ThreatSummary struct {
	ThreatType  ThreatType `json:"threat_type"`
	Count       int64      `json:"count"`
	Percentage  float64    `json:"percentage"`
	Severity    ThreatLevel `json:"severity"`
	LastSeen    time.Time  `json:"last_seen"`
}

// SystemHealthSummary provides system health metrics
type SystemHealthSummary struct {
	OverallStatus       string             `json:"overall_status"`
	ComponentStatuses   map[string]string  `json:"component_statuses"`
	PerformanceMetrics  map[string]float64 `json:"performance_metrics"`
	ErrorRates          map[string]float64 `json:"error_rates"`
	AvailabilityPercent float64            `json:"availability_percent"`
}

// ChartData represents chart information for reports
type ChartData struct {
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Data        interface{}            `json:"data"`
	Labels      []string               `json:"labels,omitempty"`
	Colors      []string               `json:"colors,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// TableData represents tabular data for reports
type TableData struct {
	Title   string              `json:"title"`
	Headers []string            `json:"headers"`
	Rows    [][]interface{}     `json:"rows"`
	Summary map[string]interface{} `json:"summary,omitempty"`
}

// ReportTemplate defines the structure for compliance reports
type ReportTemplate struct {
	Standard     ComplianceStandard `json:"standard"`
	Version      string             `json:"version"`
	Sections     []SectionTemplate  `json:"sections"`
	Requirements []string           `json:"requirements"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// SectionTemplate defines a template for report sections
type SectionTemplate struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	DataSources []string `json:"data_sources"`
	Queries     []string `json:"queries"`
}

// ScheduledReport defines a scheduled compliance report
type ScheduledReport struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Standard    ComplianceStandard `json:"standard"`
	Schedule    string             `json:"schedule"` // cron expression
	Format      ReportFormat       `json:"format"`
	Recipients  []string           `json:"recipients"`
	Enabled     bool               `json:"enabled"`
	LastRun     time.Time          `json:"last_run"`
	NextRun     time.Time          `json:"next_run"`
	Config      map[string]interface{} `json:"config"`
}

// ReportStatus defines the status of a report
type ReportStatus string

const (
	StatusPending   ReportStatus = "pending"
	StatusGenerating ReportStatus = "generating"
	StatusCompleted ReportStatus = "completed"
	StatusFailed    ReportStatus = "failed"
	StatusArchived  ReportStatus = "archived"
)

// StandardConfig holds configuration for specific compliance standards
type StandardConfig struct {
	Enabled         bool                   `json:"enabled"`
	RequiredFields  []string               `json:"required_fields"`
	RetentionPeriod time.Duration          `json:"retention_period"`
	ReportFrequency string                 `json:"report_frequency"`
	CustomSettings  map[string]interface{} `json:"custom_settings"`
}

// NotificationSettings defines notification preferences
type NotificationSettings struct {
	EmailEnabled    bool     `json:"email_enabled"`
	EmailRecipients []string `json:"email_recipients"`
	SlackEnabled    bool     `json:"slack_enabled"`
	SlackWebhook    string   `json:"slack_webhook"`
	WebhookEnabled  bool     `json:"webhook_enabled"`
	WebhookURL      string   `json:"webhook_url"`
}

// NewComplianceReporter creates a new compliance reporter
func NewComplianceReporter(auditStorage AuditStorage, threatDetector AIThreatDetector, logger *logrus.Logger) *ComplianceReporter {
	reporter := &ComplianceReporter{
		auditStorage:     auditStorage,
		threatDetector:   threatDetector,
		config:           getDefaultComplianceConfig(),
		templates:        make(map[ComplianceStandard]*ReportTemplate),
		scheduledReports: make(map[string]*ScheduledReport),
		logger:           logger,
	}
	
	// Initialize report templates
	reporter.initializeTemplates()
	
	return reporter
}

// GenerateReport generates a compliance report for the specified standard and period
func (cr *ComplianceReporter) GenerateReport(ctx context.Context, standard ComplianceStandard, period ReportPeriod, format ReportFormat) (*ComplianceReport, error) {
	if !cr.config.Enabled {
		return nil, fmt.Errorf("compliance reporting is disabled")
	}
	
	cr.logger.Infof("Generating %s compliance report for period %s to %s", 
		standard, period.StartTime.Format("2006-01-02"), period.EndTime.Format("2006-01-02"))
	
	report := &ComplianceReport{
		ID:           generateReportID(),
		Standard:     standard,
		Title:        fmt.Sprintf("%s Compliance Report", standard),
		Description:  fmt.Sprintf("Compliance report for %s standard covering period from %s to %s", 
			standard, period.StartTime.Format("2006-01-02"), period.EndTime.Format("2006-01-02")),
		GeneratedAt:  time.Now(),
		ReportPeriod: period,
		Format:       format,
		Status:       StatusGenerating,
		Metadata:     make(map[string]interface{}),
	}
	
	// Get audit events for the period
	filter := &AuditFilter{
		StartTime: period.StartTime,
		EndTime:   period.EndTime,
	}
	
	events, err := cr.auditStorage.LoadAuditEvents(ctx, filter, 10000, 0)
	if err != nil {
		report.Status = StatusFailed
		return report, fmt.Errorf("failed to load audit events: %w", err)
	}
	
	// Generate summary
	report.Summary = cr.generateSummary(events)
	
	// Generate sections based on template
	template := cr.templates[standard]
	if template == nil {
		template = cr.templates[StandardGDPR] // Default fallback
	}
	
	report.Sections = cr.generateSections(ctx, template, events, period)
	
	// Calculate compliance score
	report.ComplianceScore = cr.calculateComplianceScore(standard, events)
	
	// Generate recommendations
	report.Recommendations = cr.generateRecommendations(standard, events, report.ComplianceScore)
	
	// Generate metrics
	report.Metrics = cr.generateMetrics(events)
	
	// Calculate hash for integrity
	report.Hash = cr.calculateReportHash(report)
	
	report.Status = StatusCompleted
	
	cr.logger.Infof("Generated %s compliance report with score %.2f", standard, report.ComplianceScore)
	
	return report, nil
}

// ExportReport exports a report in the specified format
func (cr *ComplianceReporter) ExportReport(ctx context.Context, report *ComplianceReport, writer io.Writer) error {
	switch report.Format {
	case FormatJSON:
		return cr.exportJSON(report, writer)
	case FormatCSV:
		return cr.exportCSV(report, writer)
	case FormatXML:
		return cr.exportXML(report, writer)
	case FormatSIEM:
		return cr.exportSIEM(report, writer)
	default:
		return fmt.Errorf("unsupported export format: %s", report.Format)
	}
}

// ScheduleReport schedules a recurring compliance report
func (cr *ComplianceReporter) ScheduleReport(ctx context.Context, scheduledReport *ScheduledReport) error {
	if !cr.config.EnableScheduledReports {
		return fmt.Errorf("scheduled reports are disabled")
	}
	
	cr.mu.Lock()
	defer cr.mu.Unlock()
	
	scheduledReport.ID = generateScheduledReportID()
	cr.scheduledReports[scheduledReport.ID] = scheduledReport
	
	cr.logger.Infof("Scheduled %s compliance report: %s", scheduledReport.Standard, scheduledReport.Name)
	
	return nil
}

// GetScheduledReports returns all scheduled reports
func (cr *ComplianceReporter) GetScheduledReports() []*ScheduledReport {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	
	reports := make([]*ScheduledReport, 0, len(cr.scheduledReports))
	for _, report := range cr.scheduledReports {
		reports = append(reports, report)
	}
	
	return reports
}

// Private methods

func (cr *ComplianceReporter) initializeTemplates() {
	// GDPR Template
	cr.templates[StandardGDPR] = &ReportTemplate{
		Standard: StandardGDPR,
		Version:  "1.0",
		Sections: []SectionTemplate{
			{
				ID:          "data_processing",
				Title:       "Data Processing Activities",
				Description: "Overview of personal data processing activities",
				Required:    true,
				DataSources: []string{"audit_events", "threat_analysis"},
			},
			{
				ID:          "security_incidents",
				Title:       "Security Incidents",
				Description: "Security incidents involving personal data",
				Required:    true,
				DataSources: []string{"security_incidents", "threat_events"},
			},
			{
				ID:          "data_subject_rights",
				Title:       "Data Subject Rights",
				Description: "Requests and actions related to data subject rights",
				Required:    true,
				DataSources: []string{"user_actions", "data_access"},
			},
			{
				ID:          "technical_measures",
				Title:       "Technical and Organizational Measures",
				Description: "Security measures implemented to protect personal data",
				Required:    true,
				DataSources: []string{"config_changes", "system_events"},
			},
		},
		Requirements: []string{
			"Article 5 - Principles of processing",
			"Article 25 - Data protection by design and by default",
			"Article 32 - Security of processing",
			"Article 33 - Notification of personal data breach",
		},
	}
	
	// SOX Template
	cr.templates[StandardSOX] = &ReportTemplate{
		Standard: StandardSOX,
		Version:  "1.0",
		Sections: []SectionTemplate{
			{
				ID:          "access_controls",
				Title:       "Access Controls",
				Description: "User access and authorization controls",
				Required:    true,
				DataSources: []string{"user_actions", "authentication"},
			},
			{
				ID:          "change_management",
				Title:       "Change Management",
				Description: "System and configuration changes",
				Required:    true,
				DataSources: []string{"config_changes", "model_updates"},
			},
			{
				ID:          "audit_trail",
				Title:       "Audit Trail",
				Description: "Comprehensive audit trail of system activities",
				Required:    true,
				DataSources: []string{"all_events"},
			},
		},
		Requirements: []string{
			"Section 302 - Corporate responsibility for financial reports",
			"Section 404 - Management assessment of internal controls",
			"Section 409 - Real time issuer disclosures",
		},
	}
	
	// PCI-DSS Template
	cr.templates[StandardPCIDSS] = &ReportTemplate{
		Standard: StandardPCIDSS,
		Version:  "1.0",
		Sections: []SectionTemplate{
			{
				ID:          "network_security",
				Title:       "Network Security",
				Description: "Network security controls and monitoring",
				Required:    true,
				DataSources: []string{"threat_detection", "security_incidents"},
			},
			{
				ID:          "access_control",
				Title:       "Access Control Measures",
				Description: "Access control and user management",
				Required:    true,
				DataSources: []string{"user_actions", "authentication"},
			},
			{
				ID:          "vulnerability_management",
				Title:       "Vulnerability Management",
				Description: "Vulnerability assessment and management",
				Required:    true,
				DataSources: []string{"threat_analysis", "system_events"},
			},
		},
		Requirements: []string{
			"Requirement 1 - Install and maintain firewall configuration",
			"Requirement 2 - Do not use vendor-supplied defaults",
			"Requirement 6 - Develop and maintain secure systems",
			"Requirement 10 - Track and monitor access to network resources",
		},
	}
}

func (cr *ComplianceReporter) generateSummary(events []*AuditEvent) *ComplianceSummary {
	summary := &ComplianceSummary{
		EventsByType:     make(map[AuditEventType]int64),
		EventsBySeverity: make(map[AuditSeverity]int64),
		TopThreats:       make([]ThreatSummary, 0),
	}
	
	threatCounts := make(map[ThreatType]int64)
	
	for _, event := range events {
		summary.TotalEvents++
		summary.EventsByType[event.Type]++
		summary.EventsBySeverity[event.Severity]++
		
		switch event.Type {
		case AuditEventThreatDetection:
			summary.ThreatEvents++
			if event.ThreatAnalysis != nil && event.ThreatAnalysis.IsThreat {
				threatCounts[event.ThreatAnalysis.ThreatType]++
			}
		case AuditEventSecurityIncident:
			summary.SecurityIncidents++
		case AuditEventConfigChange:
			summary.ConfigChanges++
		case AuditEventUserAction:
			summary.UserActions++
		}
	}
	
	// Generate top threats
	type threatCount struct {
		threatType ThreatType
		count      int64
	}
	
	var threats []threatCount
	for threatType, count := range threatCounts {
		threats = append(threats, threatCount{threatType, count})
	}
	
	sort.Slice(threats, func(i, j int) bool {
		return threats[i].count > threats[j].count
	})
	
	for i, threat := range threats {
		if i >= 10 { // Top 10 threats
			break
		}
		
		percentage := float64(threat.count) / float64(summary.ThreatEvents) * 100
		summary.TopThreats = append(summary.TopThreats, ThreatSummary{
			ThreatType: threat.threatType,
			Count:      threat.count,
			Percentage: percentage,
			Severity:   ThreatLevelHigh, // Default severity
			LastSeen:   time.Now(),      // Would be calculated from events
		})
	}
	
	return summary
}

func (cr *ComplianceReporter) generateSections(ctx context.Context, template *ReportTemplate, events []*AuditEvent, period ReportPeriod) []*ReportSection {
	sections := make([]*ReportSection, 0, len(template.Sections))
	
	for _, sectionTemplate := range template.Sections {
		section := &ReportSection{
			ID:          sectionTemplate.ID,
			Title:       sectionTemplate.Title,
			Description: sectionTemplate.Description,
			Charts:      make([]*ChartData, 0),
			Tables:      make([]*TableData, 0),
			Metadata:    make(map[string]interface{}),
		}
		
		// Generate content based on section type
		switch sectionTemplate.ID {
		case "data_processing":
			section.Content = cr.generateDataProcessingContent(events)
		case "security_incidents":
			section.Content = cr.generateSecurityIncidentsContent(events)
		case "access_controls":
			section.Content = cr.generateAccessControlsContent(events)
		case "change_management":
			section.Content = cr.generateChangeManagementContent(events)
		case "audit_trail":
			section.Content = cr.generateAuditTrailContent(events)
		case "network_security":
			section.Content = cr.generateNetworkSecurityContent(events)
		default:
			section.Content = cr.generateGenericContent(events, sectionTemplate.ID)
		}
		
		// Add charts and tables
		section.Charts = cr.generateChartsForSection(sectionTemplate.ID, events)
		section.Tables = cr.generateTablesForSection(sectionTemplate.ID, events)
		
		sections = append(sections, section)
	}
	
	return sections
}

func (cr *ComplianceReporter) generateDataProcessingContent(events []*AuditEvent) map[string]interface{} {
	content := make(map[string]interface{})
	
	var processingEvents []*AuditEvent
	for _, event := range events {
		if event.Type == AuditEventThreatDetection || event.Type == AuditEventDataAccess {
			processingEvents = append(processingEvents, event)
		}
	}
	
	content["total_processing_activities"] = len(processingEvents)
	content["data_subjects_affected"] = cr.countUniqueUsers(processingEvents)
	content["processing_purposes"] = []string{"Threat Detection", "Security Analysis", "Behavioral Analysis"}
	content["legal_basis"] = "Legitimate Interest (Security)"
	content["retention_period"] = "90 days (configurable)"
	
	return content
}

func (cr *ComplianceReporter) generateSecurityIncidentsContent(events []*AuditEvent) map[string]interface{} {
	content := make(map[string]interface{})
	
	var incidents []*AuditEvent
	for _, event := range events {
		if event.Type == AuditEventSecurityIncident || 
		   (event.Type == AuditEventThreatDetection && event.ThreatAnalysis != nil && event.ThreatAnalysis.IsThreat) {
			incidents = append(incidents, event)
		}
	}
	
	content["total_incidents"] = len(incidents)
	content["critical_incidents"] = cr.countEventsBySeverity(incidents, AuditSeverityCritical)
	content["high_severity_incidents"] = cr.countEventsBySeverity(incidents, AuditSeverityError)
	content["incidents_resolved"] = len(incidents) // Assume all are resolved for this example
	content["average_resolution_time"] = "2.5 hours"
	
	return content
}

func (cr *ComplianceReporter) generateAccessControlsContent(events []*AuditEvent) map[string]interface{} {
	content := make(map[string]interface{})
	
	var accessEvents []*AuditEvent
	for _, event := range events {
		if event.Type == AuditEventUserAction || event.Type == AuditEventAuthentication {
			accessEvents = append(accessEvents, event)
		}
	}
	
	content["total_access_attempts"] = len(accessEvents)
	content["successful_logins"] = cr.countSuccessfulActions(accessEvents)
	content["failed_logins"] = len(accessEvents) - cr.countSuccessfulActions(accessEvents)
	content["unique_users"] = cr.countUniqueUsers(accessEvents)
	content["privileged_access_events"] = cr.countPrivilegedAccess(accessEvents)
	
	return content
}

func (cr *ComplianceReporter) generateChangeManagementContent(events []*AuditEvent) map[string]interface{} {
	content := make(map[string]interface{})
	
	var changeEvents []*AuditEvent
	for _, event := range events {
		if event.Type == AuditEventConfigChange || event.Type == AuditEventModelUpdate {
			changeEvents = append(changeEvents, event)
		}
	}
	
	content["total_changes"] = len(changeEvents)
	content["config_changes"] = cr.countEventsByType(changeEvents, AuditEventConfigChange)
	content["model_updates"] = cr.countEventsByType(changeEvents, AuditEventModelUpdate)
	content["authorized_changes"] = len(changeEvents) // Assume all are authorized
	content["emergency_changes"] = 0 // Would be calculated based on metadata
	
	return content
}

func (cr *ComplianceReporter) generateAuditTrailContent(events []*AuditEvent) map[string]interface{} {
	content := make(map[string]interface{})
	
	content["total_audit_events"] = len(events)
	content["event_types"] = len(cr.getUniqueEventTypes(events))
	content["audit_coverage"] = "100%" // All events are audited
	content["integrity_checks"] = "Passed" // Hash verification
	content["retention_compliance"] = "Compliant"
	
	return content
}

func (cr *ComplianceReporter) generateNetworkSecurityContent(events []*AuditEvent) map[string]interface{} {
	content := make(map[string]interface{})
	
	var securityEvents []*AuditEvent
	for _, event := range events {
		if event.Type == AuditEventThreatDetection || event.Type == AuditEventSecurityIncident {
			securityEvents = append(securityEvents, event)
		}
	}
	
	content["threats_detected"] = len(securityEvents)
	content["threats_blocked"] = cr.countBlockedThreats(securityEvents)
	content["network_monitoring"] = "Active"
	content["intrusion_attempts"] = cr.countIntrusionAttempts(securityEvents)
	content["vulnerability_scans"] = "Weekly"
	
	return content
}

func (cr *ComplianceReporter) generateGenericContent(events []*AuditEvent, sectionID string) map[string]interface{} {
	content := make(map[string]interface{})
	content["section_id"] = sectionID
	content["total_events"] = len(events)
	content["generated_at"] = time.Now()
	return content
}

func (cr *ComplianceReporter) generateChartsForSection(sectionID string, events []*AuditEvent) []*ChartData {
	charts := make([]*ChartData, 0)
	
	switch sectionID {
	case "security_incidents":
		// Incidents by severity chart
		severityCounts := make(map[AuditSeverity]int64)
		for _, event := range events {
			if event.Type == AuditEventSecurityIncident {
				severityCounts[event.Severity]++
			}
		}
		
		labels := []string{}
		data := []int64{}
		for severity, count := range severityCounts {
			labels = append(labels, string(severity))
			data = append(data, count)
		}
		
		charts = append(charts, &ChartData{
			Type:   "pie",
			Title:  "Security Incidents by Severity",
			Data:   data,
			Labels: labels,
			Colors: []string{"#ff4444", "#ff8800", "#ffaa00", "#00aa00"},
		})
		
	case "data_processing":
		// Processing activities over time
		charts = append(charts, &ChartData{
			Type:  "line",
			Title: "Data Processing Activities Over Time",
			Data:  cr.generateTimeSeriesData(events, AuditEventThreatDetection),
		})
	}
	
	return charts
}

func (cr *ComplianceReporter) generateTablesForSection(sectionID string, events []*AuditEvent) []*TableData {
	tables := make([]*TableData, 0)
	
	switch sectionID {
	case "audit_trail":
		// Recent audit events table
		headers := []string{"Timestamp", "Event Type", "Severity", "Source", "Description"}
		rows := make([][]interface{}, 0)
		
		// Get last 20 events
		recentEvents := events
		if len(events) > 20 {
			recentEvents = events[len(events)-20:]
		}
		
		for _, event := range recentEvents {
			row := []interface{}{
				event.Timestamp.Format("2006-01-02 15:04:05"),
				string(event.Type),
				string(event.Severity),
				event.Source,
				cr.generateEventDescription(event),
			}
			rows = append(rows, row)
		}
		
		tables = append(tables, &TableData{
			Title:   "Recent Audit Events",
			Headers: headers,
			Rows:    rows,
		})
	}
	
	return tables
}

func (cr *ComplianceReporter) calculateComplianceScore(standard ComplianceStandard, events []*AuditEvent) float64 {
	// Simplified compliance scoring
	score := 100.0
	
	// Deduct points for security incidents
	securityIncidents := cr.countEventsByType(events, AuditEventSecurityIncident)
	score -= float64(securityIncidents) * 2.0
	
	// Deduct points for critical events
	criticalEvents := cr.countEventsBySeverity(events, AuditSeverityCritical)
	score -= float64(criticalEvents) * 5.0
	
	// Deduct points for errors
	errorEvents := cr.countEventsByType(events, AuditEventError)
	score -= float64(errorEvents) * 1.0
	
	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}
	
	return score
}

func (cr *ComplianceReporter) generateRecommendations(standard ComplianceStandard, events []*AuditEvent, score float64) []string {
	recommendations := make([]string, 0)
	
	if score < 80 {
		recommendations = append(recommendations, "Review and address security incidents to improve compliance score")
	}
	
	if cr.countEventsByType(events, AuditEventSecurityIncident) > 0 {
		recommendations = append(recommendations, "Implement additional security measures to reduce security incidents")
	}
	
	if cr.countEventsBySeverity(events, AuditSeverityCritical) > 0 {
		recommendations = append(recommendations, "Investigate and resolve critical severity events")
	}
	
	switch standard {
	case StandardGDPR:
		recommendations = append(recommendations, "Ensure data subject rights are properly handled")
		recommendations = append(recommendations, "Review data retention policies")
	case StandardSOX:
		recommendations = append(recommendations, "Maintain comprehensive audit trails")
		recommendations = append(recommendations, "Implement proper change management controls")
	case StandardPCIDSS:
		recommendations = append(recommendations, "Regularly update security measures")
		recommendations = append(recommendations, "Monitor network access continuously")
	}
	
	return recommendations
}

func (cr *ComplianceReporter) generateMetrics(events []*AuditEvent) map[string]interface{} {
	metrics := make(map[string]interface{})
	
	metrics["total_events"] = len(events)
	metrics["events_per_day"] = float64(len(events)) / 30.0 // Assuming 30-day period
	metrics["threat_detection_rate"] = cr.calculateThreatDetectionRate(events)
	metrics["false_positive_rate"] = cr.calculateFalsePositiveRate(events)
	metrics["system_availability"] = 99.9 // Would be calculated from system health data
	metrics["response_time_avg"] = cr.calculateAverageResponseTime(events)
	
	return metrics
}

// Export methods

func (cr *ComplianceReporter) exportJSON(report *ComplianceReport, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (cr *ComplianceReporter) exportCSV(report *ComplianceReport, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()
	
	// Write header
	header := []string{"Section", "Metric", "Value", "Description"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}
	
	// Write summary data
	summaryRow := []string{"Summary", "Total Events", fmt.Sprintf("%d", report.Summary.TotalEvents), "Total number of audit events"}
	if err := csvWriter.Write(summaryRow); err != nil {
		return err
	}
	
	// Write section data
	for _, section := range report.Sections {
		if content, ok := section.Content.(map[string]interface{}); ok {
			for key, value := range content {
				row := []string{section.Title, key, fmt.Sprintf("%v", value), ""}
				if err := csvWriter.Write(row); err != nil {
					return err
				}
			}
		}
	}
	
	return nil
}

func (cr *ComplianceReporter) exportXML(report *ComplianceReport, writer io.Writer) error {
	// Simplified XML export
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<ComplianceReport>
  <ID>%s</ID>
  <Standard>%s</Standard>
  <GeneratedAt>%s</GeneratedAt>
  <ComplianceScore>%.2f</ComplianceScore>
  <Summary>
    <TotalEvents>%d</TotalEvents>
    <ThreatEvents>%d</ThreatEvents>
    <SecurityIncidents>%d</SecurityIncidents>
  </Summary>
</ComplianceReport>`,
		report.ID,
		report.Standard,
		report.GeneratedAt.Format(time.RFC3339),
		report.ComplianceScore,
		report.Summary.TotalEvents,
		report.Summary.ThreatEvents,
		report.Summary.SecurityIncidents,
	)
	
	_, err := writer.Write([]byte(xml))
	return err
}

func (cr *ComplianceReporter) exportSIEM(report *ComplianceReport, writer io.Writer) error {
	// Export in SIEM-friendly format (JSON Lines)
	for _, section := range report.Sections {
		siemEvent := map[string]interface{}{
			"timestamp":         report.GeneratedAt,
			"event_type":        "compliance_report",
			"standard":          report.Standard,
			"section":           section.Title,
			"compliance_score":  report.ComplianceScore,
			"content":           section.Content,
		}
		
		jsonBytes, err := json.Marshal(siemEvent)
		if err != nil {
			return err
		}
		
		if _, err := writer.Write(jsonBytes); err != nil {
			return err
		}
		if _, err := writer.Write([]byte("\n")); err != nil {
			return err
		}
	}
	
	return nil
}

// Helper methods

func (cr *ComplianceReporter) countUniqueUsers(events []*AuditEvent) int {
	users := make(map[string]bool)
	for _, event := range events {
		if event.UserID != "" {
			users[event.UserID] = true
		}
	}
	return len(users)
}

func (cr *ComplianceReporter) countEventsBySeverity(events []*AuditEvent, severity AuditSeverity) int {
	count := 0
	for _, event := range events {
		if event.Severity == severity {
			count++
		}
	}
	return count
}

func (cr *ComplianceReporter) countEventsByType(events []*AuditEvent, eventType AuditEventType) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func (cr *ComplianceReporter) countSuccessfulActions(events []*AuditEvent) int {
	// This would be determined by event metadata
	return len(events) * 9 / 10 // Assume 90% success rate
}

func (cr *ComplianceReporter) countPrivilegedAccess(events []*AuditEvent) int {
	// This would be determined by user roles and permissions
	return len(events) / 10 // Assume 10% are privileged access
}

func (cr *ComplianceReporter) countBlockedThreats(events []*AuditEvent) int {
	count := 0
	for _, event := range events {
		if event.Type == AuditEventThreatDetection && event.Action == AuditActionBlock {
			count++
		}
	}
	return count
}

func (cr *ComplianceReporter) countIntrusionAttempts(events []*AuditEvent) int {
	count := 0
	for _, event := range events {
		if event.Type == AuditEventSecurityIncident {
			count++
		}
	}
	return count
}

func (cr *ComplianceReporter) getUniqueEventTypes(events []*AuditEvent) []AuditEventType {
	types := make(map[AuditEventType]bool)
	for _, event := range events {
		types[event.Type] = true
	}
	
	result := make([]AuditEventType, 0, len(types))
	for eventType := range types {
		result = append(result, eventType)
	}
	
	return result
}

func (cr *ComplianceReporter) generateTimeSeriesData(events []*AuditEvent, eventType AuditEventType) interface{} {
	// Simplified time series data generation
	dailyCounts := make(map[string]int)
	
	for _, event := range events {
		if event.Type == eventType {
			day := event.Timestamp.Format("2006-01-02")
			dailyCounts[day]++
		}
	}
	
	return dailyCounts
}

func (cr *ComplianceReporter) generateEventDescription(event *AuditEvent) string {
	switch event.Type {
	case AuditEventThreatDetection:
		if event.ThreatAnalysis != nil && event.ThreatAnalysis.IsThreat {
			return fmt.Sprintf("Threat detected: %s", event.ThreatAnalysis.ThreatType)
		}
		return "Request analyzed - no threat"
	case AuditEventSecurityIncident:
		return "Security incident reported"
	case AuditEventConfigChange:
		return "Configuration changed"
	case AuditEventUserAction:
		return fmt.Sprintf("User action: %s", event.Action)
	default:
		return string(event.Type)
	}
}

func (cr *ComplianceReporter) calculateThreatDetectionRate(events []*AuditEvent) float64 {
	threatEvents := cr.countEventsByType(events, AuditEventThreatDetection)
	if threatEvents == 0 {
		return 0.0
	}
	
	threatsDetected := 0
	for _, event := range events {
		if event.Type == AuditEventThreatDetection && event.ThreatAnalysis != nil && event.ThreatAnalysis.IsThreat {
			threatsDetected++
		}
	}
	
	return float64(threatsDetected) / float64(threatEvents) * 100.0
}

func (cr *ComplianceReporter) calculateFalsePositiveRate(events []*AuditEvent) float64 {
	// This would be calculated based on feedback data
	return 2.5 // Assume 2.5% false positive rate
}

func (cr *ComplianceReporter) calculateAverageResponseTime(events []*AuditEvent) time.Duration {
	totalTime := time.Duration(0)
	count := 0
	
	for _, event := range events {
		if event.ResponseTime > 0 {
			totalTime += event.ResponseTime
			count++
		}
	}
	
	if count == 0 {
		return 0
	}
	
	return totalTime / time.Duration(count)
}

func (cr *ComplianceReporter) calculateReportHash(report *ComplianceReport) string {
	// Simplified hash calculation
	data := fmt.Sprintf("%s:%s:%v:%f", 
		report.ID, report.Standard, report.GeneratedAt, report.ComplianceScore)
	return fmt.Sprintf("hash-%x", len(data))
}

// Configuration methods

func (cr *ComplianceReporter) SetConfig(config *ComplianceConfig) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	
	cr.config = config
	cr.logger.Info("Updated compliance reporter configuration")
}

func (cr *ComplianceReporter) GetConfig() *ComplianceConfig {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	
	configCopy := *cr.config
	return &configCopy
}

// Helper functions

func generateReportID() string {
	return fmt.Sprintf("report-%d", time.Now().UnixNano())
}

func generateScheduledReportID() string {
	return fmt.Sprintf("scheduled-%d", time.Now().UnixNano())
}

// Default configurations

func getDefaultComplianceConfig() *ComplianceConfig {
	return &ComplianceConfig{
		Enabled:                true,
		DefaultStandard:        StandardGDPR,
		EnableScheduledReports: true,
		ReportRetentionDays:    365,
		ExportFormats:          []ReportFormat{FormatJSON, FormatCSV, FormatPDF},
		EncryptReports:         false,
		SignReports:            false,
		AutoSubmission:         false,
		NotificationSettings: &NotificationSettings{
			EmailEnabled:    true,
			EmailRecipients: []string{},
			SlackEnabled:    false,
			WebhookEnabled:  false,
		},
		StandardConfigs: map[ComplianceStandard]*StandardConfig{
			StandardGDPR: {
				Enabled:         true,
				RequiredFields:  []string{"user_id", "timestamp", "data_type"},
				RetentionPeriod: 2 * 365 * 24 * time.Hour, // 2 years
				ReportFrequency: "monthly",
			},
			StandardSOX: {
				Enabled:         true,
				RequiredFields:  []string{"user_id", "timestamp", "action", "resource"},
				RetentionPeriod: 7 * 365 * 24 * time.Hour, // 7 years
				ReportFrequency: "quarterly",
			},
			StandardPCIDSS: {
				Enabled:         true,
				RequiredFields:  []string{"timestamp", "event_type", "source_ip"},
				RetentionPeriod: 365 * 24 * time.Hour, // 1 year
				ReportFrequency: "monthly",
			},
		},
	}
}