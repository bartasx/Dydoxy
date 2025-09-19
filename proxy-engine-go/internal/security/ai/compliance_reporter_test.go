package ai

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestComplianceReporter() (*ComplianceReporter, *MockAuditStorage) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	
	storage := &MockAuditStorage{}
	threatDetector := &MockAIThreatDetector{}
	
	reporter := NewComplianceReporter(storage, threatDetector, logger)
	
	return reporter, storage
}

func createTestAuditEvents() []*AuditEvent {
	now := time.Now()
	
	return []*AuditEvent{
		{
			ID:        "event-1",
			Timestamp: now.Add(-24 * time.Hour),
			Type:      AuditEventThreatDetection,
			Severity:  AuditSeverityWarning,
			Action:    AuditActionAnalyze,
			Source:    "ai_threat_detector",
			UserID:    "user123",
			ClientIP:  "192.168.1.1",
			ThreatAnalysis: &ThreatAnalysisResult{
				IsThreat:    true,
				ThreatType:  ThreatTypeMalware,
				ThreatLevel: ThreatLevelHigh,
				Confidence:  0.9,
			},
			ResponseTime: 100 * time.Millisecond,
		},
		{
			ID:        "event-2",
			Timestamp: now.Add(-12 * time.Hour),
			Type:      AuditEventSecurityIncident,
			Severity:  AuditSeverityCritical,
			Action:    AuditActionBlock,
			Source:    "security_monitor",
			UserID:    "user456",
			ClientIP:  "192.168.1.2",
		},
		{
			ID:        "event-3",
			Timestamp: now.Add(-6 * time.Hour),
			Type:      AuditEventConfigChange,
			Severity:  AuditSeverityWarning,
			Action:    AuditActionConfigChange,
			Source:    "admin_panel",
			UserID:    "admin123",
			ConfigChanges: map[string]interface{}{
				"threat_threshold": map[string]interface{}{
					"old": 0.7,
					"new": 0.8,
				},
			},
		},
		{
			ID:        "event-4",
			Timestamp: now.Add(-3 * time.Hour),
			Type:      AuditEventUserAction,
			Severity:  AuditSeverityInfo,
			Action:    AuditActionLogin,
			Source:    "user_interface",
			UserID:    "user789",
			ClientIP:  "192.168.1.3",
		},
		{
			ID:        "event-5",
			Timestamp: now.Add(-1 * time.Hour),
			Type:      AuditEventError,
			Severity:  AuditSeverityError,
			Action:    AuditActionRead,
			Source:    "model_manager",
			ErrorDetails: &ErrorDetails{
				ErrorType:    "training_error",
				ErrorMessage: "Failed to load model",
			},
		},
	}
}

func TestComplianceReporter_Creation(t *testing.T) {
	logger := logrus.New()
	storage := &MockAuditStorage{}
	threatDetector := &MockAIThreatDetector{}
	
	reporter := NewComplianceReporter(storage, threatDetector, logger)
	
	assert.NotNil(t, reporter)
	assert.NotNil(t, reporter.config)
	assert.NotNil(t, reporter.templates)
	assert.NotNil(t, reporter.scheduledReports)
	assert.True(t, reporter.config.Enabled)
	
	// Check that templates were initialized
	assert.Contains(t, reporter.templates, StandardGDPR)
	assert.Contains(t, reporter.templates, StandardSOX)
	assert.Contains(t, reporter.templates, StandardPCIDSS)
}

func TestComplianceReporter_GenerateReport_GDPR(t *testing.T) {
	reporter, storage := setupTestComplianceReporter()
	
	events := createTestAuditEvents()
	period := ReportPeriod{
		StartTime: time.Now().Add(-30 * 24 * time.Hour),
		EndTime:   time.Now(),
		Type:      "monthly",
	}
	
	// Mock storage call
	storage.On("LoadAuditEvents", context.Background(), 
		&AuditFilter{StartTime: period.StartTime, EndTime: period.EndTime}, 
		10000, 0).Return(events, nil)
	
	report, err := reporter.GenerateReport(context.Background(), StandardGDPR, period, FormatJSON)
	require.NoError(t, err)
	
	assert.NotNil(t, report)
	assert.Equal(t, StandardGDPR, report.Standard)
	assert.Equal(t, FormatJSON, report.Format)
	assert.Equal(t, StatusCompleted, report.Status)
	assert.NotEmpty(t, report.ID)
	assert.Contains(t, report.Title, "GDPR")
	
	// Check summary
	assert.NotNil(t, report.Summary)
	assert.Equal(t, int64(5), report.Summary.TotalEvents)
	assert.Equal(t, int64(1), report.Summary.ThreatEvents)
	assert.Equal(t, int64(1), report.Summary.SecurityIncidents)
	assert.Equal(t, int64(1), report.Summary.ConfigChanges)
	assert.Equal(t, int64(1), report.Summary.UserActions)
	
	// Check sections
	assert.NotEmpty(t, report.Sections)
	sectionTitles := make([]string, len(report.Sections))
	for i, section := range report.Sections {
		sectionTitles[i] = section.Title
	}
	assert.Contains(t, sectionTitles, "Data Processing Activities")
	assert.Contains(t, sectionTitles, "Security Incidents")
	
	// Check compliance score
	assert.Greater(t, report.ComplianceScore, 0.0)
	assert.LessOrEqual(t, report.ComplianceScore, 100.0)
	
	// Check recommendations
	assert.NotEmpty(t, report.Recommendations)
	
	// Check metrics
	assert.NotEmpty(t, report.Metrics)
	assert.Contains(t, report.Metrics, "total_events")
	
	storage.AssertExpectations(t)
}

func TestComplianceReporter_GenerateReport_SOX(t *testing.T) {
	reporter, storage := setupTestComplianceReporter()
	
	events := createTestAuditEvents()
	period := ReportPeriod{
		StartTime: time.Now().Add(-90 * 24 * time.Hour),
		EndTime:   time.Now(),
		Type:      "quarterly",
	}
	
	// Mock storage call
	storage.On("LoadAuditEvents", context.Background(), 
		&AuditFilter{StartTime: period.StartTime, EndTime: period.EndTime}, 
		10000, 0).Return(events, nil)
	
	report, err := reporter.GenerateReport(context.Background(), StandardSOX, period, FormatCSV)
	require.NoError(t, err)
	
	assert.NotNil(t, report)
	assert.Equal(t, StandardSOX, report.Standard)
	assert.Equal(t, FormatCSV, report.Format)
	assert.Contains(t, report.Title, "SOX")
	
	// Check SOX-specific sections
	sectionTitles := make([]string, len(report.Sections))
	for i, section := range report.Sections {
		sectionTitles[i] = section.Title
	}
	assert.Contains(t, sectionTitles, "Access Controls")
	assert.Contains(t, sectionTitles, "Change Management")
	assert.Contains(t, sectionTitles, "Audit Trail")
	
	storage.AssertExpectations(t)
}

func TestComplianceReporter_GenerateReport_PCIDSS(t *testing.T) {
	reporter, storage := setupTestComplianceReporter()
	
	events := createTestAuditEvents()
	period := ReportPeriod{
		StartTime: time.Now().Add(-30 * 24 * time.Hour),
		EndTime:   time.Now(),
		Type:      "monthly",
	}
	
	// Mock storage call
	storage.On("LoadAuditEvents", context.Background(), 
		&AuditFilter{StartTime: period.StartTime, EndTime: period.EndTime}, 
		10000, 0).Return(events, nil)
	
	report, err := reporter.GenerateReport(context.Background(), StandardPCIDSS, period, FormatXML)
	require.NoError(t, err)
	
	assert.NotNil(t, report)
	assert.Equal(t, StandardPCIDSS, report.Standard)
	assert.Equal(t, FormatXML, report.Format)
	assert.Contains(t, report.Title, "PCI-DSS")
	
	// Check PCI-DSS-specific sections
	sectionTitles := make([]string, len(report.Sections))
	for i, section := range report.Sections {
		sectionTitles[i] = section.Title
	}
	assert.Contains(t, sectionTitles, "Network Security")
	assert.Contains(t, sectionTitles, "Access Control Measures")
	assert.Contains(t, sectionTitles, "Vulnerability Management")
	
	storage.AssertExpectations(t)
}

func TestComplianceReporter_GenerateReport_Disabled(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	// Disable compliance reporting
	config := reporter.GetConfig()
	config.Enabled = false
	reporter.SetConfig(config)
	
	period := ReportPeriod{
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
		Type:      "daily",
	}
	
	report, err := reporter.GenerateReport(context.Background(), StandardGDPR, period, FormatJSON)
	assert.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "disabled")
}

func TestComplianceReporter_ExportReport_JSON(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	report := &ComplianceReport{
		ID:              "test-report-1",
		Standard:        StandardGDPR,
		Title:           "Test GDPR Report",
		GeneratedAt:     time.Now(),
		Format:          FormatJSON,
		ComplianceScore: 85.5,
		Summary: &ComplianceSummary{
			TotalEvents:      100,
			ThreatEvents:     10,
			SecurityIncidents: 2,
		},
		Sections: []*ReportSection{
			{
				ID:    "test-section",
				Title: "Test Section",
				Content: map[string]interface{}{
					"test_metric": 42,
				},
			},
		},
		Status: StatusCompleted,
	}
	
	var buffer bytes.Buffer
	err := reporter.ExportReport(context.Background(), report, &buffer)
	require.NoError(t, err)
	
	output := buffer.String()
	assert.Contains(t, output, "test-report-1")
	assert.Contains(t, output, "GDPR")
	assert.Contains(t, output, "85.5")
	assert.Contains(t, output, "Test Section")
}

func TestComplianceReporter_ExportReport_CSV(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	report := &ComplianceReport{
		ID:       "test-report-2",
		Standard: StandardSOX,
		Format:   FormatCSV,
		Summary: &ComplianceSummary{
			TotalEvents: 50,
		},
		Sections: []*ReportSection{
			{
				Title: "Access Controls",
				Content: map[string]interface{}{
					"total_logins":    100,
					"failed_attempts": 5,
				},
			},
		},
	}
	
	var buffer bytes.Buffer
	err := reporter.ExportReport(context.Background(), report, &buffer)
	require.NoError(t, err)
	
	output := buffer.String()
	lines := strings.Split(output, "\n")
	
	// Check CSV header
	assert.Contains(t, lines[0], "Section,Metric,Value,Description")
	
	// Check data rows
	assert.Contains(t, output, "Summary,Total Events,50")
	assert.Contains(t, output, "Access Controls,total_logins,100")
	assert.Contains(t, output, "Access Controls,failed_attempts,5")
}

func TestComplianceReporter_ExportReport_XML(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	report := &ComplianceReport{
		ID:              "test-report-3",
		Standard:        StandardPCIDSS,
		Format:          FormatXML,
		GeneratedAt:     time.Now(),
		ComplianceScore: 92.0,
		Summary: &ComplianceSummary{
			TotalEvents:       200,
			ThreatEvents:      15,
			SecurityIncidents: 1,
		},
	}
	
	var buffer bytes.Buffer
	err := reporter.ExportReport(context.Background(), report, &buffer)
	require.NoError(t, err)
	
	output := buffer.String()
	assert.Contains(t, output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	assert.Contains(t, output, "<ComplianceReport>")
	assert.Contains(t, output, "<ID>test-report-3</ID>")
	assert.Contains(t, output, "<Standard>PCI-DSS</Standard>")
	assert.Contains(t, output, "<ComplianceScore>92.00</ComplianceScore>")
	assert.Contains(t, output, "<TotalEvents>200</TotalEvents>")
}

func TestComplianceReporter_ExportReport_SIEM(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	report := &ComplianceReport{
		ID:              "test-report-4",
		Standard:        StandardGDPR,
		Format:          FormatSIEM,
		GeneratedAt:     time.Now(),
		ComplianceScore: 88.0,
		Sections: []*ReportSection{
			{
				Title: "Data Processing",
				Content: map[string]interface{}{
					"processing_activities": 25,
				},
			},
			{
				Title: "Security Incidents",
				Content: map[string]interface{}{
					"total_incidents": 3,
				},
			},
		},
	}
	
	var buffer bytes.Buffer
	err := reporter.ExportReport(context.Background(), report, &buffer)
	require.NoError(t, err)
	
	output := buffer.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	// Should have one line per section
	assert.Equal(t, 2, len(lines))
	
	// Each line should be valid JSON
	for _, line := range lines {
		assert.True(t, strings.HasPrefix(line, "{"))
		assert.True(t, strings.HasSuffix(line, "}"))
		assert.Contains(t, line, "compliance_report")
		assert.Contains(t, line, "GDPR")
	}
}

func TestComplianceReporter_ScheduleReport(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	scheduledReport := &ScheduledReport{
		Name:       "Monthly GDPR Report",
		Standard:   StandardGDPR,
		Schedule:   "0 0 1 * *", // First day of every month
		Format:     FormatJSON,
		Recipients: []string{"compliance@example.com"},
		Enabled:    true,
		Config:     map[string]interface{}{"include_charts": true},
	}
	
	err := reporter.ScheduleReport(context.Background(), scheduledReport)
	require.NoError(t, err)
	
	assert.NotEmpty(t, scheduledReport.ID)
	
	// Check that report was added to scheduled reports
	scheduledReports := reporter.GetScheduledReports()
	assert.Len(t, scheduledReports, 1)
	assert.Equal(t, "Monthly GDPR Report", scheduledReports[0].Name)
	assert.Equal(t, StandardGDPR, scheduledReports[0].Standard)
}

func TestComplianceReporter_ScheduleReport_Disabled(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	// Disable scheduled reports
	config := reporter.GetConfig()
	config.EnableScheduledReports = false
	reporter.SetConfig(config)
	
	scheduledReport := &ScheduledReport{
		Name:     "Test Report",
		Standard: StandardSOX,
		Schedule: "0 0 * * 0", // Weekly
		Format:   FormatCSV,
		Enabled:  true,
	}
	
	err := reporter.ScheduleReport(context.Background(), scheduledReport)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestComplianceReporter_ComplianceScoreCalculation(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	tests := []struct {
		name           string
		events         []*AuditEvent
		expectedScore  float64
		expectedRange  bool // true if we just check range
	}{
		{
			name:          "no events",
			events:        []*AuditEvent{},
			expectedScore: 100.0,
		},
		{
			name: "with security incidents",
			events: []*AuditEvent{
				{Type: AuditEventSecurityIncident, Severity: AuditSeverityError},
				{Type: AuditEventSecurityIncident, Severity: AuditSeverityError},
			},
			expectedScore: 96.0, // 100 - (2 * 2)
		},
		{
			name: "with critical events",
			events: []*AuditEvent{
				{Type: AuditEventError, Severity: AuditSeverityCritical},
			},
			expectedScore: 95.0, // 100 - (1 * 5)
		},
		{
			name: "mixed events",
			events: []*AuditEvent{
				{Type: AuditEventSecurityIncident, Severity: AuditSeverityError},
				{Type: AuditEventError, Severity: AuditSeverityCritical},
				{Type: AuditEventError, Severity: AuditSeverityError},
			},
			expectedScore: 92.0, // 100 - 2 - 5 - 1
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := reporter.calculateComplianceScore(StandardGDPR, tt.events)
			if tt.expectedRange {
				assert.GreaterOrEqual(t, score, 0.0)
				assert.LessOrEqual(t, score, 100.0)
			} else {
				assert.Equal(t, tt.expectedScore, score)
			}
		})
	}
}

func TestComplianceReporter_RecommendationGeneration(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	tests := []struct {
		name                 string
		standard             ComplianceStandard
		events               []*AuditEvent
		score                float64
		expectedRecommendations []string
	}{
		{
			name:     "low score",
			standard: StandardGDPR,
			events:   []*AuditEvent{},
			score:    70.0,
			expectedRecommendations: []string{
				"Review and address security incidents to improve compliance score",
				"Ensure data subject rights are properly handled",
				"Review data retention policies",
			},
		},
		{
			name:     "with security incidents",
			standard: StandardSOX,
			events: []*AuditEvent{
				{Type: AuditEventSecurityIncident},
			},
			score: 90.0,
			expectedRecommendations: []string{
				"Implement additional security measures to reduce security incidents",
				"Maintain comprehensive audit trails",
				"Implement proper change management controls",
			},
		},
		{
			name:     "with critical events",
			standard: StandardPCIDSS,
			events: []*AuditEvent{
				{Type: AuditEventError, Severity: AuditSeverityCritical},
			},
			score: 85.0,
			expectedRecommendations: []string{
				"Investigate and resolve critical severity events",
				"Regularly update security measures",
				"Monitor network access continuously",
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recommendations := reporter.generateRecommendations(tt.standard, tt.events, tt.score)
			
			for _, expected := range tt.expectedRecommendations {
				assert.Contains(t, recommendations, expected)
			}
		})
	}
}

func TestComplianceReporter_SummaryGeneration(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	events := createTestAuditEvents()
	summary := reporter.generateSummary(events)
	
	assert.NotNil(t, summary)
	assert.Equal(t, int64(5), summary.TotalEvents)
	assert.Equal(t, int64(1), summary.ThreatEvents)
	assert.Equal(t, int64(1), summary.SecurityIncidents)
	assert.Equal(t, int64(1), summary.ConfigChanges)
	assert.Equal(t, int64(1), summary.UserActions)
	
	// Check event counts by type
	assert.Equal(t, int64(1), summary.EventsByType[AuditEventThreatDetection])
	assert.Equal(t, int64(1), summary.EventsByType[AuditEventSecurityIncident])
	assert.Equal(t, int64(1), summary.EventsByType[AuditEventConfigChange])
	assert.Equal(t, int64(1), summary.EventsByType[AuditEventUserAction])
	assert.Equal(t, int64(1), summary.EventsByType[AuditEventError])
	
	// Check event counts by severity
	assert.Equal(t, int64(1), summary.EventsBySeverity[AuditSeverityInfo])
	assert.Equal(t, int64(2), summary.EventsBySeverity[AuditSeverityWarning])
	assert.Equal(t, int64(1), summary.EventsBySeverity[AuditSeverityError])
	assert.Equal(t, int64(1), summary.EventsBySeverity[AuditSeverityCritical])
	
	// Check top threats
	assert.Len(t, summary.TopThreats, 1)
	assert.Equal(t, ThreatTypeMalware, summary.TopThreats[0].ThreatType)
	assert.Equal(t, int64(1), summary.TopThreats[0].Count)
	assert.Equal(t, 100.0, summary.TopThreats[0].Percentage)
}

func TestComplianceReporter_Configuration(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	// Test default configuration
	config := reporter.GetConfig()
	assert.True(t, config.Enabled)
	assert.Equal(t, StandardGDPR, config.DefaultStandard)
	assert.True(t, config.EnableScheduledReports)
	assert.Equal(t, 365, config.ReportRetentionDays)
	assert.Contains(t, config.ExportFormats, FormatJSON)
	assert.Contains(t, config.ExportFormats, FormatCSV)
	
	// Test configuration update
	newConfig := &ComplianceConfig{
		Enabled:                false,
		DefaultStandard:        StandardSOX,
		EnableScheduledReports: false,
		ReportRetentionDays:    180,
		ExportFormats:          []ReportFormat{FormatJSON},
		EncryptReports:         true,
		SignReports:            true,
	}
	
	reporter.SetConfig(newConfig)
	updatedConfig := reporter.GetConfig()
	
	assert.False(t, updatedConfig.Enabled)
	assert.Equal(t, StandardSOX, updatedConfig.DefaultStandard)
	assert.False(t, updatedConfig.EnableScheduledReports)
	assert.Equal(t, 180, updatedConfig.ReportRetentionDays)
	assert.Equal(t, []ReportFormat{FormatJSON}, updatedConfig.ExportFormats)
	assert.True(t, updatedConfig.EncryptReports)
	assert.True(t, updatedConfig.SignReports)
}

func TestComplianceReporter_HelperMethods(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	events := createTestAuditEvents()
	
	// Test countUniqueUsers
	uniqueUsers := reporter.countUniqueUsers(events)
	assert.Equal(t, 4, uniqueUsers) // user123, user456, admin123, user789
	
	// Test countEventsBySeverity
	criticalEvents := reporter.countEventsBySeverity(events, AuditSeverityCritical)
	assert.Equal(t, 1, criticalEvents)
	
	warningEvents := reporter.countEventsBySeverity(events, AuditSeverityWarning)
	assert.Equal(t, 2, warningEvents)
	
	// Test countEventsByType
	threatEvents := reporter.countEventsByType(events, AuditEventThreatDetection)
	assert.Equal(t, 1, threatEvents)
	
	configEvents := reporter.countEventsByType(events, AuditEventConfigChange)
	assert.Equal(t, 1, configEvents)
	
	// Test getUniqueEventTypes
	uniqueTypes := reporter.getUniqueEventTypes(events)
	assert.Len(t, uniqueTypes, 5)
	assert.Contains(t, uniqueTypes, AuditEventThreatDetection)
	assert.Contains(t, uniqueTypes, AuditEventSecurityIncident)
	assert.Contains(t, uniqueTypes, AuditEventConfigChange)
	assert.Contains(t, uniqueTypes, AuditEventUserAction)
	assert.Contains(t, uniqueTypes, AuditEventError)
}

func TestComplianceReporter_MetricsGeneration(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	events := createTestAuditEvents()
	metrics := reporter.generateMetrics(events)
	
	assert.NotNil(t, metrics)
	assert.Equal(t, 5, metrics["total_events"])
	assert.Contains(t, metrics, "events_per_day")
	assert.Contains(t, metrics, "threat_detection_rate")
	assert.Contains(t, metrics, "false_positive_rate")
	assert.Contains(t, metrics, "system_availability")
	assert.Contains(t, metrics, "response_time_avg")
	
	// Check that values are reasonable
	eventsPerDay := metrics["events_per_day"].(float64)
	assert.Greater(t, eventsPerDay, 0.0)
	
	threatDetectionRate := metrics["threat_detection_rate"].(float64)
	assert.GreaterOrEqual(t, threatDetectionRate, 0.0)
	assert.LessOrEqual(t, threatDetectionRate, 100.0)
	
	systemAvailability := metrics["system_availability"].(float64)
	assert.Equal(t, 99.9, systemAvailability)
}

func TestComplianceReporter_UnsupportedExportFormat(t *testing.T) {
	reporter, _ := setupTestComplianceReporter()
	
	report := &ComplianceReport{
		ID:     "test-report",
		Format: ReportFormat("unsupported"),
	}
	
	var buffer bytes.Buffer
	err := reporter.ExportReport(context.Background(), report, &buffer)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported export format")
}