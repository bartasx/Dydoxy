package filter

import (
	"path/filepath"
	"regexp"
	"strings"
)

// URLMatcher matches against full URLs
type URLMatcher struct{}

func NewURLMatcher() *URLMatcher {
	return &URLMatcher{}
}

func (m *URLMatcher) Match(request *ContentRequest, rule *FilterRule) bool {
	return strings.Contains(strings.ToLower(request.URL), strings.ToLower(rule.Pattern))
}

func (m *URLMatcher) GetMatcherType() RuleType {
	return RuleTypeURL
}

// DomainMatcher matches against domains
type DomainMatcher struct{}

func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{}
}

func (m *DomainMatcher) Match(request *ContentRequest, rule *FilterRule) bool {
	domain := strings.ToLower(request.Domain)
	pattern := strings.ToLower(rule.Pattern)
	
	// Exact match
	if domain == pattern {
		return true
	}
	
	// Subdomain match (e.g., pattern "example.com" matches "sub.example.com")
	if strings.HasSuffix(domain, "."+pattern) {
		return true
	}
	
	return false
}

func (m *DomainMatcher) GetMatcherType() RuleType {
	return RuleTypeDomain
}

// KeywordMatcher matches against keywords in URL or content
type KeywordMatcher struct{}

func NewKeywordMatcher() *KeywordMatcher {
	return &KeywordMatcher{}
}

func (m *KeywordMatcher) Match(request *ContentRequest, rule *FilterRule) bool {
	keyword := strings.ToLower(rule.Pattern)
	
	// Check URL
	if strings.Contains(strings.ToLower(request.URL), keyword) {
		return true
	}
	
	// Check headers
	for key, value := range request.Headers {
		if strings.Contains(strings.ToLower(key), keyword) ||
			strings.Contains(strings.ToLower(value), keyword) {
			return true
		}
	}
	
	// Check body if available
	if len(request.Body) > 0 {
		bodyStr := strings.ToLower(string(request.Body))
		if strings.Contains(bodyStr, keyword) {
			return true
		}
	}
	
	return false
}

func (m *KeywordMatcher) GetMatcherType() RuleType {
	return RuleTypeKeyword
}

// RegexMatcher matches using regular expressions
type RegexMatcher struct {
	compiledPatterns map[string]*regexp.Regexp
}

func NewRegexMatcher() *RegexMatcher {
	return &RegexMatcher{
		compiledPatterns: make(map[string]*regexp.Regexp),
	}
}

func (m *RegexMatcher) Match(request *ContentRequest, rule *FilterRule) bool {
	// Get or compile regex pattern
	regex, exists := m.compiledPatterns[rule.Pattern]
	if !exists {
		var err error
		regex, err = regexp.Compile(rule.Pattern)
		if err != nil {
			// Invalid regex pattern, skip this rule
			return false
		}
		m.compiledPatterns[rule.Pattern] = regex
	}
	
	// Test against URL
	if regex.MatchString(request.URL) {
		return true
	}
	
	// Test against domain
	if regex.MatchString(request.Domain) {
		return true
	}
	
	// Test against body if available
	if len(request.Body) > 0 {
		if regex.Match(request.Body) {
			return true
		}
	}
	
	return false
}

func (m *RegexMatcher) GetMatcherType() RuleType {
	return RuleTypeRegex
}

// ContentTypeMatcher matches against content types
type ContentTypeMatcher struct{}

func NewContentTypeMatcher() *ContentTypeMatcher {
	return &ContentTypeMatcher{}
}

func (m *ContentTypeMatcher) Match(request *ContentRequest, rule *FilterRule) bool {
	contentType := strings.ToLower(request.ContentType)
	pattern := strings.ToLower(rule.Pattern)
	
	// Check main content type (e.g., "image/jpeg" matches "image")
	if strings.HasPrefix(contentType, pattern) {
		return true
	}
	
	// Check exact match
	if contentType == pattern {
		return true
	}
	
	// Check Content-Type header if ContentType field is empty
	if contentType == "" {
		if ctHeader, exists := request.Headers["Content-Type"]; exists {
			contentType = strings.ToLower(ctHeader)
			if strings.HasPrefix(contentType, pattern) || contentType == pattern {
				return true
			}
		}
	}
	
	return false
}

func (m *ContentTypeMatcher) GetMatcherType() RuleType {
	return RuleTypeContentType
}

// FileExtensionMatcher matches against file extensions
type FileExtensionMatcher struct{}

func NewFileExtensionMatcher() *FileExtensionMatcher {
	return &FileExtensionMatcher{}
}

func (m *FileExtensionMatcher) Match(request *ContentRequest, rule *FilterRule) bool {
	// Extract file extension from URL
	ext := strings.ToLower(filepath.Ext(request.URL))
	pattern := strings.ToLower(rule.Pattern)
	
	// Ensure pattern starts with dot
	if !strings.HasPrefix(pattern, ".") {
		pattern = "." + pattern
	}
	
	return ext == pattern
}

func (m *FileExtensionMatcher) GetMatcherType() RuleType {
	return RuleTypeFileExtension
}