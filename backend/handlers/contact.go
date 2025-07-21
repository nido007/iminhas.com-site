// backend/handlers/contact.go
// Contact form handler with Gmail STARTTLS support
package handlers

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"time"
)

// ContactSubmission represents a contact form submission
type ContactSubmission struct {
	FirstName   string    `json:"firstName"`
	LastName    string    `json:"lastName"`
	Email       string    `json:"email"`
	Company     string    `json:"company"`
	ProjectType string    `json:"projectType"`
	Budget      string    `json:"budget"`
	Timeline    string    `json:"timeline"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	UserAgent   string    `json:"userAgent"`
	IPAddress   string    `json:"ipAddress"`
}

// EmailConfig holds SMTP configuration for Gmail
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	ToEmail      string
	FromName     string
}

// ContactFormHandler handles contact form submissions with Gmail SMTP
func ContactFormHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔍 ContactFormHandler called - Method: %s, URL: %s", r.Method, r.URL.Path)
	log.Printf("🔍 Content-Type: %s", r.Header.Get("Content-Type"))

	// Set CORS headers for all responses
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		log.Printf("✅ CORS preflight request handled")
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		log.Printf("❌ Invalid method: %s", r.Method)
		writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Add defer to catch any panics
	defer func() {
		if r := recover(); r != nil {
			log.Printf("🚨 PANIC in ContactFormHandler: %v", r)
			writeErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		}
	}()

	// Parse and validate form data
	submission, err := parseContactForm(r)
	if err != nil {
		log.Printf("❌ Form parsing error: %v", err)
		writeErrorResponse(w, "Invalid form data: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("✅ Form parsing completed successfully")

	// Debug: Log all received form data
	log.Printf("📝 Received form data:")
	log.Printf("   FirstName: '%s' (length: %d)", submission.FirstName, len(submission.FirstName))
	log.Printf("   LastName: '%s' (length: %d)", submission.LastName, len(submission.LastName))
	log.Printf("   Email: '%s'", submission.Email)
	log.Printf("   Company: '%s'", submission.Company)
	log.Printf("   ProjectType: '%s'", submission.ProjectType)
	log.Printf("   Budget: '%s'", submission.Budget)
	log.Printf("   Timeline: '%s'", submission.Timeline)
	log.Printf("   Message: '%s' (length: %d)", truncateString(submission.Message, 50), len(submission.Message))

	// Validate submission
	log.Printf("🔍 Starting validation...")
	if err := validateSubmission(submission); err != nil {
		log.Printf("❌ Validation error: %v", err)
		writeErrorResponse(w, "Validation failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("✅ Validation completed successfully")

	// Basic spam protection
	log.Printf("🔍 Checking for spam...")
	if isSpamSubmission(submission) {
		log.Printf("🚫 Spam detected from IP: %s", submission.IPAddress)
		writeErrorResponse(w, "Submission rejected", http.StatusTooManyRequests)
		return
	}
	log.Printf("✅ Spam check passed")

	// Check email configuration
	log.Printf("🔍 Checking email configuration...")
	emailConfig := getEmailConfig()
	if !isEmailConfigured(emailConfig) {
		log.Printf("⚠️ Email not configured, saving submission only")
		log.Printf("📧 SMTP_USER: %s", emailConfig.SMTPUser)
		log.Printf("📧 SMTP_PASS: %s", maskPassword(emailConfig.SMTPPassword))
		
		if err := saveSubmission(submission); err != nil {
			log.Printf("❌ Failed to save submission: %v", err)
			writeErrorResponse(w, "Failed to process submission", http.StatusInternalServerError)
			return
		}
		writeSuccessResponse(w, map[string]interface{}{
			"success": true,
			"message": "Thank you for your message! (Email not configured - message saved locally)",
			"id":      fmt.Sprintf("msg_%d", time.Now().Unix()),
		})
		return
	}
	log.Printf("✅ Email configuration valid")

	// Send email notification
	log.Printf("🔍 Starting email sending process...")
	if err := sendContactEmail(submission, emailConfig); err != nil {
		log.Printf("❌ Email sending failed: %v", err)
		// Still save the submission even if email fails
		if saveErr := saveSubmission(submission); saveErr != nil {
			log.Printf("❌ Also failed to save submission: %v", saveErr)
		}
		writeErrorResponse(w, "Failed to send message. Please try again later.", http.StatusInternalServerError)
		return
	}
	log.Printf("✅ Email sent successfully")

	// Save submission for record keeping
	log.Printf("🔍 Saving submission...")
	if err := saveSubmission(submission); err != nil {
		log.Printf("⚠️ Failed to save submission: %v", err)
		// Don't fail the request, just log the error
	}
	log.Printf("✅ Submission saved")

	// Log successful submission
	log.Printf("✅ 📮 Contact form submitted successfully from %s (%s %s)",
		submission.IPAddress, submission.FirstName, submission.LastName)

	// Return success response
	writeSuccessResponse(w, map[string]interface{}{
		"success": true,
		"message": "Thank you for your message! I'll get back to you within 24 hours.",
		"id":      fmt.Sprintf("msg_%d", time.Now().Unix()),
	})
}

// parseContactForm extracts form data from HTTP request
func parseContactForm(r *http.Request) (*ContactSubmission, error) {
	log.Printf("🔍 Parsing form data...")

	// Parse form data - handles both URL-encoded and multipart forms
	if err := r.ParseForm(); err != nil {
		log.Printf("❌ ParseForm failed: %v", err)
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}

	// Also try multipart form
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		log.Printf("⚠️ ParseMultipartForm failed (this is ok if not multipart): %v", err)
	}

	// Debug: Log all form values received
	log.Printf("🔍 All form values received:")
	for key, values := range r.Form {
		log.Printf("   %s: %v", key, values)
	}

	// Extract client information
	userAgent := r.Header.Get("User-Agent")
	ipAddress := getClientIP(r)

	submission := &ContactSubmission{
		FirstName:   strings.TrimSpace(r.FormValue("firstName")),
		LastName:    strings.TrimSpace(r.FormValue("lastName")),
		Email:       strings.TrimSpace(strings.ToLower(r.FormValue("email"))),
		Company:     strings.TrimSpace(r.FormValue("company")),
		ProjectType: strings.TrimSpace(r.FormValue("projectType")),
		Budget:      strings.TrimSpace(r.FormValue("budget")),
		Timeline:    strings.TrimSpace(r.FormValue("timeline")),
		Message:     strings.TrimSpace(r.FormValue("message")),
		Timestamp:   time.Now(),
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
	}

	return submission, nil
}

// validateSubmission performs comprehensive validation
func validateSubmission(s *ContactSubmission) error {
	log.Printf("🔍 Validating submission...")

	// Required field validation
	if s.FirstName == "" {
		return fmt.Errorf("first name is required")
	}
	if s.LastName == "" {
		return fmt.Errorf("last name is required")
	}
	if s.Email == "" {
		return fmt.Errorf("email is required")
	}
	if s.ProjectType == "" {
		return fmt.Errorf("project type is required")
	}
	if s.Message == "" {
		return fmt.Errorf("message is required")
	}

	// Length validation
	if len(s.FirstName) < 2 || len(s.FirstName) > 50 {
		return fmt.Errorf("first name must be between 2 and 50 characters (current: %d)", len(s.FirstName))
	}
	if len(s.LastName) < 2 || len(s.LastName) > 50 {
		return fmt.Errorf("last name must be between 2 and 50 characters (current: %d)", len(s.LastName))
	}
	if len(s.Company) > 100 {
		return fmt.Errorf("company name too long (max 100 characters, current: %d)", len(s.Company))
	}
	if len(s.Message) < 10 || len(s.Message) > 1000 {
		return fmt.Errorf("message must be between 10 and 1000 characters (current: %d)", len(s.Message))
	}

	// Email format validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(s.Email) {
		return fmt.Errorf("invalid email format: %s", s.Email)
	}

	// Valid project types - Updated to match your form exactly
	validProjectTypes := map[string]bool{
		"Web Development":     true,
		"Backend API":         true,
		"Go Microservices":    true,
		"Database Design":     true,
		"DevOps/Deployment":   true,
		"Consulting":          true,
		"Code Review":         true,
		"Other":               true,
	}
	if !validProjectTypes[s.ProjectType] {
		return fmt.Errorf("invalid project type: '%s'. Valid options: %v", s.ProjectType, getValidProjectTypes())
	}

	return nil
}

// getValidProjectTypes returns a list of valid project types
func getValidProjectTypes() []string {
	return []string{
		"Web Development", "Backend API", "Go Microservices",
		"Database Design", "DevOps/Deployment", "Consulting",
		"Code Review", "Other",
	}
}

// isSpamSubmission performs basic spam detection
func isSpamSubmission(s *ContactSubmission) bool {
	// Check for suspicious email domains
	suspiciousDomains := []string{
		"10minutemail.com", "tempmail.org", "guerrillamail.com",
		"mailinator.com", "throwaway.email", "temp-mail.org",
	}

	for _, domain := range suspiciousDomains {
		if strings.Contains(s.Email, domain) {
			return true
		}
	}

	// Check for duplicate content patterns
	if s.FirstName == s.LastName || s.FirstName == s.Company {
		return true
	}

	return false
}

// sendContactEmail sends beautiful HTML email via Gmail SMTP with STARTTLS
func sendContactEmail(submission *ContactSubmission, config EmailConfig) error {
	log.Printf("📧 Preparing to send email via Gmail SMTP...")

	// Create beautiful HTML email template
	emailTemplate := `Subject: 🔔 New Contact: {{.ProjectType}} - {{.FirstName}} {{.LastName}}
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
From: {{.FromName}} <{{.SMTPUser}}>
To: {{.ToEmail}}
Reply-To: {{.Email}}

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>New Contact Form Submission</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 24px; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .content { padding: 30px 20px; }
        .field { margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #667eea; }
        .field-label { font-weight: 600; color: #495057; margin-bottom: 5px; display: block; }
        .field-value { color: #212529; font-size: 16px; }
        .message-field { background: #e3f2fd; border-left-color: #2196f3; }
        .message-field .field-value { font-style: italic; white-space: pre-wrap; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; border-top: 1px solid #dee2e6; }
        .footer p { margin: 5px 0; font-size: 12px; color: #6c757d; }
        .highlight { background: #fff3cd; padding: 10px; border-radius: 5px; border-left: 4px solid #ffc107; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 New Project Inquiry</h1>
            <p>Contact form submission from iminhas.com</p>
        </div>
        
        <div class="content">
            <div class="field">
                <span class="field-label">👤 Client Name</span>
                <div class="field-value">{{.FirstName}} {{.LastName}}</div>
            </div>
            
            <div class="field">
                <span class="field-label">📧 Email Address</span>
                <div class="field-value"><a href="mailto:{{.Email}}">{{.Email}}</a></div>
            </div>
            
            {{if .Company}}
            <div class="field">
                <span class="field-label">🏢 Company</span>
                <div class="field-value">{{.Company}}</div>
            </div>
            {{end}}
            
            <div class="highlight">
                <div class="field-label">📋 Project Type</div>
                <div class="field-value"><strong>{{.ProjectType}}</strong></div>
            </div>
            
            {{if .Budget}}
            <div class="field">
                <span class="field-label">💰 Budget Range</span>
                <div class="field-value">{{.Budget}}</div>
            </div>
            {{end}}
            
            {{if .Timeline}}
            <div class="field">
                <span class="field-label">📅 Timeline</span>
                <div class="field-value">{{.Timeline}}</div>
            </div>
            {{end}}
            
            <div class="field message-field">
                <span class="field-label">💬 Project Details</span>
                <div class="field-value">{{.Message}}</div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>📅 Submitted:</strong> {{.Timestamp.Format "Monday, January 2, 2006 at 3:04 PM MST"}}</p>
            <p><strong>🌐 IP Address:</strong> {{.IPAddress}}</p>
            <p><strong>🔗 Source:</strong> iminhas.com contact form</p>
            <p style="margin-top: 15px;">
                <a href="mailto:{{.Email}}" style="background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reply to {{.FirstName}}</a>
            </p>
        </div>
    </div>
</body>
</html>`

	// Parse template
	tmpl, err := template.New("email").Parse(emailTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	// Prepare template data
	templateData := struct {
		*ContactSubmission
		SMTPUser string
		ToEmail  string
		FromName string
	}{
		ContactSubmission: submission,
		SMTPUser:          config.SMTPUser,
		ToEmail:           config.ToEmail,
		FromName:          config.FromName,
	}

	// Execute template
	var emailBody strings.Builder
	if err := tmpl.Execute(&emailBody, templateData); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	// Send email via SMTP with STARTTLS
	return sendSMTPEmailWithSTARTTLS(config, emailBody.String())
}

// sendSMTPEmailWithSTARTTLS sends email using Gmail SMTP with STARTTLS
func sendSMTPEmailWithSTARTTLS(config EmailConfig, emailBody string) error {
	log.Printf("📧 Connecting to Gmail SMTP with STARTTLS...")

	// Gmail SMTP authentication
	auth := smtp.PlainAuth("", config.SMTPUser, config.SMTPPassword, config.SMTPHost)

	// For Gmail port 587, we need to use STARTTLS, not direct TLS
	// Connect without TLS first
	conn, err := net.Dial("tcp", config.SMTPHost+":"+config.SMTPPort)
	if err != nil {
		return fmt.Errorf("failed to connect to Gmail SMTP: %w", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, config.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Quit()

	// Start TLS (STARTTLS)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         config.SMTPHost,
	}
	
	if err := client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}

	// Authenticate with Gmail
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("Gmail SMTP authentication failed: %w", err)
	}

	// Set sender
	if err := client.Mail(config.SMTPUser); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipient
	if err := client.Rcpt(config.ToEmail); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	// Send email body
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	_, err = writer.Write([]byte(emailBody))
	if err != nil {
		return fmt.Errorf("failed to write email body: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close email writer: %w", err)
	}

	log.Printf("📮 Email sent successfully to %s", config.ToEmail)
	return nil
}

// getEmailConfig loads SMTP configuration from environment variables
func getEmailConfig() EmailConfig {
	return EmailConfig{
		SMTPHost:     getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:     getEnvOrDefault("SMTP_PORT", "587"),
		SMTPUser:     os.Getenv("SMTP_USER"),
		SMTPPassword: os.Getenv("SMTP_PASS"),
		ToEmail:      getEnvOrDefault("TO_EMAIL", os.Getenv("SMTP_USER")),
		FromName:     getEnvOrDefault("FROM_NAME", "iminhas.com Contact Form"),
	}
}

// isEmailConfigured checks if email configuration is complete
func isEmailConfigured(config EmailConfig) bool {
	return config.SMTPUser != "" && config.SMTPPassword != "" && config.ToEmail != ""
}

// getClientIP extracts client IP address
func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

// saveSubmission saves contact submission to JSON file
func saveSubmission(submission *ContactSubmission) error {
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	var submissions []ContactSubmission
	if data, err := os.ReadFile("data/contact_submissions.json"); err == nil {
		json.Unmarshal(data, &submissions)
	}

	submissions = append(submissions, *submission)

	// Keep only last 1000 submissions
	if len(submissions) > 1000 {
		submissions = submissions[len(submissions)-1000:]
	}

	data, err := json.MarshalIndent(submissions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal submissions: %w", err)
	}

	if err := os.WriteFile("data/contact_submissions.json", data, 0644); err != nil {
		return fmt.Errorf("failed to write submissions file: %w", err)
	}

	log.Printf("💾 Submission saved to data/contact_submissions.json")
	return nil
}

// Helper functions for HTTP responses
func writeSuccessResponse(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

func writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    statusCode,
	})
}

// Utility helper functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func maskPassword(password string) string {
	if len(password) == 0 {
		return "(empty)"
	}
	if len(password) <= 4 {
		return strings.Repeat("*", len(password))
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}