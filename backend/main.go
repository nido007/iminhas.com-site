// backend/main.go
// Main server file with handlers import
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	contactHandlers "iminhas.com/handlers"
)

var startTime = time.Now()

func init() {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}
}

func main() {
	r := mux.NewRouter()

	log.Println("🚀 iminhas.com Go Backend Starting (Phase 2)...")
	log.Println("📁 Serving your existing HTML files from parent directory")

	// ===== API ENDPOINTS SECTION =====
	// Register API routes FIRST (before static file serving)
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/contact", contactHandlers.ContactFormHandler).Methods("POST", "OPTIONS")

	// Health check endpoint
	r.HandleFunc("/health", healthCheckHandler).Methods("GET")

	// ===== STATIC FILE SERVING SECTION =====
	// Serve your existing HTML files from parent directory
	r.HandleFunc("/", serveIndexHTML).Methods("GET")
	r.HandleFunc("/blog.html", serveFile("blog.html")).Methods("GET")
	r.HandleFunc("/blog1.html", serveFile("blog1.html")).Methods("GET")
	r.HandleFunc("/blog2.html", serveFile("blog2.html")).Methods("GET")
	r.HandleFunc("/blog3.html", serveFile("blog3.html")).Methods("GET")
	r.HandleFunc("/blog5.html", serveFile("blog5.html")).Methods("GET")
	r.HandleFunc("/contact.html", serveFile("contact.html")).Methods("GET")
	r.HandleFunc("/projects.html", serveFile("projects.html")).Methods("GET")
	r.HandleFunc("/lem-in.html", serveFile("lem-in.html")).Methods("GET")

	// Serve all other static assets (CSS, JS, images) from parent directory
	// This MUST come last as it's a catch-all
	r.PathPrefix("/").Handler(http.StripPrefix("/",
		http.FileServer(http.Dir("../")))).Methods("GET")

	// Enhanced CORS for development and production
	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{
			"http://localhost:8080",
			"https://iminhas.com",
			"https://www.iminhas.com",
			"*", // For development
		}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "X-Requested-With"}),
		handlers.AllowCredentials(),
	)(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Check email configuration on startup
	validateEmailConfig()

	log.Printf("🌐 Server running at http://localhost:%s", port)
	log.Printf("📄 Your website: http://localhost:%s/", port)
	log.Printf("📝 Your blog: http://localhost:%s/blog.html", port)
	log.Printf("📧 Contact page: http://localhost:%s/contact.html", port)
	log.Printf("🏥 Health check: http://localhost:%s/health", port)
	log.Printf("📮 Contact API: http://localhost:%s/api/contact", port)
	log.Printf("📊 Submissions stored in: ./data/contact_submissions.json")

	// Start server with timeouts
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      corsHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

// validateEmailConfig checks email configuration on startup
func validateEmailConfig() {
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	toEmail := os.Getenv("TO_EMAIL")

	if smtpUser != "" && smtpPass != "" {
		log.Printf("✅ 📧 Email functionality enabled!")
		log.Printf("📧 Sending from: %s", smtpUser)
		if toEmail != "" {
			log.Printf("📧 Sending to: %s", toEmail)
		} else {
			log.Printf("📧 Sending to: %s (using SMTP_USER)", smtpUser)
		}
	} else {
		log.Printf("❌ ⚠️  WARNING: Email not configured!")
		log.Printf("📧 To enable email functionality:")
		log.Printf("   1. Check your .env file exists in backend/ directory")
		log.Printf("   2. Verify SMTP_USER and SMTP_PASS are set correctly")
		log.Printf("   3. Restart the server")
		log.Printf("📝 Contact forms will be saved but emails won't be sent")

		// Debug environment variables
		log.Printf("🔍 Environment check:")
		log.Printf("   SMTP_USER: '%s'", smtpUser)
		log.Printf("   SMTP_PASS: '%s'", maskPassword(smtpPass))
		log.Printf("   TO_EMAIL: '%s'", toEmail)
	}
}

// Static file serving functions
func serveIndexHTML(w http.ResponseWriter, r *http.Request) {
	log.Printf("📄 Serving index.html")
	http.ServeFile(w, r, "../index.html")
}

func serveFile(filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filePath := filepath.Join("..", filename)
		log.Printf("📄 Serving %s", filename)

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			log.Printf("❌ File not found: %s", filePath)
			http.NotFound(w, r)
			return
		}

		http.ServeFile(w, r, filePath)
	}
}

// healthCheckHandler provides comprehensive health check
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("🏥 Health check requested from %s", r.RemoteAddr)

	emailConfigured := os.Getenv("SMTP_USER") != "" && os.Getenv("SMTP_PASS") != ""

	response := map[string]interface{}{
		"status":           "healthy",
		"service":          "iminhas.com-backend",
		"version":          "2.0.0",
		"timestamp":        time.Now().Format(time.RFC3339),
		"uptime":           time.Since(startTime).String(),
		"email_configured": emailConfigured,
		"features": map[string]interface{}{
			"static_files":    true,
			"json_api":        true,
			"contact_form":    true,
			"email_sending":   emailConfigured,
			"form_validation": true,
			"spam_protection": true,
			"data_storage":    true,
		},
		"endpoints": []string{
			"GET / - Main website",
			"GET /contact.html - Contact page",
			"POST /api/contact - Contact form API",
			"GET /health - This health check",
		},
		"email_status": map[string]interface{}{
			"configured": emailConfigured,
			"smtp_host":  os.Getenv("SMTP_HOST"),
			"smtp_user":  os.Getenv("SMTP_USER"),
			"to_email":   os.Getenv("TO_EMAIL"),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Utility helper functions
func maskPassword(password string) string {
	if len(password) == 0 {
		return "(empty)"
	}
	if len(password) <= 4 {
		return strings.Repeat("*", len(password))
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}
