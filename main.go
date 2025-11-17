package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed static/*
var staticFiles embed.FS

const mandatoryImport = "github.com/amarnathcjd/gogram/telegram"

const (
	maxCodeSize          = 50 * 1024
	maxConcurrentBuilds  = 3
	buildTimeout         = 120
	rateLimitPerIP       = 5
	maxEnvVars           = 10
	maxEnvVarKeyLength   = 50
	maxEnvVarValueLength = 200
)

type rateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientInfo
}

type clientInfo struct {
	count     int
	resetTime time.Time
}

var (
	limiter = &rateLimiter{
		clients: make(map[string]*clientInfo),
	}
	buildSemaphore = make(chan struct{}, maxConcurrentBuilds)
)

var forbiddenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)os\.Remove`),
	regexp.MustCompile(`(?i)os\.RemoveAll`),
	regexp.MustCompile(`(?i)os\.Exec`),
	regexp.MustCompile(`(?i)exec\.Command`),
	regexp.MustCompile(`(?i)syscall\.`),
	regexp.MustCompile(`(?i)unsafe\.`),
	regexp.MustCompile(`(?i)os\.Create`),
	regexp.MustCompile(`(?i)os\.Open.*Write`),
	regexp.MustCompile(`(?i)ioutil\.WriteFile`),
	regexp.MustCompile(`(?i)os\.Chmod`),
	regexp.MustCompile(`(?i)os\.Chown`),
	regexp.MustCompile(`(?i)net\.Listen`),
	regexp.MustCompile(`(?i)http\.ListenAndServe`),
	regexp.MustCompile(`(?i)plugin\.`),
	regexp.MustCompile(`(?i)reflect\.`),
	regexp.MustCompile(`(?i)\.\.\/`),
	regexp.MustCompile(`(?i)\/etc\/`),
	regexp.MustCompile(`(?i)\/proc\/`),
	regexp.MustCompile(`(?i)\/sys\/`),
	regexp.MustCompile(`(?i)\/root\/`),
	regexp.MustCompile(`(?i)\/home\/`),
}

var allowedImports = map[string]bool{
	"fmt":                                    true,
	"strings":                                true,
	"time":                                   true,
	"errors":                                 true,
	"context":                                true,
	"sync":                                   true,
	"math":                                   true,
	"sort":                                   true,
	"strconv":                                true,
	"bytes":                                  true,
	"io":                                     true,
	"encoding/json":                          true,
	"encoding/base64":                        true,
	"github.com/amarnathcjd/gogram/telegram": true,
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

const encryptionKey = "1234567890abcdef1234567890abcdef"

func (rl *rateLimiter) checkLimit(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	client, exists := rl.clients[ip]

	if !exists || now.After(client.resetTime) {
		rl.clients[ip] = &clientInfo{
			count:     1,
			resetTime: now.Add(time.Minute),
		}
		return true
	}

	if client.count >= rateLimitPerIP {
		return false
	}

	client.count++
	return true
}

func validateCode(code string) error {

	if len(code) > maxCodeSize {
		return fmt.Errorf("code exceeds maximum size of %d bytes", maxCodeSize)
	}

	for _, pattern := range forbiddenPatterns {
		if pattern.MatchString(code) {
			return fmt.Errorf("forbidden pattern detected: %s", pattern.String())
		}
	}

	importRegex := regexp.MustCompile(`import\s+(?:\(([^)]+)\)|"([^"]+)")`)
	matches := importRegex.FindAllStringSubmatch(code, -1)

	for _, match := range matches {
		var imports string
		if match[1] != "" {
			imports = match[1]
		} else {
			imports = match[2]
		}

		importPaths := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(imports, -1)
		for _, imp := range importPaths {
			if len(imp) > 1 {
				importPath := imp[1]

				parts := strings.Fields(importPath)
				if len(parts) > 0 {
					importPath = parts[len(parts)-1]
				}
				importPath = strings.Trim(importPath, "\"")

				if !allowedImports[importPath] && !strings.HasPrefix(importPath, "github.com/amarnathcjd/gogram") {
					return fmt.Errorf("import not allowed: %s", importPath)
				}
			}
		}
	}

	return nil
}

func validateEnvVars(envVars map[string]string) error {
	if len(envVars) > maxEnvVars {
		return fmt.Errorf("too many environment variables (max: %d)", maxEnvVars)
	}

	for key, value := range envVars {
		if len(key) > maxEnvVarKeyLength {
			return fmt.Errorf("environment variable key too long: %s", key)
		}
		if len(value) > maxEnvVarValueLength {
			return fmt.Errorf("environment variable value too long for key: %s", key)
		}

		if strings.ContainsAny(key, "$`;\n\r&|<>") {
			return fmt.Errorf("invalid characters in environment variable key: %s", key)
		}
	}

	return nil
}

func getClientIP(r *http.Request) string {

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

func encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertextBytes, nil)
}

func ensureImport(source string) string {
	if strings.Contains(source, mandatoryImport) {
		return source
	}

	lines := strings.Split(source, "\n")
	var result []string
	importAdded := false

	for i, line := range lines {
		result = append(result, line)

		if !importAdded && strings.Contains(line, "import") {
			if strings.Contains(line, "(") {
				result = append(result, fmt.Sprintf("\t\"%s\"", mandatoryImport))
				importAdded = true
			} else if i+1 < len(lines) && !strings.Contains(line, ")") {
				result = append(result, fmt.Sprintf("import \"%s\"", mandatoryImport))
				importAdded = true
			}
		}
	}

	if !importAdded {
		for i, line := range result {
			if strings.HasPrefix(line, "package ") {
				newResult := make([]string, 0, len(result)+2)
				newResult = append(newResult, result[:i+1]...)
				newResult = append(newResult, "")
				newResult = append(newResult, fmt.Sprintf("import \"%s\"", mandatoryImport))
				newResult = append(newResult, result[i+1:]...)
				return strings.Join(newResult, "\n")
			}
		}
	}

	return strings.Join(result, "\n")
}

func logStep(w http.ResponseWriter, msg string) {
	fmt.Fprintf(w, "[LOG] %s\n", msg)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func compileHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[COMPILE] New compilation request received")

	clientIP := getClientIP(r)
	if !limiter.checkLimit(clientIP) {
		fmt.Printf("[SECURITY] Rate limit exceeded for IP: %s\n", clientIP)
		http.Error(w, "Rate limit exceeded. Try again later.", http.StatusTooManyRequests)
		return
	}

	select {
	case buildSemaphore <- struct{}{}:
		defer func() { <-buildSemaphore }()
	default:
		fmt.Println("[SECURITY] Too many concurrent builds")
		http.Error(w, "Server is busy. Please try again later.", http.StatusServiceUnavailable)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("[ERROR] WebSocket upgrade failed: %v\n", err)
		http.Error(w, err.Error(), 500)
		return
	}
	defer conn.Close()
	fmt.Println("[COMPILE] WebSocket connection established")

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		fmt.Printf("[ERROR] Failed to read message: %v\n", err)
		conn.WriteJSON(map[string]string{"type": "error", "message": "Failed to read message: " + err.Error()})
		return
	}
	fmt.Printf("[COMPILE] Message received, length: %d bytes\n", len(message))

	var payload struct {
		Code    string            `json:"code"`
		EnvVars map[string]string `json:"envVars"`
		Version string            `json:"version"`
	}

	if err := json.Unmarshal(message, &payload); err != nil {
		fmt.Printf("[ERROR] Failed to parse payload: %v\n", err)
		conn.WriteJSON(map[string]string{"type": "error", "message": "Failed to parse payload: " + err.Error()})
		return
	}
	fmt.Printf("[COMPILE] Payload parsed, version: %s, env vars: %d\n", payload.Version, len(payload.EnvVars))

	sourceBytes, err := decrypt(payload.Code)
	if err != nil {
		fmt.Printf("[ERROR] Failed to decrypt source: %v\n", err)
		conn.WriteJSON(map[string]string{"type": "error", "message": "Failed to decrypt source: " + err.Error()})
		return
	}
	fmt.Printf("[COMPILE] Code decrypted, length: %d bytes\n", len(sourceBytes))

	sourceStr := string(sourceBytes)

	if err := validateCode(sourceStr); err != nil {
		fmt.Printf("[SECURITY] Code validation failed: %v\n", err)
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Security validation failed: " + err.Error()})
		return
	}

	if err := validateEnvVars(payload.EnvVars); err != nil {
		fmt.Printf("[SECURITY] Environment variable validation failed: %v\n", err)
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Invalid environment variables: " + err.Error()})
		return
	}

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Code decrypted successfully"})

	tmpDir, err := os.MkdirTemp("", "jxdb-compile-*")
	if err != nil {
		fmt.Printf("[ERROR] Failed to create temp directory: %v\n", err)
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Failed to create temp directory: " + err.Error()})
		return
	}
	defer os.RemoveAll(tmpDir)
	fmt.Printf("[COMPILE] Created temp directory: %s\n", tmpDir)

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Created temp directory: " + tmpDir})

	sourceStr = ensureImport(sourceStr)

	codeFile := filepath.Join(tmpDir, "code.go")
	if err := os.WriteFile(codeFile, []byte(sourceStr), 0644); err != nil {
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Failed to write code file: " + err.Error()})
		return
	}

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Written code file"})

	fmt.Println("[COMPILE] Initializing Go module...")
	modInit := exec.Command("go", "mod", "init", "tempmodule")
	modInit.Dir = tmpDir
	if err := modInit.Run(); err != nil {
		fmt.Printf("[ERROR] Failed to init module: %v\n", err)
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Failed to init module: " + err.Error()})
		return
	}
	fmt.Println("[COMPILE] Module initialized successfully")

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Initialized Go module"})

	version := payload.Version
	if version == "" {
		version = "master"
	}

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Running go mod tidy..."})
	fmt.Println("[COMPILE] Starting go mod tidy...")

	modTidy := exec.Command("go", "mod", "tidy")
	modTidy.Dir = tmpDir
	var tidyStderr bytes.Buffer
	var tidyStdout bytes.Buffer
	modTidy.Stderr = &tidyStderr
	modTidy.Stdout = &tidyStdout

	modTidy.Env = append(os.Environ(), "GOPROXY=https://proxy.golang.org,direct")

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Executing go mod tidy command..."})

	tidyDone := make(chan error, 1)
	go func() {
		fmt.Println("[COMPILE] go mod tidy running...")
		tidyDone <- modTidy.Run()
	}()

	select {
	case err := <-tidyDone:
		if err != nil {
			fmt.Printf("[ERROR] go mod tidy failed: %v, stderr: %s\n", err, tidyStderr.String())
			sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "go mod tidy failed: " + tidyStderr.String() + " | " + tidyStdout.String()})
			return
		}
		fmt.Println("[COMPILE] go mod tidy completed successfully")
	case <-time.After(60 * time.Second):
		fmt.Println("[ERROR] go mod tidy timeout after 60s")
		modTidy.Process.Kill()
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "go mod tidy timeout after 60s"})
		return
	}

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "go mod tidy completed successfully"})

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Compiling to WebAssembly..."})
	fmt.Println("[COMPILE] Starting WebAssembly compilation...")

	outFile := filepath.Join(tmpDir, "out.wasm")
	cmd := exec.Command("go", "build",
		"-o", outFile,
		"code.go",
	)
	cmd.Dir = tmpDir

	envList := append(os.Environ(), "GOOS=js", "GOARCH=wasm")

	envList = append(envList,
		"GOMEMLIMIT=2560MiB",
		"GOGC=50",
		"GOMAXPROCS=1",
	)

	for key, value := range payload.EnvVars {
		if key != "" {
			envList = append(envList, key+"="+value)
		}
	}
	cmd.Env = envList

	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Starting go build..."})

	buildDone := make(chan error, 1)
	go func() {
		fmt.Println("[COMPILE] go build executing...")
		buildDone <- cmd.Run()
	}()

	select {
	case err := <-buildDone:
		if err != nil {
			fmt.Printf("[ERROR] Compilation failed: %v, stderr: %s\n", err, stderr.String())
			sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Compilation failed: " + stderr.String() + " | " + stdout.String()})
			return
		}
		fmt.Println("[COMPILE] Compilation successful")
	case <-time.After(90 * time.Second):
		fmt.Println("[ERROR] Compilation timeout after 90s")
		cmd.Process.Kill()
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Compilation timeout after 90s"})
		return
	}

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Compilation successful, reading output file..."})

	data, err := os.ReadFile(outFile)
	if err != nil {
		fmt.Printf("[ERROR] Failed to read output file: %v\n", err)
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Failed to read output: " + err.Error()})
		return
	}
	fmt.Printf("[COMPILE] WASM binary read successfully, size: %d bytes\n", len(data))

	sendEncryptedJSON(conn, map[string]interface{}{
		"type":    "success",
		"message": fmt.Sprintf("Build complete (%d bytes)", len(data)),
		"size":    len(data),
	})

	fmt.Println("[COMPILE] Sending WASM binary to client...")
	conn.WriteMessage(websocket.BinaryMessage, data)
	fmt.Println("[COMPILE] Compilation request completed successfully")
}

func sendEncryptedJSON(conn *websocket.Conn, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	encrypted, err := encrypt(jsonData)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, []byte(encrypted))
}

func keepAliveHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"alive","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

func main() {
	fmt.Println("[SERVER] Starting Gogram Playground server...")

	goVersion := exec.Command("go", "version")
	output, err := goVersion.CombinedOutput()
	if err != nil {
		fmt.Printf("[FATAL] Go is not installed or not in PATH: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[SERVER] %s\n", strings.TrimSpace(string(output)))

	goPath := os.Getenv("GOPATH")
	goCache := os.Getenv("GOCACHE")
	fmt.Printf("[SERVER] GOPATH: %s\n", goPath)
	fmt.Printf("[SERVER] GOCACHE: %s\n", goCache)

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/keepalive", keepAliveHandler)
	http.HandleFunc("/compile", compileHandler)

	staticFS := http.FileServer(http.FS(staticFiles))
	http.Handle("/static/", staticFS)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := staticFiles.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Page not found", 404)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(data)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "10000"
	}

	fmt.Printf("[SERVER] Server starting on port %s\n", port)
	fmt.Printf("[SERVER] Health check: http://localhost:%s/health\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("[FATAL] Server failed to start: %v\n", err)
	}
}
