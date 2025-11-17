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
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed static/*
var staticFiles embed.FS

const mandatoryImport = "github.com/amarnathcjd/gogram/telegram"

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

const encryptionKey = "1234567890abcdef1234567890abcdef" // 32 bytes for AES-256

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
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		conn.WriteJSON(map[string]string{"type": "error", "message": "Failed to read message: " + err.Error()})
		return
	}

	// Parse JSON payload with code and env vars
	var payload struct {
		Code    string            `json:"code"`
		EnvVars map[string]string `json:"envVars"`
		Version string            `json:"version"`
	}

	if err := json.Unmarshal(message, &payload); err != nil {
		conn.WriteJSON(map[string]string{"type": "error", "message": "Failed to parse payload: " + err.Error()})
		return
	}

	sourceBytes, err := decrypt(payload.Code)
	if err != nil {
		conn.WriteJSON(map[string]string{"type": "error", "message": "Failed to decrypt source: " + err.Error()})
		return
	}

	tmpDir, err := os.MkdirTemp("", "jxdb-compile-*")
	if err != nil {
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Failed to create temp directory: " + err.Error()})
		return
	}
	defer os.RemoveAll(tmpDir)

	sourceStr := ensureImport(string(sourceBytes))

	codeFile := filepath.Join(tmpDir, "code.go")
	if err := os.WriteFile(codeFile, []byte(sourceStr), 0644); err != nil {
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Failed to write code file: " + err.Error()})
		return
	}

	modInit := exec.Command("go", "mod", "init", "tempmodule")
	modInit.Dir = tmpDir
	if err := modInit.Run(); err != nil {
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Failed to init module: " + err.Error()})
		return
	}

	// Determine version suffix
	version := payload.Version
	if version == "" {
		version = "master"
	}
	// versionSuffix := "@" + version

	// sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Fetching gogram" + versionSuffix + "..."})

	// // Run go get with version
	// getCmd := exec.Command("go", "get", "-u", "github.com/amarnathcjd/gogram"+versionSuffix)
	// getCmd.Dir = tmpDir
	// var getStderr bytes.Buffer
	// getCmd.Stderr = &getStderr
	// if err := getCmd.Run(); err != nil {
	// 	sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "go get failed: " + getStderr.String()})
	// 	return
	// }

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Running go mod tidy..."})

	modTidy := exec.Command("go", "mod", "tidy")
	modTidy.Dir = tmpDir
	var tidyStderr bytes.Buffer
	modTidy.Stderr = &tidyStderr
	if err := modTidy.Run(); err != nil {
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "go mod tidy failed: " + tidyStderr.String()})
		return
	}
	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "go mod tidy completed successfully"})

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Compiling to WebAssembly..."})

	outFile := filepath.Join(tmpDir, "out.wasm")
	cmd := exec.Command("go", "build",
		"-o", outFile,
		"code.go",
	)
	cmd.Dir = tmpDir

	// Set environment with user-provided env vars
	envList := append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	for key, value := range payload.EnvVars {
		if key != "" {
			envList = append(envList, key+"="+value)
		}
	}
	cmd.Env = envList

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Compilation failed: " + stderr.String()})
		return
	}

	sendEncryptedJSON(conn, map[string]string{"type": "log", "message": "Compilation successful"})

	data, err := os.ReadFile(outFile)
	if err != nil {
		sendEncryptedJSON(conn, map[string]string{"type": "error", "message": "Failed to read output: " + err.Error()})
		return
	}

	sendEncryptedJSON(conn, map[string]interface{}{
		"type":    "success",
		"message": fmt.Sprintf("Build complete (%d bytes)", len(data)),
		"size":    len(data),
	})

	conn.WriteMessage(websocket.BinaryMessage, data)
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

	fmt.Println("Server starting on http://localhost:10000")
	http.ListenAndServe(":10000", nil)
}
