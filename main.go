package main

import (
    "bytes"
    "io"
    "net/http"
    "os"
    "os/exec"
)

func compileHandler(w http.ResponseWriter, r *http.Request) {
    source, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, err.Error(), 400)
        return
    }

    os.WriteFile("code.go", source, 0644)

    cmd := exec.Command("tinygo", "build",
        "-o", "out.wasm",
        "-target=wasm",
        "code.go",
    )

    var stderr bytes.Buffer
    cmd.Stderr = &stderr

    if err := cmd.Run(); err != nil {
        http.Error(w, stderr.String(), 400)
        return
    }

    data, _ := os.ReadFile("out.wasm")
    w.Header().Set("Content-Type", "application/wasm")
    w.Write(data)
}

func main() {
    http.HandleFunc("/compile", compileHandler)
    http.ListenAndServe(":10000", nil)
}
