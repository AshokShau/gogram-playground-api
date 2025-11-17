let wasmBinary = null;
let compiledWasm = null;
let editor = null;
let activeWebSocket = null;
let isRunning = false;
let activeWasmInstance = null;
let wasmAbortController = null;

const themeToggle = document.getElementById('themeToggle');
const runBtn = document.getElementById('runBtn');
const stopBtn = document.getElementById('stopBtn');
const clearBtn = document.getElementById('clearBtn');
const editorTextarea = document.getElementById('editor');
const buildLogs = document.getElementById('buildLogs');
const programOutput = document.getElementById('programOutput');
const tabs = document.querySelectorAll('.tab');
const statusIndicator = document.getElementById('statusIndicator');
const examplesBtn = document.getElementById('examplesBtn');
const examplesMenu = document.getElementById('examplesMenu');
const shortcutsBtn = document.getElementById('shortcutsBtn');
const shortcutsModal = document.getElementById('shortcutsModal');
const closeModal = document.getElementById('closeModal');
const envVarsBtn = document.getElementById('envVarsBtn');
const envVarsPanel = document.getElementById('envVarsPanel');
const envVarsList = document.getElementById('envVarsList');
const addEnvBtn = document.getElementById('addEnvBtn');

// Version selection state
let selectedVersion = 'master';

// Version button handlers
document.querySelectorAll('.version-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        // Remove active from all buttons
        document.querySelectorAll('.version-btn').forEach(b => b.classList.remove('active'));
        // Add active to clicked button
        btn.classList.add('active');
        // Store selected version
        selectedVersion = btn.dataset.version;
    });
});
const hamburgerBtn = document.getElementById('hamburgerBtn');
const mobileMenu = document.getElementById('mobileMenu');

// Environment variables storage
let envVars = [];

// Load env vars from localStorage
function loadEnvVars() {
    const stored = localStorage.getItem('envVars');
    if (stored) {
        envVars = JSON.parse(stored);
        renderEnvVars();
    }
}

// Save env vars to localStorage
function saveEnvVars() {
    localStorage.setItem('envVars', JSON.stringify(envVars));
}

// Render env vars list
function renderEnvVars() {
    if (envVars.length === 0) {
        envVarsList.innerHTML = '<div class="env-var-empty">No environment variables set. Click "Add" to create one.</div>';
        return;
    }
    
    envVarsList.innerHTML = envVars.map((env, index) => `
        <div class="env-var-item">
            <input type="text" placeholder="KEY" value="${env.key}" data-index="${index}" data-type="key" />
            <span style="color: var(--text-secondary)">=</span>
            <input type="text" placeholder="value" value="${env.value}" data-index="${index}" data-type="value" />
            <button class="env-var-delete" data-index="${index}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
    `).join('');
    
    // Add event listeners
    envVarsList.querySelectorAll('input').forEach(input => {
        input.addEventListener('input', (e) => {
            const index = parseInt(e.target.dataset.index);
            const type = e.target.dataset.type;
            envVars[index][type] = e.target.value;
            saveEnvVars();
        });
    });
    
    envVarsList.querySelectorAll('.env-var-delete').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = parseInt(e.currentTarget.dataset.index);
            const item = e.currentTarget.closest('.env-var-item');
            
            // Add fade out animation
            item.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                envVars.splice(index, 1);
                saveEnvVars();
                renderEnvVars();
            }, 250);
        });
    });
}

// Toggle env vars panel
envVarsBtn.addEventListener('click', () => {
    const isVisible = envVarsPanel.style.display !== 'none';
    envVarsPanel.style.display = isVisible ? 'none' : 'block';
    envVarsBtn.classList.toggle('active', !isVisible);
});

// Hamburger menu toggle
if (hamburgerBtn) {
    hamburgerBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        mobileMenu.classList.toggle('active');
    });
    
    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
        if (!mobileMenu.contains(e.target) && !hamburgerBtn.contains(e.target)) {
            mobileMenu.classList.remove('active');
        }
    });
    
    // Close menu when clicking a menu item
    mobileMenu.querySelectorAll('.mobile-menu-item').forEach(item => {
        item.addEventListener('click', () => {
            mobileMenu.classList.remove('active');
        });
    });
    
    // Connect mobile menu buttons to desktop handlers
    const envVarsBtnMobile = document.getElementById('envVarsBtnMobile');
    const examplesBtnMobile = document.getElementById('examplesBtnMobile');
    const shortcutsBtnMobile = document.getElementById('shortcutsBtnMobile');
    const themeToggleMobile = document.getElementById('themeToggleMobile');
    
    if (envVarsBtnMobile) {
        envVarsBtnMobile.addEventListener('click', () => {
            envVarsBtn.click();
        });
    }
    
    if (examplesBtnMobile) {
        examplesBtnMobile.addEventListener('click', () => {
            examplesBtn.click();
        });
    }
    
    if (shortcutsBtnMobile) {
        shortcutsBtnMobile.addEventListener('click', () => {
            shortcutsBtn.click();
        });
    }
    
    if (themeToggleMobile) {
        themeToggleMobile.addEventListener('click', () => {
            themeToggle.click();
        });
    }
}

// Add new env var
addEnvBtn.addEventListener('click', () => {
    envVars.push({ key: '', value: '' });
    saveEnvVars();
    renderEnvVars();
    // Focus first empty input
    setTimeout(() => {
        const firstInput = envVarsList.querySelector('input[value=""]');
        if (firstInput) firstInput.focus();
    }, 50);
});

// Load env vars on page load
loadEnvVars();

// Code examples
const examples = {
    basic: `package main

import (
\t"fmt"
\t"os"

\ttg "github.com/amarnathcjd/gogram/telegram"
)

func main() {
\tcfg := tg.NewClientConfigBuilder(2040, "b18441a1ff607e10a989891a5462e627").
\t\tWithMemorySession().
\t\tWithCache(tg.NewCache("mem_cache", &tg.CacheConfig{
\t\t\tMemory: true,
\t\t})).
\t\tBuild()

\tcfg.UseWebSocket = true // important, to work inside browser
\tcfg.UseWebSocketTLS = true
\tclient, _ := tg.NewClient(cfg)
\tclient.Conn()

\t// use the $ button to set ENV variables in the browser
\tif err := client.LoginBot(os.Getenv("BOT_TOKEN")); err != nil {
\t\tpanic(err)
\t}

\tfmt.Println(client.GetMe())
}`,
    version: `package main

import (
\t"fmt"

\ttg "github.com/amarnathcjd/gogram/telegram"
)

func main() {
\tfmt.Println(fmt.Sprintf("Gogram Version: %s, TL Layer: %d", 
            tg.Version,
            tg.ApiVersion))
}`,
    runbot: `package main

import (
\t"fmt"
\t"os"

\ttg "github.com/amarnathcjd/gogram/telegram"
)

func main() {
\tcfg := tg.NewClientConfigBuilder(2040, "b18441a1ff607e10a989891a5462e627").
\t\tWithLogger(tg.NewLogger(tg.DebugLevel, tg.LoggerConfig{
\t\t\tColor:           false,
\t\t\tShowCaller:      false,
\t\t\tShowFunction:    true,
\t\t\tTimestampFormat: "2006-01-02 15:04:05 DST",
\t\t})).
\t\tWithMemorySession().
\t\tWithCache(tg.NewCache("mem_cache", &tg.CacheConfig{
\t\t\tMemory: true,
\t\t})).
\t\tWithDataCenter(5).
\t\tWithReqTimeout(100).
\t\tBuild()

\tcfg.UseWebSocket = true
\tcfg.UseWebSocketTLS = true
\tclient, err := tg.NewClient(cfg)
\tif err != nil {
\t\tpanic(err)
\t}

\ttoken := os.Getenv("BOT_TOKEN")
\tclient.Conn()

\tif err := client.LoginBot(token); err != nil {
\t\tpanic(err)
\t}

\tclient.Idle()
}`,
    session: `package main

import (
\t"fmt"
\t"syscall/js"

\ttg "github.com/amarnathcjd/gogram/telegram"
)

func prompt(message string) string {
\treturn js.Global().Call("prompt", message).String()
}

func main() {
\tcfg := tg.NewClientConfigBuilder(2040, "b18441a1ff607e10a989891a5462e627").
\t\tWithMemorySession().
\t\tWithCache(tg.NewCache("mem_cache", &tg.CacheConfig{
\t\t\tMemory: true,
\t\t})).
\t\tBuild()

\tcfg.UseWebSocket = true
\tcfg.UseWebSocketTLS = true
\tclient, err := tg.NewClient(cfg)
\tif err != nil {
\t\tpanic(err)
\t}

\tphone := prompt("Enter phone number:")
\t
\tif _, err := client.Login(phone, &tg.LoginOptions{
\t\tCodeCallback: func() (string, error) {
\t\t\tcode := prompt("Enter verification code:")
\t\t\treturn code, nil
\t\t},
\t\tPasswordCallback: func() (string, error) {
\t\t\tpassword := prompt("Enter 2FA password:")
\t\t\treturn password, nil
\t\t},
\t}); err != nil {
\t\tpanic(err)
\t}

\tfmt.Println("String Session: ", client.ExportSession())
}`
};

// Initialize CodeMirror editor
document.addEventListener('DOMContentLoaded', () => {
    editor = CodeMirror.fromTextArea(editorTextarea, {
        mode: 'text/x-go',
        theme: savedTheme === 'dark' ? 'dracula' : 'eclipse',
        lineNumbers: true,
        indentUnit: 4,
        indentWithTabs: true,
        tabSize: 4,
        lineWrapping: false,
        autofocus: true,
        extraKeys: {
            'Ctrl-Enter': () => runBtn.click(),
            'Alt-L': () => tabs[0].click(),
            'Alt-O': () => tabs[1].click()
        }
    });
});

// Theme management
const savedTheme = localStorage.getItem('theme') || 'light';
document.body.setAttribute('data-theme', savedTheme);

themeToggle.addEventListener('click', () => {
    const currentTheme = document.body.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    if (editor) {
        editor.setOption('theme', newTheme === 'dark' ? 'dracula' : 'eclipse');
    }
});

// Tab management
tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        
        const tabName = tab.getAttribute('data-tab');
        document.getElementById(`${tabName}-content`).classList.add('active');
    });
});

// Status indicator updates
function setStatus(text, state = 'ready') {
    const statusText = statusIndicator.querySelector('.status-text');
    const statusDot = statusIndicator.querySelector('.status-dot');
    
    statusText.textContent = text;
    statusIndicator.className = 'status-indicator status-' + state;
}

// Logging functions with icons
function addLog(message, type = 'info') {
    const line = document.createElement('div');
    line.className = `log-line log-${type}`;
    
    const icon = document.createElement('span');
    icon.className = 'log-icon';
    
    if (type === 'success') {
        icon.innerHTML = '✓';
    } else if (type === 'error') {
        icon.innerHTML = '✗';
    } else if (type === 'info') {
        icon.innerHTML = '●';
    }
    
    const text = document.createElement('span');
    text.className = 'log-text';
    text.textContent = message;
    
    line.appendChild(icon);
    line.appendChild(text);
    buildLogs.appendChild(line);
    
    // Smooth scroll to bottom
    requestAnimationFrame(() => {
        buildLogs.scrollTop = buildLogs.scrollHeight;
    });
    
    // Add smooth entrance animation
    line.style.opacity = '0';
    line.style.transform = 'translateX(-10px)';
    setTimeout(() => {
        line.style.transition = 'all 0.3s ease';
        line.style.opacity = '1';
        line.style.transform = 'translateX(0)';
    }, 10);
}

function clearLogs() {
    buildLogs.innerHTML = '';
}

function clearOutput() {
    programOutput.innerHTML = '';
}

// Handle output input
const outputInput = document.getElementById('outputInput');
if (outputInput) {
    outputInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const value = outputInput.value;
            outputInput.value = '';
            
            // Display the input in output
            addOutput('> ' + value);
            
            // Resolve the promise if waiting for input
            if (inputResolve) {
                inputResolve(value);
                inputResolve = null;
            }
            
            // Hide input wrapper
            document.getElementById('outputInputWrapper').style.display = 'none';
        }
    });
}

function addOutput(message) {
    const line = document.createElement('div');
    line.className = 'output-line';
    
    // Parse ANSI color codes
    const parsed = parseAnsiColors(message);
    line.innerHTML = parsed;
    
    programOutput.appendChild(line);
    
    // Smooth scroll to bottom
    requestAnimationFrame(() => {
        programOutput.scrollTop = programOutput.scrollHeight;
    });
}

// Parse ANSI color codes to HTML
function parseAnsiColors(text) {
    // ANSI color code mappings
    const colorMap = {
        '30': '#000000', '31': '#e74856', '32': '#16c60c', '33': '#f9f1a5',
        '34': '#3b78ff', '35': '#b4009e', '36': '#61d6d6', '37': '#cccccc',
        '90': '#767676', '91': '#ff6b6b', '92': '#3fb950', '93': '#f9f1a5',
        '94': '#58a6ff', '95': '#bc3fbc', '96': '#76e3ea', '97': '#f2f2f2',
        '0': 'reset'
    };
    
    let result = '';
    let currentColor = '';
    let currentBg = '';
    let isBold = false;
    
    // Escape HTML first
    text = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    
    // Parse ANSI codes
    const parts = text.split(/\x1b\[([0-9;]+)m/);
    
    for (let i = 0; i < parts.length; i++) {
        if (i % 2 === 0) {
            // Text content
            if (parts[i]) {
                let style = '';
                if (currentColor) style += `color: ${currentColor};`;
                if (currentBg) style += `background: ${currentBg};`;
                if (isBold) style += 'font-weight: 600;';
                
                if (style) {
                    result += `<span style="${style}">${parts[i]}</span>`;
                } else {
                    result += parts[i];
                }
            }
        } else {
            // ANSI code
            const codes = parts[i].split(';');
            for (const code of codes) {
                if (code === '0' || code === '00') {
                    currentColor = '';
                    currentBg = '';
                    isBold = false;
                } else if (code === '1') {
                    isBold = true;
                } else if (colorMap[code]) {
                    currentColor = colorMap[code];
                } else if (code.startsWith('4') && colorMap[code.substring(1)]) {
                    currentBg = colorMap[code.substring(1)];
                }
            }
        }
    }
    
    return result || text;
}

// Stop button - kill execution
stopBtn.addEventListener('click', () => {
    if (activeWebSocket) {
        activeWebSocket.close();
        activeWebSocket = null;
    }
    
    // Kill active WASM instance
    if (activeWasmInstance) {
        activeWasmInstance = null;
        addOutput('\\n--- Program terminated by user ---');
    }
    
    isRunning = false;
    
    addLog('⚠️ Execution stopped by user', 'warning');
    setStatus('Stopped', 'warning');
    
    runBtn.disabled = false;
    runBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
        Run
    `;
    runBtn.style.display = 'inline-flex';
    stopBtn.style.display = 'none';
});

// Clear button
clearBtn.addEventListener('click', () => {
    // Kill any running WASM
    if (activeWasmInstance) {
        activeWasmInstance = null;
    }
    
    clearLogs();
    clearOutput();
    wasmBinary = null;
    compiledWasm = null;
    setStatus('Ready', 'ready');
    
    // Reset buttons if needed
    runBtn.style.display = 'inline-flex';
    stopBtn.style.display = 'none';
});

// Keep-alive ping to prevent Render free tier sleep
function startKeepAlive() {
    setInterval(async () => {
        try {
            await fetch('/keepalive');
            console.log('Keep-alive ping sent');
        } catch (error) {
            console.error('Keep-alive failed:', error);
        }
    }, 5 * 60 * 1000); // Every 5 minutes
}

// Start keep-alive on page load
startKeepAlive();

// Examples dropdown
examplesBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    examplesMenu.classList.toggle('active');
});

document.addEventListener('click', (e) => {
    if (!examplesMenu.contains(e.target) && e.target !== examplesBtn) {
        examplesMenu.classList.remove('active');
    }
});

document.querySelectorAll('.dropdown-item').forEach(item => {
    item.addEventListener('click', () => {
        const exampleName = item.getAttribute('data-example');
        if (examples[exampleName] && editor) {
            editor.setValue(examples[exampleName]);
            examplesMenu.classList.remove('active');
            setStatus('Example loaded', 'ready');
        }
    });
});

// Keyboard shortcuts modal
shortcutsBtn.addEventListener('click', () => {
    shortcutsModal.classList.add('active');
});

closeModal.addEventListener('click', () => {
    shortcutsModal.classList.remove('active');
});

shortcutsModal.addEventListener('click', (e) => {
    if (e.target === shortcutsModal) {
        shortcutsModal.classList.remove('active');
    }
});

document.addEventListener('keydown', (e) => {
    // Escape to close modal
    if (e.key === 'Escape') {
        shortcutsModal.classList.remove('active');
        examplesMenu.style.display = 'none';
        if (mobileMenu) {
            mobileMenu.classList.remove('active');
        }
    }
    
    // Alt+E for environment variables
    if (e.altKey && e.key === 'e') {
        e.preventDefault();
        envVarsBtn.click();
    }
    
    // Alt+T for theme toggle
    if (e.altKey && e.key === 't') {
        e.preventDefault();
        themeToggle.click();
    }
    
    // ? for keyboard shortcuts (when not in input field)
    if (e.key === '?' && !e.ctrlKey && !e.altKey && !e.metaKey) {
        const activeElement = document.activeElement;
        const isInputField = activeElement.tagName === 'INPUT' || 
                           activeElement.tagName === 'TEXTAREA' || 
                           activeElement.classList.contains('CodeMirror');
        if (!isInputField) {
            e.preventDefault();
            shortcutsBtn.click();
        }
    }
});

// Run button - compile and execute
runBtn.addEventListener('click', async () => {
    const code = editor ? editor.getValue().trim() : editorTextarea.value.trim();
    
    if (!code) {
        addLog('Error: Editor is empty', 'error');
        return;
    }
    
    clearLogs();
    clearOutput();
    
    runBtn.disabled = true;
    runBtn.innerHTML = '<div class="spinner"></div> Compiling...';
    setStatus('Compiling...', 'compiling');
    
    try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${protocol}//${window.location.host}/compile`);
        activeWebSocket = ws;
        isRunning = true;
        
        // Show stop button, hide run button
        runBtn.style.display = 'none';
        stopBtn.style.display = 'inline-flex';
        
        ws.onopen = async () => {
            setStatus('Encrypting...', 'compiling');
            const encryptedCode = await window.JxDBCrypto.encrypt(code);
            
            // Prepare payload with code and env vars
            const payload = {
                code: encryptedCode,
                envVars: {},
                version: selectedVersion || 'master'
            };
            
            // Add env vars to payload
            envVars.forEach(env => {
                if (env.key && env.key.trim()) {
                    payload.envVars[env.key.trim()] = env.value || '';
                }
            });
            
            ws.send(JSON.stringify(payload));
            setStatus('Building...', 'compiling');
        };
        
        ws.onmessage = async (event) => {
            if (event.data instanceof Blob) {
                // Binary message = WASM binary
                wasmBinary = await event.data.arrayBuffer();
                addLog(`✓ Received WASM binary (${wasmBinary.byteLength} bytes)`, 'success');
                setStatus('Build successful', 'success');
                
                // Auto-switch to output tab and run WASM
                tabs[1].click();
                setTimeout(() => runWasm(), 100);
                
                ws.close();
            } else {
                // Text message = encrypted JSON log
                try {
                    const decrypted = await window.JxDBCrypto.decrypt(event.data);
                    const msg = JSON.parse(decrypted);
                    
                    if (msg.type === 'log') {
                        addLog(msg.message, 'info');
                    } else if (msg.type === 'error') {
                        addLog(msg.message, 'error');
                        setStatus('Build failed', 'error');
                    } else if (msg.type === 'success') {
                        addLog(msg.message, 'success');
                    }
                } catch (e) {
                    console.error('Failed to decrypt/parse message:', e);
                    addLog('Decryption error: ' + e.message, 'error');
                }
            }
        };
        
        ws.onerror = (error) => {
            addLog('WebSocket error: ' + error, 'error');
            setStatus('Connection error', 'error');
            runBtn.disabled = false;
            runBtn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polygon points="5 3 19 12 5 21 5 3"/>
                </svg>
                Run
            `;
        };
        
        ws.onclose = () => {
            activeWebSocket = null;
            isRunning = false;
            runBtn.disabled = false;
            runBtn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polygon points="5 3 19 12 5 21 5 3"/>
                </svg>
                Run
            `;
            runBtn.style.display = 'inline-flex';
            stopBtn.style.display = 'none';
        };
        
    } catch (error) {
        addLog(`Error: ${error.message}`, 'error');
        setStatus('Error', 'error');
        activeWebSocket = null;
        isRunning = false;
        runBtn.disabled = false;
        runBtn.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polygon points="5 3 19 12 5 21 5 3"/>
            </svg>
            Run
        `;
        runBtn.style.display = 'inline-flex';
        stopBtn.style.display = 'none';
    }
});

// Run compiled WASM binary
let inputQueue = [];
let inputResolve = null;

async function runWasm() {
    if (!wasmBinary) {
        addOutput('Error: No compiled WASM binary available');
        return;
    }
    
    // Kill any existing WASM instance
    if (activeWasmInstance) {
        try {
            addOutput('\n--- Stopping previous program ---\n');
            // Attempt to terminate the previous instance
            activeWasmInstance = null;
        } catch (e) {
            console.error('Error stopping previous WASM:', e);
        }
    }
    
    // Clear input queue
    inputQueue = [];
    inputResolve = null;
    
    try {
        setStatus('Running WASM...', 'running');
        const go = new Go();
        
        // Set environment variables in WASM runtime
        envVars.forEach(env => {
            if (env.key && env.key.trim()) {
                go.env[env.key.trim()] = env.value || '';
            }
        });
        
        // Intercept console.log/error to display in output
        const originalLog = console.log;
        const originalError = console.error;
        
        console.log = (...args) => {
            addOutput(args.join(' '));
            originalLog(...args); // Also log to browser console
        };
        
        console.error = (...args) => {
            addOutput('[ERROR] ' + args.join(' '));
            originalError(...args); // Also log to browser console
        };
        
        // Override prompt for input
        const originalPrompt = window.prompt;
        window.prompt = (message) => {
            addOutput(message || 'Enter input:');
            const outputInputWrapper = document.getElementById('outputInputWrapper');
            const outputInput = document.getElementById('outputInput');
            
            outputInputWrapper.style.display = 'flex';
            outputInput.focus();
            
            return new Promise((resolve) => {
                inputResolve = resolve;
            });
        };
        
        const result = await WebAssembly.instantiate(wasmBinary, go.importObject);
        activeWasmInstance = result.instance;
        
        // Run WASM asynchronously (don't await - it may run indefinitely)
        go.run(result.instance).then(() => {
            console.log = originalLog;
            console.error = originalError;
            window.prompt = originalPrompt;
            activeWasmInstance = null;
            setStatus('Execution complete', 'success');
            addOutput('\n--- Program exited ---');
            
            // Hide input wrapper and stop button, show run button
            document.getElementById('outputInputWrapper').style.display = 'none';
            runBtn.style.display = 'inline-flex';
            stopBtn.style.display = 'none';
        }).catch((err) => {
            console.log = originalLog;
            console.error = originalError;
            window.prompt = originalPrompt;
            activeWasmInstance = null;
            addOutput(`\nRuntime error: ${err.message}`);
            setStatus('Runtime error', 'error');
            
            // Hide input wrapper and stop button, show run button
            document.getElementById('outputInputWrapper').style.display = 'none';
            runBtn.style.display = 'inline-flex';
            stopBtn.style.display = 'none';
        });
        
        // Set status to running (program is now executing)
        setStatus('Running...', 'success');
        
    } catch (error) {
        addOutput(`Runtime error: ${error.message}`);
        console.error('WASM Error:', error);
        setStatus('Runtime error', 'error');
    }
}
