#include "BlackoutAC.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <ctime>
#include <cstdlib>
#include <atomic>
#include <thread>
#include <fstream>
#include <unordered_map>
#include <Windows.h>
#include <mutex>
#include <filesystem>
#include <shlobj.h>

#pragma comment(lib, "psapi.lib")
std::atomic<bool> g_Running(true);
std::thread g_MonitorThread;
std::mutex cacheMutex;
std::ofstream logFile;

// Initialize log file in %LOCALAPPDATA%\BlackoutAC\logs
void InitLogFile() {
    char localAppData[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
        std::string logDir = std::string(localAppData) + "\\BlackoutAC\\logs";
        std::filesystem::create_directories(logDir);
        std::string logPath = logDir + "\\blackoutac_log.txt";

        logFile.open(logPath, std::ios::app);
    }
}

void LogMessage(const std::string& message) {
    if (!logFile.is_open()) InitLogFile();
    if (logFile.is_open()) {
        logFile << "[" << std::time(nullptr) << "] " << message << std::endl;
    }
}

FARPROC ResolveAPI(const char* dll, const char* function) {
    HMODULE hMod = LoadLibraryA(dll);
    return (hMod) ? GetProcAddress(hMod, function) : nullptr;
}

bool IsBeingDebugged() {
    typedef BOOL(WINAPI* pIsDebuggerPresent)();
    pIsDebuggerPresent func = (pIsDebuggerPresent)ResolveAPI("kernel32.dll", "IsDebuggerPresent");
    if (func && func()) return true;

    typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
    pNtQueryInformationProcess NtQueryInfoProc = (pNtQueryInformationProcess)ResolveAPI("ntdll.dll", "NtQueryInformationProcess");

    if (NtQueryInfoProc) {
        DWORD debugPort = 0;
        if (NtQueryInfoProc(GetCurrentProcess(), 7, &debugPort, sizeof(DWORD), NULL) == 0 && debugPort)
            return true;
    }

    return false;
}

void AntiDebugTrap() {
    if (IsBeingDebugged()) {
        LogMessage("Debugger Detected. Closing process.");
        MessageBoxA(NULL, "Debugger Detected. Closing...", "AntiCheat", MB_ICONERROR | MB_OK);
        ExitProcess(0xDEAD);
    }
}

void HideThread() {
    typedef NTSTATUS(WINAPI* pNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
    pNtSetInformationThread NtSetInfo = (pNtSetInformationThread)ResolveAPI("ntdll.dll", "NtSetInformationThread");

    if (NtSetInfo) {
        NtSetInfo(GetCurrentThread(), 0x11, 0, 0);
    }
}

HANDLE OpenProcessWithCheck(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (!hProcess) {
        LogMessage("Failed to open process with PID: " + std::to_string(dwProcessId));
    }
    return hProcess;
}

void TerminateExternalProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        LogMessage("External Process Terminated: " + std::to_string(pid));
    }
}

bool DetectExternalHandles() {
    DWORD myPID = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe = { sizeof(pe) };
    bool externalHandleDetected = false;

    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == myPID) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pe.th32ProcessID);
            if (hProc) {
                if (DuplicateHandle(hProc, GetCurrentProcess(), NULL, NULL, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                    externalHandleDetected = true;
                    LogMessage("External Handle Detected. Terminating PID: " + std::to_string(pe.th32ProcessID));
                    TerminateExternalProcess(pe.th32ProcessID);
                }
                CloseHandle(hProc);
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return externalHandleDetected;
}

bool DetectRemoteThreads() {
    DWORD myPID = GetCurrentProcessId();
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te = { sizeof(te) };
    bool remoteThreadDetected = false;

    if (Thread32First(hThreadSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != myPID) continue;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (hThread) {
                remoteThreadDetected = true;
                CloseHandle(hThread);
                LogMessage("Remote Thread Detected in current process.");
            }
        } while (Thread32Next(hThreadSnap, &te));
    }

    CloseHandle(hThreadSnap);
    return remoteThreadDetected;
}

void DetectManualMappedModules() {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
            TCHAR modName[MAX_PATH];
            if (GetModuleFileNameEx(GetCurrentProcess(), hMods[i], modName, MAX_PATH)) {
                if (wcslen(modName) == 0) {
                    LogMessage("Manual Map Detected. Exiting.");
                    MessageBoxA(NULL, "Manual Map Detected! Closing...", "AntiCheat", MB_ICONERROR | MB_OK);
                    ExitProcess(0xBAAD);
                }
            }
        }
    }
}

bool DetectSuspiciousMemoryRegions() {
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;
    bool found = false;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS) &&
            (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            LogMessage("Suspicious RWX memory region at: " + std::to_string((uintptr_t)addr));
            found = true;
        }
        addr += mbi.RegionSize;
    }

    return found;
}

bool DetectSpeedHack() {
    static ULONGLONG lastTick = GetTickCount64();
    static time_t lastTime = time(NULL);

    ULONGLONG curTick = GetTickCount64();
    time_t curTime = time(NULL);

    double tickDiff = static_cast<double>(curTick - lastTick);
    double timeDiff = difftime(curTime, lastTime) * 1000.0;

    lastTick = curTick;
    lastTime = curTime;

    if (abs(tickDiff - timeDiff) > 200) {
        LogMessage("SpeedHack Detected: Tick mismatch.");
        return true;
    }

    return false;
}

std::unordered_map<DWORD, bool> moduleCache;

bool IsModuleCached(HMODULE hModule) {
    std::lock_guard<std::mutex> lock(cacheMutex);
    return moduleCache.find((DWORD)hModule) != moduleCache.end();
}

void CacheModule(HMODULE hModule) {
    std::lock_guard<std::mutex> lock(cacheMutex);
    moduleCache[(DWORD)hModule] = true;
}

void AdaptiveSleep(int suspiciousActivityCount) {
    int sleepTime = 500 + (rand() % 500);
    if (suspiciousActivityCount > 5) {
        sleepTime = 250 + (rand() % 250);
    }
    Sleep(sleepTime);
}

void AntiCheatLoop() {
    int suspiciousActivityCount = 0;
    while (g_Running.load()) {
        AntiDebugTrap();
        if (DetectExternalHandles()) suspiciousActivityCount++;
        if (DetectRemoteThreads()) suspiciousActivityCount++;
        if (DetectSuspiciousMemoryRegions()) suspiciousActivityCount++;
        if (DetectSpeedHack()) suspiciousActivityCount++;
        DetectManualMappedModules();
        AdaptiveSleep(suspiciousActivityCount);
    }
}

extern "C" __declspec(dllexport) void StartAntiCheatMonitoring() {
    srand(static_cast<unsigned int>(time(NULL)));
    InitLogFile();
    g_Running.store(true);
    g_MonitorThread = std::thread([]() {
        HideThread();
        AntiCheatLoop();
        });
}

extern "C" __declspec(dllexport) void StopAntiCheatMonitoring() {
    g_Running.store(false);
    if (g_MonitorThread.joinable()) {
        g_MonitorThread.join();
    }
    LogMessage("AntiCheat Monitoring Stopped.");
    if (logFile.is_open()) logFile.close();
}
