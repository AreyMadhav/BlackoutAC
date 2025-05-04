// BlackoutAntiCheatV1_DLL.h

#pragma once

#include <windows.h>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <string>  // For string utilities

// Function Declarations
FARPROC ResolveAPI(const char* dll, const char* function);
bool IsBeingDebugged();
void AntiDebugTrap();
void HideThread();
bool DetectExternalHandles(); // Declared return type
bool DetectRemoteThreads();   // Declared return type
void DetectManualMappedModules();
void AdaptiveSleep(int suspiciousActivityCount);  // Added adaptive sleep function for more flexibility
void LogMessage(const std::string& message);     // Added log function for message logging
extern "C" __declspec(dllexport) void StartAntiCheatMonitoring();  // Correct linkage for external function
extern "C" __declspec(dllexport) void StopAntiCheatMonitoring();   // Correct linkage for external function

// Global Variables
extern std::atomic<bool> g_Running;  // Flag to control the running state of the monitoring thread
extern std::thread g_MonitorThread;  // The thread handling the anti-cheat monitoring process

// Caching related variables and functions
extern std::unordered_map<DWORD, bool> moduleCache; // Cache for detected modules to avoid redundant checks
bool IsModuleCached(HMODULE hModule);   // Checks if a module is cached
void CacheModule(HMODULE hModule);      // Caches a module after detection
