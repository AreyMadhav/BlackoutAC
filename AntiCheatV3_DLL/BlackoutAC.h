#pragma once

#include <windows.h>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <string>

FARPROC ResolveAPI(const char* dll, const char* function);
bool IsBeingDebugged();
void AntiDebugTrap();
void HideThread();
bool DetectExternalHandles();
bool DetectRemoteThreads();
void DetectManualMappedModules();
bool DetectSuspiciousMemoryRegions();
bool DetectSpeedHack();
void AdaptiveSleep(int suspiciousActivityCount);
void LogMessage(const std::string& message);
void InitLogFile();

extern "C" __declspec(dllexport) void StartAntiCheatMonitoring();
extern "C" __declspec(dllexport) void StopAntiCheatMonitoring();

extern std::atomic<bool> g_Running;
extern std::thread g_MonitorThread;

extern std::unordered_map<DWORD, bool> moduleCache;
bool IsModuleCached(HMODULE hModule);
void CacheModule(HMODULE hModule);