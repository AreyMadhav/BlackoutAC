#include "ProxyDLL.h"
#include <Windows.h>

typedef void (*OriginalUnityMainFunc)();

OriginalUnityMainFunc originalUnityMain = nullptr;

void HookedUnityMain()
{
    // Custom AntiCheat Logic or any additional functionality can go here.
    MessageBoxA(0, "AntiCheat Loaded!", "BlackoutAC", MB_OK);

    if (originalUnityMain)
    {
        originalUnityMain();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        // Use GetModuleHandleW (the wide-character version)
        HMODULE hUnityPlayer = GetModuleHandleW(L"UnityPlayer.dll");
        if (hUnityPlayer)
        {
            // Find the entry point for Unity main function
            originalUnityMain = (OriginalUnityMainFunc)GetProcAddress(hUnityPlayer, "UnityMain");

            if (originalUnityMain)
            {
                // Hook the original function with our custom function
                DWORD oldProtect;
                VirtualProtect((LPVOID)&originalUnityMain, sizeof(OriginalUnityMainFunc), PAGE_EXECUTE_READWRITE, &oldProtect);
                originalUnityMain = HookedUnityMain;
                VirtualProtect((LPVOID)&originalUnityMain, sizeof(OriginalUnityMainFunc), oldProtect, &oldProtect);
            }
        }
    }
    return TRUE;
}
