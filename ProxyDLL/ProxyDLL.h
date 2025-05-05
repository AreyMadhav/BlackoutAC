#pragma once

#include <Windows.h>

// Function prototype for Unity main entry point
typedef void (*OriginalUnityMainFunc)();

// Main hook function for Unity entry point
void HookedUnityMain();
