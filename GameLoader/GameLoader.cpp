#include <Windows.h>
#include <iostream>
#include <string>

void ReplaceUnityPlayerDLL(const std::string& gamePath)
{
    // Assuming the ProxyDLL should be renamed as UnityPlayer.dll
    std::string unityPlayerPath = gamePath + "\\UnityPlayer.dll";

    // Copy the ProxyDLL to the game folder
    if (CopyFile("ProxyDLL.dll", unityPlayerPath.c_str(), FALSE))
    {
        std::cout << "UnityPlayer.dll (ProxyDLL) successfully replaced." << std::endl;
    }
    else
    {
        std::cerr << "Failed to replace UnityPlayer.dll." << std::endl;
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Please specify the game path." << std::endl;
        return -1;
    }

    std::string gamePath = argv[1];
    ReplaceUnityPlayerDLL(gamePath);

    // Now run the game (assuming main.exe is the game executable)
    std::string gameExecutable = gamePath + "\\main.exe";
    WinExec(gameExecutable.c_str(), SW_SHOW);

    return 0;
}
