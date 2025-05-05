#include <Windows.h>
#include <commdlg.h>  // For file selection dialog
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <wincrypt.h>

// Function to calculate SHA256 hash of a file using Windows CryptoAPI
std::string GetFileSHA256(const std::string& filePath)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE hash[32];  // SHA256 produces 32-byte hash
    DWORD hashSize = sizeof(hash);

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, 0))
    {
        std::cerr << "Error acquiring context!" << std::endl;
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        std::cerr << "Error creating hash!" << std::endl;
        CryptReleaseContext(hProv, 0);
        return "";
    }

    const int bufferSize = 4096;
    char buffer[bufferSize];

    while (file.read(buffer, bufferSize) || file.gcount())
    {
        if (!CryptHashData(hHash, (BYTE*)buffer, (DWORD)file.gcount(), 0))
        {
            std::cerr << "Error hashing data!" << std::endl;
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            return "";
        }
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0))
    {
        std::cerr << "Error retrieving hash!" << std::endl;
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        return "";
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);

    std::stringstream hashStream;
    for (DWORD i = 0; i < hashSize; i++)
    {
        hashStream << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i];
    }

    return hashStream.str();
}

// Function to install the AntiCheat and GameLoader
void InstallAntiCheatAndGameLoader(const std::string& gameExePath)
{
    const std::string validHash = ""; // Replace with the actual hash

    // Get the hash of the selected game executable
    std::string currentHash = GetFileSHA256(gameExePath);

    // Compare hashes
    if (currentHash != validHash)
    {
        MessageBoxA(0, "Game integrity check failed! The game executable has been modified or corrupted.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Get the path of the game
    std::string gamePath = gameExePath.substr(0, gameExePath.find_last_of("\\"));

    // Define file paths for DLLs and EXEs
    std::string proxyDllPath = "\\ProxyDLL.dll";
    std::string antiCheatDllPath = "\\AntiCheatDLL.dll";
    std::string gameLoaderPath = "\\GameLoader.exe";

    // Install Proxy DLL (replace UnityPlayer.dll)
    std::string proxyDllTargetPath = gamePath + "\\UnityPlayer.dll";
    if (!CopyFile(proxyDllPath.c_str(), proxyDllTargetPath.c_str(), FALSE))
    {
        MessageBoxA(0, "Failed to install Proxy DLL!", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Copy AntiCheat DLL
    std::string antiCheatDllTargetPath = gamePath + "\\AntiCheatDLL.dll";
    if (!CopyFile(antiCheatDllPath.c_str(), antiCheatDllTargetPath.c_str(), FALSE))
    {
        MessageBoxA(0, "Failed to install AntiCheat DLL!", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Install the GameLoader
    std::string gameLoaderTargetPath = gamePath + "\\GameLoader.exe";
    if (!CopyFile(gameLoaderPath.c_str(), gameLoaderTargetPath.c_str(), FALSE))
    {
        MessageBoxA(0, "Failed to install GameLoader!", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    MessageBoxA(0, "AntiCheat and GameLoader installed successfully!", "Success", MB_OK);
}

// Function to open the file dialog and select the game executable
void SelectGameExecutable()
{
    OPENFILENAME ofn;       // common dialog box structure
    char szFile[260];       // buffer for file name

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "Executable Files\0*.exe\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE)
    {
        InstallAntiCheatAndGameLoader(ofn.lpstrFile);
    }
    else
    {
        MessageBoxA(0, "Failed to select game executable!", "Error", MB_OK | MB_ICONERROR);
    }
}

int main()
{
    // Open file dialog to select game executable and install the anti-cheat
    SelectGameExecutable();
    return 0;
}
