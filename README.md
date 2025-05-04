# BlackoutAC

A lightweight, thread-based anti-cheat system written in C++ designed to protect Unity IL2CPP games from common external threats such as memory editors, injected code, and debuggers.

---

## 🛡️ Features

- **Debugger Detection**  
  Uses both `IsDebuggerPresent` and native `NtQueryInformationProcess` to detect active debuggers.

- **Thread Cloaking**  
  Hides the anti-cheat monitoring thread from debuggers via `NtSetInformationThread`.

- **External Handle Detection**  
  Identifies processes that hold suspicious handles to the game and terminates them.

- **Remote Thread Detection**  
  Scans for threads injected into the game process by external tools.

- **Manual Map Detection**  
  Inspects modules loaded without a valid file path (common in manual mapping).

- **Adaptive Sleep Logic**  
  Modifies scan frequency based on detected suspicious activity, balancing performance and security.

- **Logging**  
  Persistent activity logs are written to `anticheat_log.txt` for review and debugging.

---

## 🧠 Limitations

- **Internal Mod Bypass**  
  Currently ineffective against internal modifications made using mod frameworks like:
  - [MelonLoader](https://melonwiki.xyz)
  - [BepInEx](https://github.com/BepInEx/BepInEx)

- **No Script Hook Prevention**  
  No logic to verify in-game behavior or detect malicious assemblies/scripts.

---

## 📦 Usage

1. Compile the DLL using a Visual Studio C++ project.
2. Inject `ExampleLatest.dll` into your IL2CPP-based Unity game.
3. Call `StartAntiCheatMonitoring()` when the game initializes.
4. To gracefully stop the anti-cheat, call `StopAntiCheatMonitoring()` before shutdown.

---

## 🔧 Planned Improvements

- Detect and block known modding frameworks.
- Implement in-memory checksum validation of assemblies.
- Create a trusted mod verification system or signed whitelist.
- Behavioral scanning (e.g., memory write frequency, input hooks).

---

## ⚠️ Disclaimer

This project is **not guaranteed** to stop all cheats or exploits. It is a foundation to build upon and should be used in conjunction with other security practices such as obfuscation, integrity checks, and server-side validation.

---
