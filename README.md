# TryBypassMe

A top-down wave shooter with an integrated anti-cheat. The game is the challenge, play it, then try to cheat without getting caught.

Built in pure Win32/GDI. No engine, no framework, no dependencies. Three files, compiles out of the box.

---

## Game


### Controls

| Key | Action |
|-----|--------|
| WASD | Move |
| Mouse | Aim |
| LMB | Shoot |
| R | Reload |
| ESC | Pause |

### Enemies

| Type | Label | Behavior |
|------|-------|----------|
| Walker | - | Charges directly at you |
| Shooter | S | Keeps distance and fires back |
| Tank | T | High HP, deals heavy melee damage |

Enemies increase in speed and count every wave. You gain +10 HP between waves.

### Drops

Random chance on every kill:

| Drop | Chance | Effect |
|------|--------|--------|
| Health Pack | 8% | +30 HP |
| Ammo Pack | 12% | Full reload |
| Shotgun | ~2% | 6-pellet spread, 10 seconds |
| Minigun | ~2% | Full-auto, 10 seconds |
| Rocket Launcher | ~2% | High damage, 10 seconds |

---

## Anti-Cheat

All detection runs on a background thread at 1-second intervals.

| Vector | Description |
|--------|-------------|
| Process blacklist | 130+ exact name matches: CE, x64dbg, IDA, Ghidra, ReClass, WeMod, injectors and more |
| Window title scan | Catches renamed executables that kept their original window title |
| Debugger detection | `IsDebuggerPresent`, `NtQueryInformationProcess` DebugPort, PEB `NtGlobalFlag`, hardware breakpoints DR0-DR3 |
| Hook detection | Checks prologues of 9 WinAPI and ntdll functions for JMP patches, mid-session byte comparison |
| HP freeze detection | Cumulative damage accounting, flags if HP is mathematically higher than possible |
| Ammo freeze detection | Shot counter vs consumption counter, gap above 5 triggers detection |
| Code integrity | CRC32 of own `.text` section checked every 3 seconds, detects NOP patches and byte modifications |

---

## The Goal

**Make yourself unkillable or give yourself infinite ammo without the AC catching you.**


---

## Important

Everything here is **usermode ring 3**. A kernel driver bypasses all of it trivially. That is intentional.

This is **Level 1**. Kernel-level detection, hypervisor detection, and handle-based checks are coming in future levels.

If you find a bypass, post your method in the thread: https://www.unknowncheats.me/forum/anti-cheat-bypass/743802-trybypassme-bypass-anti-cheat.html

---

## Build

1. Create a new empty C++ project in Visual Studio 2022
2. Add `AntiCheat.h`, `AntiCheat.cpp`, and `Game.cpp`
3. Use Multi-Byte Charachter Set:
   ```
   Project Properties -> Configuration Properties -> Advanced -> Charachter Set -> Use Multi-Byte Character Set
   ```
4. Set the subsystem to Windows:
   ```
   Project Properties -> Linker -> System -> SubSystem -> Windows
   ```
5. Build in Release x86 or x64

No additional libraries, resource files, or dependencies required. All libs are linked via `#pragma comment`.

---

## Project Structure

```
TryBypassMe/
    AntiCheat.h       # Public AC interface and shared atomic counters
    AntiCheat.cpp     # All detection logic, background thread, CRC32
    Game.cpp          # Game loop, rendering, entity logic, entry point
```

---

## Credits

Created by **DeadEye707** aka **@ali123x** on UnknownCheats.
