# TryBypassMe

A top-down wave shooter with an integrated anti-cheat. The game is the challenge, play it, then try to cheat without getting caught.

Built in pure Win32/GDI. No engine, no framework, no dependencies. Few files, compiles out of the box.

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

## Usermode Edition

Everything here is **usermode ring 3**. A kernel driver bypasses all of it trivially. That is intentional. These levels are about solving it in usermode.

**Download:** [TryBypassMe Releases v1.2.3](https://github.com/DeadEye707/TryBypassMe/releases/tag/v1.2.3)

---

### Level 1

**Detection vectors:**

| Vector | Description |
|--------|-------------|
| Process blacklist | 130+ exact name matches: CE, x64dbg, IDA, Ghidra, ReClass, WeMod, injectors and more |
| Window title scan | Catches renamed executables that kept their original window title |
| Debugger detection | `IsDebuggerPresent`, `NtQueryInformationProcess` DebugPort, PEB `NtGlobalFlag`, hardware breakpoints DR0-DR3 |
| Hook detection | Checks prologues of 9 WinAPI and ntdll functions for JMP patches, mid-session byte comparison |
| HP freeze detection | Cumulative damage accounting, flags if HP is mathematically higher than possible |
| Ammo freeze detection | Shot counter vs consumption counter, gap above 5 triggers detection |
| Code integrity | CRC32 of own `.text` section checked every 3 seconds, detects NOP patches and byte modifications |

**Goal:** Make yourself unkillable or give yourself infinite ammo without the AC catching you.



<details>
<summary>Detailed Solution (spoilers)</summary>

Open the game and then open Cheat Engine, you will get this message and the game will close after 5 seconds:

![CE detected by process name](https://i.imgur.com/K0UcnVV.png)

So now we know the game has anti-cheat and detected our executable name. Simply rename the exe from `cheatengine-x86_64-SSE4-AVX2.exe` (or whatever showed in the message) to any random name and try again, you will get a new message:

![Window title detected](https://i.imgur.com/jML7md9.png)

So the AC also detects our window name. Close CE and use HxD hex editor and replace (CTRL+R) `Cheat Engine` with any name - **but it must be the same number of characters (12)!**

![HxD hex replace](https://i.imgur.com/o3wSrV4.png)

Make sure none of your currently opened windows contain "Cheat Engine" (including file explorer), and now you can simply search for the ammo value and edit it to 9999. However you will get this error:

![Ammo freeze detected](https://i.imgur.com/dmG4Lnd.png)

So the AC detects if our ammo value is abnormal. But now we know the AC must be constantly reading our ammo value, so search for the ammo value again, select the address, right-click it, and select **Find out what accesses this address**:

![Find what accesses address](https://i.imgur.com/gNSMDIo.png)

Although the AC detected our debugger, it gave us enough time. Let's look at the first address in IDA Pro. If you tried to go to `009F77FE` IDA will say "Command JumpAsk failed" - that's because the real address is `TryBypassMe_[unknowncheats.me]_.exe+77FE`. In Cheat Engine, go to Memory View -> View -> Enumerate DLL's and Symbols. You will notice that `TryBypassMe` starts at `009F0000` while IDA's default base for 32-bit apps is `00400000`. Either calculate the correct address or go to IDA: **Edit -> Segments -> Rebase program** and enter `009F0000`.

![CE base address](https://i.imgur.com/NeGtz9q.png)
![IDA rebase](https://i.imgur.com/up5lWYT.png)

Now press G, go to `009F77FE`, and press F5 to see the pseudocode:

![IDA pseudocode render](https://i.imgur.com/BDEXKUj.png)

This looks like the rendering function - `AMMO %d/%d` is what we see in the top left while playing. The second CE address is the one below it (`v67 = *(_DWORD *)dword_A040AC`). Looking at the render function, there are no AC checks here. The AC checks ammo in a cycle with a time delay, so by the time CE's debugger was detected, the AC thread hadn't accessed the ammo address yet in that cycle - only the render thread did, which reads it every frame.

Now we can either hide the debugger (very hard in usermode since the AC checks for it in 4 different methods), or take the easier route: we know the AC detects debuggers using `IsDebuggerPresent`, so the application must be importing that function. Let's check imports in IDA:

![IDA imports](https://i.imgur.com/lvrvN8t.png)

Double-click `IsDebuggerPresent`, then select it and press X to see the xrefs. There are 2 functions that call `IsDebuggerPresent()`. Check the first one:

![IsDebuggerPresent xref](https://i.imgur.com/V7k0SfE.png)

By looking at the whole function, we can assume it's `CheckForDebuggers()`. Now xref `sub_9F2D60` and double-click the first caller:

![AC thread xref](https://i.imgur.com/VZMVOkn.png)

This is the main AC thread - it runs a loop every second via `Sleep(0x3E8u)`. Now let's patch it in Cheat Engine. Go to `0x9F3C40` and change the instruction from `push ebp` to `ret`. Unfortunately this isn't enough:

![Integrity check fires](https://i.imgur.com/SfnQHYp.png)

How did the integrity check fire when we patched the function that calls it? The code runs in a for loop as long as `byte_A044F1` is 0, so the main function is only called once and then the loop continues. We can assume `byte_A044F1` tracks whether a violation has already been detected.

Try changing it in Cheat Engine: add the address manually (`A044F1`), type byte, set it to `1`. Now try changing your ammo to `999999`:

![Bypass success](https://i.imgur.com/Ju1vDh6.png)

It worked! The game is still running. It thinks a detection already fired and is waiting to close, so it doesn't run checks again. That's how you solve Level 1.

</details>

---

### Level 2

**What's New (on top of Level 1):**

| Feature | Notes |
|---------|-------|
| Runtime value encryption | XOR key randomized every run, HP/ammo/score/kills/wave are never plaintext in memory |
| Memory canaries | Shadow-copy verification on all protected values |
| Surgical write detection | A 1-byte WPM to a flag is caught even if canaries are untouched* |
| Mutual watchdog threads | Two threads watching each other* |
| Main-thread watchdog fallback | Survives dual-thread suspension* |
| Self-healing code integrity | Patches get reversed before detection fires* |
| System-wide handle scan | Via `NtQuerySystemInformation` (easy to bypass) |

*Partially working - will be completely fixed in v3.

**Goal:** Make yourself unkillable and write code that will decrypt/encrypt the health value.

**Extra challenge:** Find out how the encryption key is generated.



---

### Level 3 - The Great Leap Forward

A massive jump from Levels 1 & 2, extensively tested against most of the solutions posted in the thread.

**What's New:**

| Feature | Description |
|---------|-------------|
| 64-bit | Game is now x64 |
| External watchdog process | HMAC-authenticated named pipe |
| Watchdog CRC32 disk hash | Verifies binary integrity on disk |
| AcToken 3-word commit | No more single detection flag |
| AC checks inlined in render loop | No isolated AC thread to simply kill |
| Code CRC split across 3 checkers | Re-keyed every 30 seconds |
| Dual-key encrypted memory | Shadow copies and canaries |
| Encrypted damage/heal counters | Values never plaintext |
| DLL injection detection | Authenticode verification |
| Compile-time string encryption | All strings encrypted via [skCrypter by skadro](https://www.unknowncheats.me/forum/anti-cheat-bypass/374040-skcrypter-compile-time-um-km-safe-string-crypter-library-11-a.html) |
| Cookie echo thread liveness | Detects thread suspension |
| CREATE_SUSPENDED loader detection | Catches suspended launch |
| VEH + PAGE_GUARD detection | Detects vectored exception hooks |
| Triple-kill termination | Redundant kill paths |
| Mandatory splash screen | 12-second watchdog deadline |
| Randomized AC check dispatch | 7 checks shuffled per iteration via GetTickCount64 entropy |
| Hardware breakpoint detection | GetThreadContext on DR0-DR3 |
| NtQueryInformationProcess dual-check | ProcessDebugPort (flag 7) and ProcessDebugObjectHandle (flag 31) |
| NtGlobalFlag heap flag check | 0x70, survives user-mode debugger patches |
| RDTSC timing attack detection | Catches execution slowdown from debugger overhead |
| Dynamic API resolution | ntdll and NtTerminateProcess resolved at runtime via XOR-decoded strings, bypasses IAT hooks |
| Frequency-gated checks | Some detections only run every N iterations to avoid timing patterns |
| Runs as administrator | Required |
| Decentralized detection handler | No single point of failure |

**Goal:** Make yourself unkillable or give yourself infinite ammo.

![Level 3 screenshot 1](https://i.imgur.com/qlxdFjU.png)
![Level 3 screenshot 2](https://i.imgur.com/5fTn85d.png)
![Level 3 screenshot 3](https://i.imgur.com/QwaVr8G.png)

---

### Extra Challenge: TrySpoofHWID

The same game, but when you launch it you are permanently banned for cheating.

In your journey of bypassing anti-cheats you will eventually face this scenario. Your goal is to spoof your HWID to enter the game. You can also use it to test any spoofer you downloaded online.

![TrySpoofHWID screenshot](https://i.imgur.com/A2NJA4R.png)

**Credits:** [@apexlegends](https://www.unknowncheats.me/forum/members/2681398.html) for [All methods of retrieving unique identifiers (HWIDs) on your PC](https://www.unknowncheats.me/forum/anti-cheat-bypass/333662-methods-retrieving-unique-identifiers-hwids-pc.html)

---

## Kernel Edition

Coming Soon.

---

## Build

1. Create a new empty C++ project in Visual Studio 2022
2. Add `AntiCheat.h`, `AntiCheat.cpp`, and `Game.cpp`
3. Use Multi-Byte Character Set:
   ```
   Project Properties -> Configuration Properties -> Advanced -> Character Set -> Use Multi-Byte Character Set
   ```
4. Set the subsystem to Windows:
   ```
   Project Properties -> Linker -> System -> SubSystem -> Windows
   ```
5. Build in Release x86

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
