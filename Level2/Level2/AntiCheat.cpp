#include "AntiCheat.h"
#include <string>
#include <cstdio>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

// ============================================================
// PROCESS BLACKLIST
// ============================================================
static const std::unordered_set<std::string> s_exactBL = {
    "cheatengine-x86_64.exe", "cheatengine-x86_64-sse4-avx2.exe",
    "cheatengine-i386.exe", "cheatengine.exe", "cetrainer.exe", "ce64.exe",
    "x64dbg.exe", "x32dbg.exe", "cpudbg64.exe", "asmdbg32.exe", "asmdbg64.exe",
    "ollydbg.exe", "ollydbg2.exe", "odbg200.exe",
    "idaq.exe", "idaq64.exe", "ida.exe", "ida64.exe", "idaw.exe", "idaw64.exe", "ida_weasel.exe",
    "windbg.exe", "windbgx.exe", "cdb.exe", "ntsd.exe", "kd.exe",
    "hyperdbg.exe", "hyperdbg-cli.exe",
    "ghidra.exe", "ghidrarun.exe", "binaryninja.exe", "binja.exe", "cutter.exe", "radare2.exe",
    "dnspy.exe", "ilspy.exe", "dotpeek.exe", "dotpeek64.exe", "justdecompile.exe",
    "artmoney.exe", "artmoney7.exe", "artmoney8.exe", "tsearch.exe",
    "squalr.exe", "pkhex.exe", "winhex.exe", "hxd.exe", "010editor.exe",
    "processhacker.exe", "processhacker2.exe", "systeminformer.exe",
    "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
    "extremeinjector.exe", "xenos.exe", "xenos64.exe", "ghinject.exe",
    "nightshade.exe", "winject.exe", "remotedll.exe",
    "scylla.exe", "scylla_x64.exe", "scylla_x86.exe", "importrec.exe",
    "lordpe.exe", "peid.exe", "pestudio.exe", "pe-bear.exe", "peview.exe", "cffexplorer.exe",
    "reclass.exe", "reclass64.exe", "reclass.net.exe", "reclassex.exe",
    "wireshark.exe", "fiddler.exe", "fiddler4.exe", "charles.exe", "mitmproxy.exe",
    "wemod.exe", "trainmanager.exe",
    "scyllahide.exe", "titanhide.exe", "hyperhide.exe", "strongod.exe",
};

static const std::vector<std::string> s_substringBL = {
    "cheatengine", "cheat-engine", "ollydbg", "scyllahide", "titanhide",
    "reclass", "wireshark", "extremeinjector", "processhacker", "systeminformer", "wemod",
};

// ============================================================
// GLOBALS
// ============================================================
std::atomic<bool> g_acDetected(false);
std::string       g_acReason;

std::atomic<int>  g_totalDamageDealt(0);
std::atomic<int>  g_totalHealed(0);
std::atomic<int>  g_shotsFired(0);
std::atomic<int>  g_ammoConsumed(0);
std::atomic<int>  g_ammoRefilled(0);

std::atomic<uint32_t> g_gameTick(0);

uint32_t g_xorKey = 0;

EncInt g_encHp = {};
EncInt g_encAmmo = {};
EncInt g_encScore = {};
EncInt g_encKills = {};
EncInt g_encWave = {};

GuardedBool g_pausedGuard = { AC_CANARY_LO, false, {}, AC_CANARY_HI };
GuardedBool g_powerWeaponGuard = { AC_CANARY_LO, false, {}, AC_CANARY_HI };

std::atomic<uint32_t> g_flagWriteCount(0);
std::atomic<bool>     g_shadowPaused(false);
std::atomic<bool>     g_shadowPowerWeapon(false);

std::atomic<ULONGLONG> g_acThreadTs(0);
std::atomic<ULONGLONG> g_wdThreadTs(0);

bool g_gameOver = false;

static BYTE  s_origRPM[8] = {};
static BYTE  s_origWPM[8] = {};

static DWORD  s_codeCrc = 0;
static BYTE* s_codeStart = nullptr;
static SIZE_T s_codeSize = 0;

static BYTE* s_codeBackup = nullptr;

// ============================================================
// WATCHDOG TIMEOUT
// ============================================================
static constexpr DWORD WD_TIMEOUT_MS = 4000;

static std::atomic<bool> s_wdReady(false);
static std::atomic<bool> s_acInitDone(false);

// ============================================================
// CRC32
// ============================================================
static DWORD CalcCRC32(const BYTE* data, SIZE_T len)
{
    DWORD crc = 0xFFFFFFFF;
    for (SIZE_T i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & (DWORD)(-(int)(crc & 1)));
    }
    return ~crc;
}

static std::string ToLower(std::string s)
{
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

// ============================================================
// DETECT
// ============================================================
void ACDetect(const std::string& reason)
{
    if (g_acDetected.exchange(true)) return;
    g_acReason = reason;
    g_gameOver = true;

    std::string* msg = new std::string(
        "[!] CHEAT DETECTED\n\nReason: " + reason + "\n\nGame will terminate.");

    CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* m = (std::string*)p;
        MessageBoxA(nullptr, m->c_str(), "Anti-Cheat",
            MB_ICONERROR | MB_OK | MB_TOPMOST | MB_SYSTEMMODAL);
        delete m;
        return 0;
        }, msg, 0, nullptr);

    Sleep(5000);
    TerminateProcess(GetCurrentProcess(), 1);
}

// ============================================================
// PROCESS SCAN
// ============================================================
static bool ACCheckProcesses()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    bool found = false;

    if (Process32First(snap, &pe)) {
        do {
            std::string name = ToLower(pe.szExeFile);

            if (s_exactBL.count(name)) {
                ACDetect("Blacklisted process: " + std::string(pe.szExeFile));
                found = true; break;
            }
            for (auto& sub : s_substringBL) {
                if (name.find(sub) != std::string::npos) {
                    ACDetect("Blacklisted process ('" + sub + "'): " + std::string(pe.szExeFile));
                    found = true; break;
                }
            }
        } while (!found && Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return found;
}

// ============================================================
// WINDOW TITLE SCAN
// ============================================================
struct WndScanResult { bool found; std::string title; };

static BOOL CALLBACK EnumWndCb(HWND hwnd, LPARAM lp)
{
    auto* p = (WndScanResult*)lp;
    char title[512] = {};
    GetWindowTextA(hwnd, title, sizeof(title));
    std::string t = ToLower(title);

    const char* keys[] = {
        "cheat engine", "cheatengine", "x64dbg", "x32dbg", "ollydbg",
        "process hacker", "system informer", "scylla", "reclass",
        "wireshark", "fiddler", "hyperdbg", "windbg", "ida pro",
        "ghidra", "binary ninja", "dnspy", "wemod", "extreme injector",
        nullptr
    };
    for (int i = 0; keys[i]; i++) {
        if (t.find(keys[i]) != std::string::npos) {
            p->found = true; p->title = title; return FALSE;
        }
    }
    return TRUE;
}

static bool ACCheckWindows()
{
    WndScanResult r = { false, "" };
    EnumWindows(EnumWndCb, (LPARAM)&r);
    if (r.found) { ACDetect("Suspicious window: \"" + r.title + "\""); return true; }
    return false;
}

// ============================================================
// DEBUGGER DETECTION
// ============================================================
static bool ACCheckDebugger()
{
    if (IsDebuggerPresent()) { ACDetect("Debugger (IsDebuggerPresent)"); return true; }

    typedef NTSTATUS(WINAPI* NtQIP_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto fn = ntdll ? (NtQIP_t)GetProcAddress(ntdll, "NtQueryInformationProcess") : nullptr;
    if (fn) {
        DWORD port = 0;
        if (NT_SUCCESS(fn(GetCurrentProcess(), 7, &port, sizeof(port), nullptr)) && port) {
            ACDetect("Debugger (DebugPort)"); return true;
        }
    }

#ifdef _WIN64
    ULONG_PTR peb = __readgsqword(0x60);
    ULONG     flag = *(ULONG*)(peb + 0xBC);
#else
    ULONG_PTR peb = (ULONG_PTR)__readfsdword(0x30);
    ULONG     flag = *(ULONG*)(peb + 0x68);
#endif
    if (flag & 0x70) { ACDetect("Debugger (NtGlobalFlag)"); return true; }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
        ACDetect("Hardware breakpoints (DR0-DR3)"); return true;
    }
    return false;
}

// ============================================================
// CANARY + SHADOW CHECK
// ============================================================
static bool ACCheckCanaries()
{
    if (!s_acInitDone.load()) return false;
    if (g_pausedGuard.guardPre != AC_CANARY_LO ||
        g_pausedGuard.guardPost != AC_CANARY_HI)
    {
        ACDetect("Canary corruption (g_paused)"); return true;
    }
    if (g_powerWeaponGuard.guardPre != AC_CANARY_LO ||
        g_powerWeaponGuard.guardPost != AC_CANARY_HI)
    {
        ACDetect("Canary corruption (g_powerWeapon)"); return true;
    }

    if ((bool)g_pausedGuard.flag != g_shadowPaused.load()) {
        ACDetect("Flag tamper: g_paused written outside setter");
        return true;
    }
    if ((bool)g_powerWeaponGuard.flag != g_shadowPowerWeapon.load()) {
        ACDetect("Flag tamper: g_powerWeapon written outside setter");
        return true;
    }

    struct { const EncInt* e; const char* name; } ev[] = {
        { &g_encHp,    "encHp"    },
        { &g_encAmmo,  "encAmmo"  },
        { &g_encScore, "encScore" },
        { &g_encKills, "encKills" },
        { &g_encWave,  "encWave"  },
    };
    for (auto& v : ev) {
        if (v.e->canaryLo != AC_CANARY_LO || v.e->canaryHi != AC_CANARY_HI) {
            ACDetect(std::string("Canary corruption (") + v.name + ")");
            return true;
        }
    }
    return false;
}

// ============================================================
// HP FREEZE DETECTION
// ============================================================
static bool ACCheckHpFreeze()
{
    if (g_gameOver || g_paused) return false;

    int dealt = g_totalDamageDealt.load();
    int healed = g_totalHealed.load();
    int hpNow = ACReadEnc(g_encHp);

    int expected = 100 - dealt + healed;
    if (expected < 0)   expected = 0;
    if (expected > 100) expected = 100;

    if (hpNow > expected + 10) {
        char buf[128];
        sprintf_s(buf, "HP freeze (hp=%d expected=%d dealt=%d healed=%d)",
            hpNow, expected, dealt, healed);
        ACDetect(buf); return true;
    }
    return false;
}

// ============================================================
// AMMO FREEZE DETECTION
// ============================================================
static bool ACCheckAmmoFreeze()
{
    if (g_gameOver || g_paused || g_powerWeapon) return false;

    int gap = g_shotsFired.load() - g_ammoConsumed.load();
    if (gap > 5) {
        ACDetect("Ammo freeze (shots=" + std::to_string(g_shotsFired.load())
            + " consumed=" + std::to_string(g_ammoConsumed.load())
            + " gap=" + std::to_string(gap) + ")");
        return true;
    }
    return false;
}

// ============================================================
// HOOK DETECTION
// ============================================================
static bool ACCheckHooks()
{
    struct FuncEntry { const char* mod; const char* fn; };
    static const FuncEntry targets[] = {
        { "kernel32.dll", "ReadProcessMemory"    },
        { "kernel32.dll", "WriteProcessMemory"   },
        { "kernel32.dll", "OpenProcess"          },
        { "kernel32.dll", "VirtualProtect"       },
        { "kernel32.dll", "CreateRemoteThread"   },
        { "ntdll.dll",    "NtReadVirtualMemory"  },
        { "ntdll.dll",    "NtWriteVirtualMemory" },
        { "ntdll.dll",    "NtOpenProcess"        },
        { "ntdll.dll",    "LdrLoadDll"           },
        { nullptr, nullptr }
    };

    for (int i = 0; targets[i].mod; i++) {
        HMODULE m = GetModuleHandleA(targets[i].mod);
        if (!m) continue;
        BYTE* f = (BYTE*)GetProcAddress(m, targets[i].fn);
        if (!f) continue;

        bool hooked = (f[0] == 0xE9)
            || (f[0] == 0xEB)
            || (f[0] == 0xFF && f[1] == 0x25)
            || (f[0] == 0x68 && f[4] == 0xC3);

        if (hooked) {
            ACDetect(std::string("Hook: ") + targets[i].mod + "!" + targets[i].fn);
            return true;
        }
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (k32) {
        BYTE* rpm = (BYTE*)GetProcAddress(k32, "ReadProcessMemory");
        if (rpm && memcmp(s_origRPM, rpm, 8)) {
            ACDetect("ReadProcessMemory hooked mid-session"); return true;
        }
        BYTE* wpm = (BYTE*)GetProcAddress(k32, "WriteProcessMemory");
        if (wpm && memcmp(s_origWPM, wpm, 8)) {
            ACDetect("WriteProcessMemory hooked mid-session"); return true;
        }
    }
    return false;
}

// ============================================================
// CODE INTEGRITY
// ============================================================
static bool ACCheckCodeIntegrity()
{
    if (!s_codeStart || s_codeSize == 0) return false;

    DWORD current = CalcCRC32(s_codeStart, s_codeSize);
    if (current != s_codeCrc) {
        if (s_codeBackup) {
            DWORD old;
            if (VirtualProtect(s_codeStart, s_codeSize, PAGE_EXECUTE_READWRITE, &old)) {
                memcpy(s_codeStart, s_codeBackup, s_codeSize);
                VirtualProtect(s_codeStart, s_codeSize, old, &old);
            }
        }
        char buf[64];
        sprintf_s(buf, "Code integrity (expected %08X got %08X)", s_codeCrc, current);
        ACDetect(buf); return true;
    }
    return false;
}

// ============================================================
// HANDLE SCAN
// ============================================================
struct SYSTEM_HANDLE_ENTRY {
    ULONG  OwnerPid;
    BYTE   ObjectType;
    BYTE   HandleFlags;
    USHORT HandleValue;
    PVOID  ObjectPointer;
    ULONG  AccessMask;
};
struct SYSTEM_HANDLE_INFORMATION {
    ULONG              HandleCount;
    SYSTEM_HANDLE_ENTRY Handles[1];
};

static bool ACCheckHandles()
{
    typedef NTSTATUS(WINAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto NtQSI = (NtQSI_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return false;

    DWORD myPid = GetCurrentProcessId();

    static BYTE* s_buf = nullptr;
    static ULONG s_bufSz = 0;

    if (!s_buf) {
        s_bufSz = 256 * 1024;
        s_buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, s_bufSz);
        if (!s_buf) return false;
    }

    NTSTATUS st;
    for (int attempt = 0; attempt < 8; attempt++) {
        ULONG ret = 0;
        st = NtQSI(16, s_buf, s_bufSz, &ret);
        if (NT_SUCCESS(st)) break;
        if ((ULONG)st == 0xC0000004) {
            s_bufSz *= 2;
            BYTE* grown = (BYTE*)HeapReAlloc(GetProcessHeap(), 0, s_buf, s_bufSz);
            if (!grown) return false;
            s_buf = grown;
        }
        else { return false; }
    }
    if (!NT_SUCCESS(st)) return false;

    static constexpr ULONG SUSPICIOUS = 0x0010 | 0x0020;

    auto* info = (SYSTEM_HANDLE_INFORMATION*)s_buf;
    for (ULONG i = 0; i < info->HandleCount; i++) {
        const auto& h = info->Handles[i];
        if (h.OwnerPid == myPid)          continue;
        if (!(h.AccessMask & SUSPICIOUS)) continue;

        HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, h.OwnerPid);
        if (!hOwner) continue;

        HANDLE hDup = nullptr;
        if (DuplicateHandle(hOwner, (HANDLE)(ULONG_PTR)h.HandleValue,
            GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            bool targetsUs = (GetProcessId(hDup) == myPid);
            CloseHandle(hDup);
            if (targetsUs) {
                CloseHandle(hOwner);
                char detBuf[128];
                sprintf_s(detBuf, "External process handle (pid=%lu access=%08lX)",
                    (unsigned long)h.OwnerPid, (unsigned long)h.AccessMask);
                ACDetect(detBuf); return true;
            }
        }
        CloseHandle(hOwner);
    }
    return false;
}

// ============================================================
// WATCHDOG THREAD
// ============================================================
static DWORD WINAPI WatchdogThread(LPVOID)
{
    while (!s_wdReady.load()) Sleep(50);

    while (!g_acDetected.load()) {
        g_wdThreadTs.store(GetTickCount64());
        Sleep(WD_TIMEOUT_MS / 2);

        ULONGLONG lastAC = g_acThreadTs.load();
        if (lastAC != 0 && (GetTickCount64() - lastAC) > WD_TIMEOUT_MS) {
            ACDetect("Watchdog: ACThread suspended or killed");
            return 0;
        }
    }
    return 0;
}

// ============================================================
// BACKGROUND THREAD
// ============================================================
static void ACThread()
{
    int tick = 0;
    g_acThreadTs.store(GetTickCount64());
    s_wdReady.store(true);

    while (!g_acDetected.load()) {
        g_acThreadTs.store(GetTickCount64());

        ULONGLONG lastWD = g_wdThreadTs.load();
        if (lastWD != 0 && (GetTickCount64() - lastWD) > WD_TIMEOUT_MS) {
            ACDetect("Watchdog: WatchdogThread suspended or killed");
            return;
        }

        ACCheckCanaries();
        ACCheckHpFreeze();
        ACCheckAmmoFreeze();
        ACCheckHooks();

        if (tick % 2 == 0) ACCheckProcesses();
        if (tick % 2 == 1) ACCheckWindows();
        if (tick % 2 == 1) ACCheckDebugger();

        if (tick % 4 == 0) ACCheckCodeIntegrity();

        if (tick % 10 == 0) ACCheckHandles();

        tick++;
        Sleep(1000);
    }
}

// ============================================================
// TICK
// ============================================================
void ACTick()
{
    g_gameTick.fetch_add(1, std::memory_order_relaxed);

    if (!s_wdReady.load(std::memory_order_acquire)) return;

    ULONGLONG now = GetTickCount64();
    ULONGLONG lastAC = g_acThreadTs.load();
    ULONGLONG lastWD = g_wdThreadTs.load();

    bool acDead = (lastAC != 0 && (now - lastAC) > WD_TIMEOUT_MS);
    bool wdDead = (lastWD != 0 && (now - lastWD) > WD_TIMEOUT_MS);

    if (acDead && wdDead) {
        ACDetect("Game-loop watchdog: both AC threads suspended");
    }
    else if (acDead) {
        ACDetect("Game-loop watchdog: ACThread suspended");
    }
    else if (wdDead) {
        ACDetect("Game-loop watchdog: WatchdogThread suspended");
    }
}

// ============================================================
// INIT
// ============================================================
void ACInit()
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (k32) {
        BYTE* f;
        f = (BYTE*)GetProcAddress(k32, "ReadProcessMemory");
        if (f) memcpy(s_origRPM, f, 8);
        f = (BYTE*)GetProcAddress(k32, "WriteProcessMemory");
        if (f) memcpy(s_origWPM, f, 8);
    }

    BYTE* base = (BYTE*)GetModuleHandleA(nullptr);
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            s_codeStart = base + sec->VirtualAddress;
            s_codeSize = sec->Misc.VirtualSize;
            s_codeCrc = CalcCRC32(s_codeStart, s_codeSize);
            s_codeBackup = (BYTE*)HeapAlloc(GetProcessHeap(), 0, s_codeSize);
            if (s_codeBackup) memcpy(s_codeBackup, s_codeStart, s_codeSize);
            break;
        }
    }

    ACSetPaused(false);
    ACSetPowerWeapon(false);

    ACWriteEnc(g_encHp, 100);
    ACWriteEnc(g_encAmmo, 30);
    ACWriteEnc(g_encScore, 0);
    ACWriteEnc(g_encKills, 0);
    ACWriteEnc(g_encWave, 1);

    s_acInitDone.store(true);

    ACCheckDebugger();
    ACCheckProcesses();
    ACCheckWindows();

    CreateThread(nullptr, 0, [](LPVOID) -> DWORD { ACThread(); return 0; }, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, WatchdogThread, nullptr, 0, nullptr);
}