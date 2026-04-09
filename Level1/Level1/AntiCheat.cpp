#include "AntiCheat.h"
#include <string>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

// ============================================================
//  PROCESS BLACKLIST
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
//  GLOBALS
// ============================================================
std::atomic<bool> g_acDetected(false);
std::string       g_acReason;

std::atomic<int>  g_totalDamageDealt(0);
std::atomic<int>  g_totalHealed(0);
std::atomic<int>  g_shotsFired(0);
std::atomic<int>  g_ammoConsumed(0);
std::atomic<int>  g_ammoRefilled(0);

static BYTE       s_origRPM[8] = {};
static BYTE       s_origWPM[8] = {};
static DWORD      s_codeCrc = 0;
static BYTE* s_codeStart = nullptr;
static SIZE_T     s_codeSize = 0;

// ============================================================
//  CRC32
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
//  DETECT
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
//  PROCESS SCAN
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
                found = true;
                break;
            }

            for (auto& sub : s_substringBL) {
                if (name.find(sub) != std::string::npos) {
                    ACDetect("Blacklisted process ('" + sub + "'): " + std::string(pe.szExeFile));
                    found = true;
                    break;
                }
            }
        } while (!found && Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return found;
}

// ============================================================
//  WINDOW TITLE SCAN
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
            p->found = true;
            p->title = title;
            return FALSE;
        }
    }
    return TRUE;
}

static bool ACCheckWindows()
{
    WndScanResult r = { false, "" };
    EnumWindows(EnumWndCb, (LPARAM)&r);
    if (r.found) {
        ACDetect("Suspicious window: \"" + r.title + "\"");
        return true;
    }
    return false;
}

// ============================================================
//  DEBUGGER DETECTION
// ============================================================
static bool ACCheckDebugger()
{
    if (IsDebuggerPresent()) {
        ACDetect("Debugger (IsDebuggerPresent)");
        return true;
    }

    typedef NTSTATUS(WINAPI* NtQIP_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto fn = ntdll ? (NtQIP_t)GetProcAddress(ntdll, "NtQueryInformationProcess") : nullptr;
    if (fn) {
        DWORD port = 0;
        if (NT_SUCCESS(fn(GetCurrentProcess(), 7, &port, sizeof(port), nullptr)) && port) {
            ACDetect("Debugger (DebugPort)");
            return true;
        }
    }

#ifdef _WIN64
    ULONG_PTR peb = __readgsqword(0x60);
    ULONG     flag = *(ULONG*)(peb + 0xBC);
#else
    ULONG_PTR peb = (ULONG_PTR)__readfsdword(0x30);
    ULONG     flag = *(ULONG*)(peb + 0x68);
#endif

    if (flag & 0x70) {
        ACDetect("Debugger (NtGlobalFlag)");
        return true;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
        ACDetect("Hardware breakpoints (DR0-DR3)");
        return true;
    }

    return false;
}

// ============================================================
//  HP FREEZE DETECTION
// ============================================================
static bool ACCheckHpFreeze()
{
    if (g_gameOver || g_paused) return false;

    int dealt = g_totalDamageDealt.load();
    int healed = g_totalHealed.load();
    int hpNow = 0;

    // Read current HP from the game (extern from game translation unit)
    extern volatile int g_playerHp;
    hpNow = g_playerHp;

    int expected = 100 - dealt + healed;
    if (expected < 0)   expected = 0;
    if (expected > 100) expected = 100;

    if (hpNow > expected + 15) {
        char buf[128];
        sprintf_s(buf, "HP freeze (hp=%d expected=%d dealt=%d healed=%d)",
            hpNow, expected, dealt, healed);
        ACDetect(buf);
        return true;
    }
    return false;
}

// ============================================================
//  AMMO FREEZE DETECTION
// ============================================================
static bool ACCheckAmmoFreeze()
{
    if (g_gameOver || g_paused || g_powerWeapon) return false;

    int shots = g_shotsFired.load();
    int consumed = g_ammoConsumed.load();
    int gap = shots - consumed;

    if (gap > 5) {
        ACDetect("Ammo freeze (shots=" + std::to_string(shots)
            + " consumed=" + std::to_string(consumed)
            + " gap=" + std::to_string(gap) + ")");
        return true;
    }
    return false;
}

// ============================================================
//  HOOK DETECTION
// ============================================================
static bool ACCheckHooks()
{
    struct FuncEntry { const char* mod; const char* fn; };
    static const FuncEntry targets[] = {
        { "kernel32.dll", "ReadProcessMemory"  },
        { "kernel32.dll", "WriteProcessMemory" },
        { "kernel32.dll", "OpenProcess"        },
        { "kernel32.dll", "VirtualProtect"     },
        { "kernel32.dll", "CreateRemoteThread" },
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
            ACDetect("ReadProcessMemory hooked mid-session");
            return true;
        }
        BYTE* wpm = (BYTE*)GetProcAddress(k32, "WriteProcessMemory");
        if (wpm && memcmp(s_origWPM, wpm, 8)) {
            ACDetect("WriteProcessMemory hooked mid-session");
            return true;
        }
    }

    return false;
}

// ============================================================
//  CODE INTEGRITY
// ============================================================
static bool ACCheckCodeIntegrity()
{
    if (!s_codeStart || s_codeSize == 0) return false;

    DWORD current = CalcCRC32(s_codeStart, s_codeSize);
    if (current != s_codeCrc) {
        char buf[64];
        sprintf_s(buf, "Code integrity (expected %08X got %08X)", s_codeCrc, current);
        ACDetect(buf);
        return true;
    }
    return false;
}

// ============================================================
//  BACKGROUND THREAD
// ============================================================
static void ACThread()
{
    int tick = 0;
    while (!g_acDetected) {
        ACCheckProcesses();
        ACCheckWindows();
        ACCheckDebugger();
        ACCheckHpFreeze();
        ACCheckAmmoFreeze();
        ACCheckHooks();
        if (tick % 3 == 0) ACCheckCodeIntegrity();
        tick++;
        Sleep(1000);
    }
}

// ============================================================
//  INIT
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

    HMODULE self = GetModuleHandleA(nullptr);
    BYTE* base = (BYTE*)self;
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            s_codeStart = base + sec->VirtualAddress;
            s_codeSize = sec->Misc.VirtualSize;
            s_codeCrc = CalcCRC32(s_codeStart, s_codeSize);
            break;
        }
    }

    ACCheckDebugger();
    ACCheckProcesses();
    ACCheckWindows();

    std::thread(ACThread).detach();
}