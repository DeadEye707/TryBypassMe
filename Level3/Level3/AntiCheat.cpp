#include "AntiCheat.h"
#include "skCrypter.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <intrin.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#define AC_DEBUG_BUILD

// ============================================================
// PROCESS BLACKLIST
// ============================================================
static const std::unordered_set<std::string> s_exactBL = {
    skStr("cheatengine-x86_64.exe"), skStr("cheatengine-x86_64-sse4-avx2.exe"),
    skStr("cheatengine-i386.exe"),   skStr("cheatengine.exe"),
    skStr("cetrainer.exe"),          skStr("ce64.exe"),
    skStr("x64dbg.exe"),             skStr("x32dbg.exe"),
    skStr("cpudbg64.exe"),           skStr("asmdbg32.exe"),   skStr("asmdbg64.exe"),
    skStr("ollydbg.exe"),            skStr("ollydbg2.exe"),   skStr("odbg200.exe"),
    skStr("idaq.exe"),               skStr("idaq64.exe"),     skStr("ida.exe"),
    skStr("ida64.exe"),              skStr("idaw.exe"),        skStr("idaw64.exe"),
    skStr("ida_weasel.exe"),
    skStr("windbg.exe"),             skStr("windbgx.exe"),    skStr("cdb.exe"),
    skStr("ntsd.exe"),               skStr("kd.exe"),
    skStr("hyperdbg.exe"),           skStr("hyperdbg-cli.exe"),
    skStr("ghidra.exe"),             skStr("ghidrarun.exe"),  skStr("binaryninja.exe"),
    skStr("binja.exe"),              skStr("cutter.exe"),      skStr("radare2.exe"),
    skStr("r2.exe"),
    skStr("dnspy.exe"),              skStr("ilspy.exe"),       skStr("dotpeek.exe"),
    skStr("dotpeek64.exe"),          skStr("justdecompile.exe"),
    skStr("artmoney.exe"),           skStr("artmoney7.exe"),   skStr("artmoney8.exe"),
    skStr("tsearch.exe"),
    skStr("squalr.exe"),             skStr("pkhex.exe"),       skStr("winhex.exe"),
    skStr("hxd.exe"),                skStr("010editor.exe"),
    skStr("processhacker.exe"),      skStr("processhacker2.exe"),
    skStr("systeminformer.exe"),
    skStr("procmon.exe"),            skStr("procmon64.exe"),   skStr("procexp.exe"),
    skStr("procexp64.exe"),
    skStr("extremeinjector.exe"),    skStr("xenos.exe"),       skStr("xenos64.exe"),
    skStr("ghinject.exe"),           skStr("nightshade.exe"),  skStr("winject.exe"),
    skStr("remotedll.exe"),
    skStr("scylla.exe"),             skStr("scylla_x64.exe"),  skStr("scylla_x86.exe"),
    skStr("importrec.exe"),
    skStr("lordpe.exe"),             skStr("peid.exe"),        skStr("pestudio.exe"),
    skStr("pe-bear.exe"),            skStr("peview.exe"),       skStr("cffexplorer.exe"),
    skStr("reclass.exe"),            skStr("reclass64.exe"),   skStr("reclass.net.exe"),
    skStr("reclassex.exe"),
    skStr("wireshark.exe"),          skStr("fiddler.exe"),     skStr("fiddler4.exe"),
    skStr("charles.exe"),            skStr("mitmproxy.exe"),
    skStr("wemod.exe"),              skStr("trainmanager.exe"),
    skStr("scyllahide.exe"),         skStr("titanhide.exe"),   skStr("hyperhide.exe"),
    skStr("strongod.exe"),
    skStr("cheatdb.exe"),            skStr("gameguardian.exe"),
};

static const std::vector<std::string> s_substringBL = {
    skStr("cheatengine"),  skStr("cheat-engine"), skStr("ollydbg"),
    skStr("scyllahide"),   skStr("titanhide"),     skStr("reclass"),
    skStr("wireshark"),    skStr("extremeinjector"),skStr("processhacker"),
    skStr("systeminformer"),skStr("wemod"),        skStr("radare2"),
    skStr("hyperdbg"),
};

// ============================================================
// GLOBALS
// ============================================================
AcToken      g_acToken = {};
std::string  g_acReason;

uint32_t* g_pCtrKey1 = nullptr;
uint32_t* g_pCtrKey2 = nullptr;

EncCounter* g_pDmgCounter = nullptr;
EncCounter* g_pHealCounter = nullptr;
EncCounter* g_pShotsFiredCounter = nullptr;
EncCounter* g_pAmmoConsumedCounter = nullptr;
EncCounter* g_pAmmoRefilledCounter = nullptr;
EncCounter* g_pGameOverFlag = nullptr;
bool        g_gameOverLegacy = false;

std::atomic<uint32_t> g_gameTick(0);

uint32_t* g_pXorKey1 = nullptr;
uint32_t* g_pXorKey2 = nullptr;

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
std::atomic<ULONGLONG> g_powerWeaponActivatedTs(0);

std::atomic<ULONGLONG> g_acThreadTs(0);
std::atomic<ULONGLONG> g_wdThreadTs(0);
std::atomic<ULONGLONG> g_crcThreadTs(0);

uint32_t* g_pAcThreadCookie = nullptr;
uint32_t* g_pWdThreadCookie = nullptr;
uint32_t* g_pCrcThreadCookie = nullptr;

std::atomic<uint32_t>  g_acCookieEcho(0);
std::atomic<uint32_t>  g_wdCookieEcho(0);
std::atomic<uint32_t>  g_crcCookieEcho(0);

std::atomic<ULONGLONG> g_acEchoTs(0);
std::atomic<ULONGLONG> g_wdEchoTs(0);
std::atomic<ULONGLONG> g_crcEchoTs(0);

uint32_t* g_pCrcSlot0 = nullptr;
uint32_t* g_pCrcSlot1 = nullptr;
uint32_t* g_pCrcSlot2 = nullptr;
uint32_t* g_pCrcSessionKey = nullptr;

// Disk CRC  (heap-encrypted, dual-key)
uint32_t* g_pDiskCrcKey = nullptr;
uint32_t* g_pDiskCrcEnc = nullptr;
uint32_t* g_pDiskCrcShadow = nullptr;

std::atomic<bool> g_dllBaselineReady(false);

static BYTE* s_codeStart = nullptr;
static SIZE_T  s_codeSize = 0;
static BYTE* s_codeBackup = nullptr;

static BYTE s_origRPM[8] = {};
static BYTE s_origWPM[8] = {};

static constexpr DWORD WD_TIMEOUT_MS = 4000;

static std::atomic<bool> s_wdReady(false);
static std::atomic<bool> s_acInitDone(false);

// Pipe IPC state
static HANDLE              s_hPipe = INVALID_HANDLE_VALUE;
static std::atomic<DWORD>  s_wdPid(0);       // watchdog process ID
static std::atomic<ULONGLONG> s_lastPipeTs(0);
static uint32_t            s_pipeSessionKey = 0;
static std::atomic<uint32_t> s_pipeSeq(0);

// Watchdog connection deadline — game must have a connected watchdog
// within this many ms of ACInit completing, or it kills itself.
static constexpr DWORD WD_CONNECT_DEADLINE_MS = 12000;
static std::atomic<ULONGLONG> s_acInitTs(0); // timestamp when ACInit finished
static std::atomic<bool> s_wdHandshakeDone(false);

// DLL baseline snapshot
struct ModEntry { uint32_t nameHash; char fullPath[MAX_PATH]; };
static std::vector<ModEntry> s_dllBaseline;

// DLL signature verification cache (avoids re-calling WinVerifyTrust)
static std::unordered_set<uint32_t> s_signedDllCache;
static std::unordered_set<uint32_t> s_unsignedDllCache;

// Re-keying epoch for disk CRC (rotated every ~30 s)
static std::atomic<uint32_t> s_diskCrcEpoch(0);

// ============================================================
//  HELPERS
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

static uint32_t SimpleHash(const char* s)
{
    uint32_t h = 0x811C9DC5u;
    while (*s) { h ^= (uint8_t)*s++; h *= 0x01000193u; }
    return h;
}

static DWORD CalcDiskCrc()
{
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, MAX_PATH);

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD crc = 0xFFFFFFFF;
    BYTE  buf[4096];
    DWORD read = 0;
    while (ReadFile(hFile, buf, sizeof(buf), &read, nullptr) && read > 0) {
        for (DWORD i = 0; i < read; i++) {
            crc ^= buf[i];
            for (int j = 0; j < 8; j++)
                crc = (crc >> 1) ^ (0xEDB88320 & (DWORD)(-(int)(crc & 1)));
        }
    }
    CloseHandle(hFile);
    return ~crc;
}

static void StoreDiskCrc(uint32_t diskCrc)
{
    if (!g_pDiskCrcKey || !g_pDiskCrcEnc || !g_pDiskCrcShadow) return;
    uint32_t epoch = s_diskCrcEpoch.load(std::memory_order_relaxed);
    uint32_t k = *g_pDiskCrcKey ^ epoch;
    *g_pDiskCrcEnc = diskCrc ^ k;
    *g_pDiskCrcShadow = diskCrc ^ (~k);
}

static uint32_t LoadDiskCrc(bool* consistent = nullptr)
{
    if (!g_pDiskCrcKey || !g_pDiskCrcEnc || !g_pDiskCrcShadow) {
        if (consistent) *consistent = false;
        return 0;
    }
    uint32_t epoch = s_diskCrcEpoch.load(std::memory_order_relaxed);
    uint32_t k = *g_pDiskCrcKey ^ epoch;
    uint32_t v1 = *g_pDiskCrcEnc ^ k;
    uint32_t v2 = *g_pDiskCrcShadow ^ (~k);
    if (consistent) *consistent = (v1 == v2);
    return v1;
}

static void StoreSplitCrc(uint32_t crc)
{
    if (!g_pCrcSlot0 || !g_pCrcSlot1 || !g_pCrcSlot2 || !g_pCrcSessionKey) return;
    uint32_t sk = *g_pCrcSessionKey;
    *g_pCrcSlot0 = ((crc >> 22) & 0x3FF) ^ CRC_SLOT_MAGIC0 ^ sk;
    *g_pCrcSlot1 = ((crc >> 11) & 0x7FF) ^ CRC_SLOT_MAGIC1 ^ (sk * 3);
    *g_pCrcSlot2 = (crc & 0x7FF) ^ CRC_SLOT_MAGIC2 ^ (sk * 7);
}

static uint32_t LoadSplitCrc()
{
    if (!g_pCrcSlot0 || !g_pCrcSlot1 || !g_pCrcSlot2 || !g_pCrcSessionKey) return 0;
    uint32_t sk = *g_pCrcSessionKey;
    uint32_t b2 = (*g_pCrcSlot0 ^ CRC_SLOT_MAGIC0 ^ sk) & 0x3FF;
    uint32_t b1 = (*g_pCrcSlot1 ^ CRC_SLOT_MAGIC1 ^ (sk * 3)) & 0x7FF;
    uint32_t b0 = (*g_pCrcSlot2 ^ CRC_SLOT_MAGIC2 ^ (sk * 7)) & 0x7FF;
    return (b2 << 22) | (b1 << 11) | b0;
}

static uint32_t ComputeHmac(uint32_t magic, uint32_t seq, uint32_t sessionKey)
{
    // Simple but not trivially reversible: fnv-mix of all three words
    uint32_t h = magic ^ 0x811C9DC5u;
    h ^= seq;   h *= 0x01000193u;
    h ^= sessionKey; h *= 0x01000193u;
    h ^= (magic >> 16); h *= 0x01000193u;
    return h;
}

// ============================================================
// DETECT
// ============================================================
void ACDetect(const std::string& reason)
{
    AcTokenWrite(g_acToken, AC_TOKEN_DETECTED);
    g_acReason = reason;
    ACGameOverSet(true);

    std::string* msg = new std::string(
        skStr("[!] CHEAT DETECTED\n\nReason: ") + reason +
        skStr("\n\nGame will terminate."));

    CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* m = (std::string*)p;
        MessageBoxA(nullptr, m->c_str(), skStr("Anti-Cheat"),
            MB_ICONERROR | MB_OK | MB_TOPMOST | MB_SYSTEMMODAL);
        delete m;
        return 0;
        }, msg, 0, nullptr);

    Sleep(5000);
    TerminateProcess(GetCurrentProcess(), 1);
    typedef LONG(NTAPI* pNtTerminate)(HANDLE, LONG);
    pNtTerminate ntTerm = (pNtTerminate)GetProcAddress(
        GetModuleHandleA(skStr("ntdll.dll")), skStr("NtTerminateProcess"));
    if (ntTerm) ntTerm(GetCurrentProcess(), 1);
    ExitProcess(1);
    for (;;) { TerminateProcess(GetCurrentProcess(), 1); Sleep(10); }
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

    if (Process32First(snap, &pe)) {
        do {
            std::string name = ToLower(pe.szExeFile);
            if (s_exactBL.count(name)) {
                CloseHandle(snap);
                char buf[256];
                sprintf_s(buf,
                    skStr("[!] CHEAT DETECTED\n\nReason: Blacklisted process: %s\n\nGame will terminate."),
                    pe.szExeFile);
                ACInlineKill(buf);
                return true;
            }
            for (auto& sub : s_substringBL) {
                if (name.find(sub) != std::string::npos) {
                    CloseHandle(snap);
                    char buf[256];
                    sprintf_s(buf,
                        skStr("[!] CHEAT DETECTED\n\nReason: Blacklisted process ('%s'): %s\n\nGame will terminate."),
                        sub.c_str(), pe.szExeFile);
                    ACInlineKill(buf);
                    return true;
                }
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return false;
}

// ============================================================
// WINDOW TITLE SCAN
// ============================================================
struct WndScanResult { bool found; char title[512]; };

static BOOL CALLBACK EnumWndCb(HWND hwnd, LPARAM lp)
{
    auto* p = (WndScanResult*)lp;
    char title[512] = {};
    GetWindowTextA(hwnd, title, sizeof(title));
    std::string t = ToLower(title);

    const char* keys[] = {
        skStr("cheat engine"), skStr("cheatengine"), skStr("x64dbg"), skStr("x32dbg"),
        skStr("ollydbg"),      skStr("process hacker"), skStr("system informer"),
        skStr("scylla"),       skStr("reclass"),     skStr("wireshark"),
        skStr("fiddler"),      skStr("hyperdbg"),    skStr("windbg"),
        skStr("ida pro"),      skStr("ghidra"),      skStr("binary ninja"),
        skStr("dnspy"),        skStr("wemod"),        skStr("extreme injector"),
        skStr("radare2"),      skStr("r2gui"),
        nullptr
    };
    for (int i = 0; keys[i]; i++) {
        if (t.find(keys[i]) != std::string::npos) {
            p->found = true;
            strncpy_s(p->title, title, _TRUNCATE);
            return FALSE;
        }
    }
    return TRUE;
}

static bool ACCheckWindows()
{
    WndScanResult r = { false, {} };
    EnumWindows(EnumWndCb, (LPARAM)&r);
    if (r.found) {
        char buf[600];
        sprintf_s(buf,
            skStr("[!] CHEAT DETECTED\n\nReason: Suspicious window: \"%s\"\n\nGame will terminate."),
            r.title);
        ACInlineKill(buf);
        return true;
    }
    return false;
}

// ============================================================
// DEBUGGER DETECTION
// ============================================================
static bool ACCheckDebugger()
{
    if (IsDebuggerPresent()) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Debugger (IsDebuggerPresent)\n\nGame will terminate."));
        return true;
    }

    typedef NTSTATUS(WINAPI* NtQIP_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA(skStr("ntdll.dll"));
    auto fn = ntdll ? (NtQIP_t)GetProcAddress(ntdll, skStr("NtQueryInformationProcess")) : nullptr;
    if (fn) {
        DWORD port = 0;
        if (NT_SUCCESS(fn(GetCurrentProcess(), 7, &port, sizeof(port), nullptr)) && port) {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Debugger (DebugPort)\n\nGame will terminate."));
            return true;
        }
        DWORD flags = 1;
        if (NT_SUCCESS(fn(GetCurrentProcess(), 0x1F, &flags, sizeof(flags), nullptr)) && flags == 0) {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Debugger (DebugFlags)\n\nGame will terminate."));
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
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Debugger (NtGlobalFlag)\n\nGame will terminate."));
        return true;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Hardware breakpoints (DR0-DR3)\n\nGame will terminate."));
        return true;
    }

    {
        ULONGLONG t1, t2;
        int cpuInfo[4];
        __cpuid(cpuInfo, 0);
        t1 = __rdtsc();
        __cpuid(cpuInfo, 0);
        t2 = __rdtsc();
        if ((t2 - t1) > 2000000ULL) {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Debugger (RDTSC timing)\n\nGame will terminate."));
            return true;
        }
    }

    return false;
}

// ============================================================
// CANARY + SHADOW + COUNTER INTEGRITY CHECK
// ============================================================
static bool ACCheckCanaries()
{
    if (!s_acInitDone.load()) return false;

    if (g_pausedGuard.guardPre != AC_CANARY_LO ||
        g_pausedGuard.guardPost != AC_CANARY_HI)
    {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Canary corruption (g_paused)\n\nGame will terminate."));
        return true;
    }
    if (g_powerWeaponGuard.guardPre != AC_CANARY_LO ||
        g_powerWeaponGuard.guardPost != AC_CANARY_HI)
    {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Canary corruption (g_powerWeapon)\n\nGame will terminate."));
        return true;
    }
    if ((bool)g_pausedGuard.flag != g_shadowPaused.load()) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Flag tamper: g_paused written outside setter\n\nGame will terminate."));
        return true;
    }
    if ((bool)g_powerWeaponGuard.flag != g_shadowPowerWeapon.load()) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Flag tamper: g_powerWeapon written outside setter\n\nGame will terminate."));
        return true;
    }

    struct { const EncInt* e; const char* name; } ev[] = {
        { &g_encHp,    skStr("encHp")    },
        { &g_encAmmo,  skStr("encAmmo")  },
        { &g_encScore, skStr("encScore") },
        { &g_encKills, skStr("encKills") },
        { &g_encWave,  skStr("encWave")  },
    };
    for (auto& v : ev) {
        if (v.e->canaryLo != AC_CANARY_LO || v.e->canaryHi != AC_CANARY_HI) {
            char buf[160];
            sprintf_s(buf,
                skStr("[!] CHEAT DETECTED\n\nReason: Canary corruption (%s)\n\nGame will terminate."),
                v.name);
            ACInlineKill(buf);
            return true;
        }
        if (!ACVerifyEnc(*v.e)) {
            char buf[160];
            sprintf_s(buf,
                skStr("[!] CHEAT DETECTED\n\nReason: Dual-key shadow mismatch (%s)\n\nGame will terminate."),
                v.name);
            ACInlineKill(buf);
            return true;
        }
    }

    struct { const EncCounter* c; const char* name; } cv[] = {
        { g_pDmgCounter,          skStr("damage counter")       },
        { g_pHealCounter,         skStr("heal counter")         },
        { g_pShotsFiredCounter,   skStr("shots counter")        },
        { g_pAmmoConsumedCounter, skStr("ammoConsumed counter") },
        { g_pAmmoRefilledCounter, skStr("ammoRefilled counter") },
        { g_pGameOverFlag,        skStr("gameOver flag")        },
    };
    for (auto& v : cv) {
        if (!v.c) continue;
        if (!ACCounterVerify(v.c)) {
            char buf[160];
            sprintf_s(buf,
                skStr("[!] CHEAT DETECTED\n\nReason: Counter tamper (%s)\n\nGame will terminate."),
                v.name);
            ACInlineKill(buf);
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

    int dealt = ACCounterRead(g_pDmgCounter);
    int healed = ACCounterRead(g_pHealCounter);
    int hpNow = ACReadEnc(g_encHp);
    int expected = 100 - dealt + healed;
    if (expected < 0)   expected = 0;
    if (expected > 100) expected = 100;

    if (hpNow > expected + 10) {
        char buf[160];
        sprintf_s(buf,
            skStr("[!] CHEAT DETECTED\n\nReason: HP freeze (hp=%d expected=%d dealt=%d healed=%d)\n\nGame will terminate."),
            hpNow, expected, dealt, healed);
        ACInlineKill(buf);
        return true;
    }
    return false;
}

// ============================================================
// AMMO FREEZE DETECTION
// ============================================================
static bool ACCheckAmmoFreeze()
{
    if (g_gameOver || g_paused || g_powerWeapon) return false;

    int gap = ACCounterRead(g_pShotsFiredCounter) - ACCounterRead(g_pAmmoConsumedCounter);
    if (gap > 5) {
        char buf[200];
        sprintf_s(buf,
            skStr("[!] CHEAT DETECTED\n\nReason: Ammo freeze (shots=%d consumed=%d gap=%d)\n\nGame will terminate."),
            (int)ACCounterRead(g_pShotsFiredCounter),
            (int)ACCounterRead(g_pAmmoConsumedCounter),
            gap);
        ACInlineKill(buf);
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
    const FuncEntry targets[] = {
        { skStr("kernel32.dll"), skStr("ReadProcessMemory")    },
        { skStr("kernel32.dll"), skStr("WriteProcessMemory")   },
        { skStr("kernel32.dll"), skStr("OpenProcess")          },
        { skStr("kernel32.dll"), skStr("VirtualProtect")       },
        { skStr("kernel32.dll"), skStr("CreateRemoteThread")   },
        { skStr("ntdll.dll"),    skStr("NtReadVirtualMemory")  },
        { skStr("ntdll.dll"),    skStr("NtWriteVirtualMemory") },
        { skStr("ntdll.dll"),    skStr("NtOpenProcess")        },
        { skStr("ntdll.dll"),    skStr("LdrLoadDll")           },
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
            char buf[200];
            sprintf_s(buf,
                skStr("[!] CHEAT DETECTED\n\nReason: Hook: %s!%s\n\nGame will terminate."),
                targets[i].mod, targets[i].fn);
            ACInlineKill(buf);
            return true;
        }
    }

    HMODULE k32 = GetModuleHandleA(skStr("kernel32.dll"));
    if (k32) {
        BYTE* rpm = (BYTE*)GetProcAddress(k32, skStr("ReadProcessMemory"));
        if (rpm && memcmp(s_origRPM, rpm, 8)) {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: ReadProcessMemory hooked mid-session\n\nGame will terminate."));
            return true;
        }
        BYTE* wpm = (BYTE*)GetProcAddress(k32, skStr("WriteProcessMemory"));
        if (wpm && memcmp(s_origWPM, wpm, 8)) {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: WriteProcessMemory hooked mid-session\n\nGame will terminate."));
            return true;
        }
    }
    return false;
}

// ============================================================
// CODE INTEGRITY
// ============================================================
static bool ACCheckCodeIntegrity()
{
    if (!s_codeStart || s_codeSize == 0 || !g_pCrcSessionKey) return false;

    DWORD current = CalcCRC32(s_codeStart, s_codeSize);
    DWORD expected = LoadSplitCrc();

    // expected==0 means StoreSplitCrc hasn't been called yet; skip
    if (expected == 0) return false;

    bool mismatch = (current != expected);

    if (mismatch) {
        // Attempt in-memory restore before killing
        if (s_codeBackup) {
            DWORD old;
            if (VirtualProtect(s_codeStart, s_codeSize, PAGE_EXECUTE_READWRITE, &old)) {
                memcpy(s_codeStart, s_codeBackup, s_codeSize);
                VirtualProtect(s_codeStart, s_codeSize, old, &old);
            }
        }
        char buf[160];
        sprintf_s(buf,
            skStr("[!] CHEAT DETECTED\n\nReason: Code integrity (got %08X expected %08X)\n\nGame will terminate."),
            current, expected);
        AcTokenWrite(g_acToken, AC_TOKEN_DETECTED);
        ACGameOverSet(true);
        ACInlineKill(buf);
        return true;
    }
    return false;
}

// ============================================================
// DISK INTEGRITY
// ============================================================
static bool ACCheckDiskIntegrity()
{
    bool consistent = false;
    uint32_t stored = LoadDiskCrc(&consistent);
    if (!consistent) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Disk CRC storage tampered (key mismatch)\n\nGame will terminate."));
        return true;
    }
    if (stored == 0) return false; // not yet initialised

    uint32_t current = CalcDiskCrc();
    if (current != stored) {
        char buf[160];
        sprintf_s(buf,
            skStr("[!] CHEAT DETECTED\n\nReason: Disk integrity (got %08X expected %08X)\n\nGame will terminate."),
            current, stored);
        ACInlineKill(buf);
        return true;
    }
    return false;
}

// ============================================================
// DLL INJECTION DETECTION
// ============================================================
// ---- Authenticode signature verification helper (CACHED) ----
// Returns true if the file is signed by a trusted publisher (Microsoft, etc.)
// Results are cached by path hash to avoid calling WinVerifyTrust repeatedly.
static bool IsFileSignedRaw(const char* filePath)
{
    WCHAR wPath[MAX_PATH] = {};
    MultiByteToWideChar(CP_ACP, 0, filePath, -1, wPath, MAX_PATH);

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wPath;

    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(NULL, &actionId, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionId, &trustData);

    return (status == ERROR_SUCCESS);
}

static bool IsFileSigned(const char* filePath)
{
    uint32_t h = SimpleHash(ToLower(std::string(filePath)).c_str());
    // Check caches first
    if (s_signedDllCache.count(h))   return true;
    if (s_unsignedDllCache.count(h)) return false;
    // Not cached — do the expensive check once
    bool signed_ = IsFileSignedRaw(filePath);
    if (signed_) s_signedDllCache.insert(h);
    else         s_unsignedDllCache.insert(h);
    return signed_;
}

static void ACBuildDllBaseline()
{
    s_dllBaseline.clear();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            ModEntry entry = {};
            entry.nameHash = SimpleHash(ToLower(me.szExePath).c_str());
            strncpy_s(entry.fullPath, me.szExePath, _TRUNCATE);
            s_dllBaseline.push_back(entry);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    g_dllBaselineReady.store(true);
}

static bool ACCheckDllInjection()
{
    if (!g_dllBaselineReady.load()) return false;

    // ---- 1. PEB module list scan ----
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return false;

    // Build set of known hashes
    static std::unordered_set<uint32_t> s_baselineSet;
    if (s_baselineSet.empty())
        for (auto& e : s_dllBaseline) s_baselineSet.insert(e.nameHash);

    // Build trusted directory list:
    //   - Windows directory tree (System32, SysWOW64, WinSxS, etc.)
    //   - Game directory
    //   - Program Files directories (for MSVC runtime, etc.)
    char winDir[MAX_PATH] = {};
    char gameDir[MAX_PATH] = {};
    char progFiles[MAX_PATH] = {};
    char progFilesX86[MAX_PATH] = {};

    GetWindowsDirectoryA(winDir, MAX_PATH);   // e.g. "C:\Windows"
    GetModuleFileNameA(nullptr, gameDir, MAX_PATH);
    char* lastSep = strrchr(gameDir, '\\');
    if (lastSep) *(lastSep + 1) = '\0';

    // Get Program Files paths
    if (GetEnvironmentVariableA(skStr("ProgramFiles"), progFiles, MAX_PATH) == 0)
        progFiles[0] = '\0';
    if (GetEnvironmentVariableA(skStr("ProgramFiles(x86)"), progFilesX86, MAX_PATH) == 0)
        progFilesX86[0] = '\0';

    std::string winDirLower = ToLower(winDir);
    std::string gameDirLower = ToLower(gameDir);
    std::string progFilesLower = ToLower(progFiles);
    std::string progFilesX86Lower = ToLower(progFilesX86);

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            uint32_t h = SimpleHash(ToLower(me.szExePath).c_str());
            std::string pathLower = ToLower(me.szExePath);

            // Check if this module is from a trusted directory
            bool trustedPath = false;

            // Windows directory tree (covers System32, SysWOW64, WinSxS, etc.)
            if (!winDirLower.empty() && pathLower.find(winDirLower) == 0)
                trustedPath = true;

            // Game directory
            if (!gameDirLower.empty() && pathLower.find(gameDirLower) == 0)
                trustedPath = true;

            // Program Files (MSVC runtime, etc.)
            if (!progFilesLower.empty() && pathLower.find(progFilesLower) == 0)
                trustedPath = true;
            if (!progFilesX86Lower.empty() && pathLower.find(progFilesX86Lower) == 0)
                trustedPath = true;

            if (!s_baselineSet.count(h)) {
                // New module loaded after baseline.
                // Windows lazily loads many DLLs (sechost.dll, uxtheme.dll, etc.)
                // so we only flag modules from UNTRUSTED paths.
                if (trustedPath) {
                    // Trusted OS/game DLL loaded late — add to baseline silently
                    s_baselineSet.insert(h);
                }
                else if (pathLower.find(skStr(".dll")) != std::string::npos) {
                    // New DLL from untrusted path — check signature
                    if (IsFileSigned(me.szExePath)) {
                        // Signed by a trusted publisher — allow it
                        s_baselineSet.insert(h);
                    }
                    else {
                        // Unsigned DLL from untrusted path = injection
                        CloseHandle(snap);
                        char buf[MAX_PATH + 128];
                        sprintf_s(buf,
                            skStr("[!] CHEAT DETECTED\n\nReason: DLL injected: %s\n\nGame will terminate."),
                            me.szExePath);
                        ACInlineKill(buf);
                        return true;
                    }
                }
            }
            else {
                // Module was in baseline — verify it's still from a trusted path
                // (catches renamed injected DLLs that hijacked a baseline entry)
                if (!trustedPath && pathLower.find(skStr(".dll")) != std::string::npos) {
                    if (!IsFileSigned(me.szExePath)) {
                        CloseHandle(snap);
                        char buf[MAX_PATH + 128];
                        sprintf_s(buf,
                            skStr("[!] CHEAT DETECTED\n\nReason: Untrusted unsigned module: %s\n\nGame will terminate."),
                            me.szExePath);
                        ACInlineKill(buf);
                        return true;
                    }
                }
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);

    // ---- 2. Manual-map / anonymous executable region scan ----
    // Scan the process VAD for PAGE_EXECUTE* regions with no module backing.
    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t addr = 0;
    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT
            && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            && mbi.Type == MEM_PRIVATE)
        {
            // Private + executable = anonymous allocation; could be manual-mapped
            // Allow the stack region, TLS, and very small allocations (<4KB)
            if (mbi.RegionSize > 0x1000) {
                // Check if it's one of ours: s_codeStart region or heap executable
                bool isCode = ((uintptr_t)s_codeStart >= addr
                    && (uintptr_t)s_codeStart < addr + mbi.RegionSize);
                if (!isCode) {
                    char buf[128];
                    sprintf_s(buf,
                        skStr("[!] CHEAT DETECTED\n\nReason: Anonymous executable region @ %p (%zu bytes)\n\nGame will terminate."),
                        mbi.BaseAddress, mbi.RegionSize);
                    ACInlineKill(buf);
                    return true;
                }
            }
        }
        addr += mbi.RegionSize;
        if (addr == 0) break; // wrapped around
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
    ULONG               HandleCount;
    SYSTEM_HANDLE_ENTRY Handles[1];
};

static bool ACCheckHandles()
{
#ifdef AC_DEBUG_BUILD
    return false;
#endif
    typedef NTSTATUS(WINAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    typedef NTSTATUS(WINAPI* NtDupObj_t)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
    HMODULE ntdll = GetModuleHandleA(skStr("ntdll.dll"));
    if (!ntdll) return false;
    auto NtQSI = (NtQSI_t)GetProcAddress(ntdll, skStr("NtQuerySystemInformation"));
    auto NtDupObj = (NtDupObj_t)GetProcAddress(ntdll, skStr("NtDuplicateObject"));
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

    // Whitelist: the watchdog PID is allowed to hold a handle to us
    DWORD wdPid = s_wdPid.load();

    auto* info = (SYSTEM_HANDLE_INFORMATION*)s_buf;
    for (ULONG i = 0; i < info->HandleCount; i++) {
        const auto& h = info->Handles[i];
        if (h.OwnerPid == myPid)          continue;
        if (h.OwnerPid == wdPid)          continue; // watchdog is trusted
        if (!(h.AccessMask & SUSPICIOUS)) continue;

        // Try OpenProcess; if it fails (elevated attacker), try NtDuplicateObject
        HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, h.OwnerPid);
        if (!hOwner && NtDupObj) {
            // Even though we can't OpenProcess on elevated processes,
            // NtQuerySystemInformation already told us the handle exists
            // with suspicious access to a process object.
            // We can cross-reference by checking if the object type is "Process"
            // and the access mask includes VM_READ | VM_WRITE.
            // Since we can't dup the handle, check via object type index.
            // Type 7 is typically "Process" on Windows 10/11.
            if (h.ObjectType == 7 && (h.AccessMask & (0x0010 | 0x0020 | 0x0008))) {
                // Can't definitively confirm it targets us without dup,
                // but a process handle with VM_READ|VM_WRITE from an elevated
                // process is highly suspicious. Log but don't kill (could be
                // a system service). We'll rely on the other DuplicateHandle
                // path for confirmed detection.
            }
            continue;
        }
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
                sprintf_s(detBuf,
                    skStr("[!] CHEAT DETECTED\n\nReason: External process handle (pid=%lu access=%08lX)\n\nGame will terminate."),
                    (unsigned long)h.OwnerPid, (unsigned long)h.AccessMask);
                ACInlineKill(detBuf);
                return true;
            }
        }
        CloseHandle(hOwner);
    }
    return false;
}

// ============================================================
// AC TOKEN INTEGRITY
// ============================================================
static bool ACCheckTokenIntegrity()
{
    bool isClean = AcTokenIsClean(g_acToken);
    bool isDetected = AcTokenIsDetected(g_acToken);

    if (!isClean && !isDetected) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: AC token tampered (inconsistent state)\n\nGame will terminate."));
        return true;
    }
    if (isDetected) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Deferred detection enforced by token\n\nGame will terminate."));
        return true;
    }
    return false;
}

// ============================================================
// WATCHDOG PROCESS LIVENESS CHECK
// ============================================================
static bool ACCheckWatchdogLiveness()
{
    DWORD wdPid = s_wdPid.load();
    if (wdPid == 0) return false; // not yet connected

    HANDLE hWd = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, wdPid);
    if (!hWd) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog process terminated\n\nGame will terminate."));
        return true;
    }
    DWORD exitCode = STILL_ACTIVE;
    GetExitCodeProcess(hWd, &exitCode);

    // Verify the watchdog image name contains "WatchdogMain"
    // Prevents attacker from killing real watchdog and spawning
    // a dummy process with the same PID reuse
    char wdImagePath[MAX_PATH] = {};
    DWORD wdPathLen = MAX_PATH;
    if (QueryFullProcessImageNameA(hWd, 0, wdImagePath, &wdPathLen)) {
        std::string wdLower = ToLower(wdImagePath);
        if (wdLower.find(skStr("watchdogmain")) == std::string::npos) {
            CloseHandle(hWd);
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog process replaced (image mismatch)\n\nGame will terminate."));
            return true;
        }
    }

    CloseHandle(hWd);
    if (exitCode != STILL_ACTIVE) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog process exited\n\nGame will terminate."));
        return true;
    }
    return false;
}

// ============================================================
// PIPE HEARTBEAT CHECK
// ============================================================
static bool ACCheckPipeHeartbeat()
{
    if (s_hPipe == INVALID_HANDLE_VALUE) return false;

    ULONGLONG now = GetTickCount64();
    ULONGLONG last = s_lastPipeTs.load();

    if (last != 0 && now > last && (now - last) > WD_PIPE_TIMEOUT_MS) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog pipe heartbeat timeout\n\nGame will terminate."));
        return true;
    }
    return false;
}

// ============================================================
// DISK CRC EPOCH RE-KEY
// ============================================================
static void ACRekeyDiskCrc()
{
    if (!g_pDiskCrcKey || !g_pDiskCrcEnc || !g_pDiskCrcShadow) return;

    // Read current plaintext disk CRC before re-keying
    bool consistent = false;
    uint32_t diskCrc = LoadDiskCrc(&consistent);
    if (!consistent) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Disk CRC tampered (failed rekey consistency check)\n\nGame will terminate."));
        return;
    }

    // Advance epoch
    s_diskCrcEpoch.fetch_add(1, std::memory_order_relaxed);

    // Rotate the base key itself using the new epoch
    uint32_t epoch = s_diskCrcEpoch.load(std::memory_order_relaxed);
    *g_pDiskCrcKey = (*g_pDiskCrcKey * 0x08088405u + 1u) ^ epoch;
    if (*g_pDiskCrcKey == 0) *g_pDiskCrcKey = 0xABCD1234;

    // Re-store the CRC under the new key
    StoreDiskCrc(diskCrc);
}

// ============================================================
// WATCHDOG THREAD
// ============================================================
static DWORD WINAPI WatchdogThread(LPVOID)
{
    while (!s_wdReady.load()) Sleep(50);

    while (true) {
        if (g_pWdThreadCookie) {
            ULONGLONG ts = GetTickCount64();
            g_wdCookieEcho.store(*g_pWdThreadCookie ^ (uint32_t)ts);
            g_wdEchoTs.store(ts);
        }
        g_wdThreadTs.store(GetTickCount64());

        Sleep(WD_TIMEOUT_MS / 2);

        ULONGLONG lastAC = g_acThreadTs.load();
        if (lastAC != 0 && GetTickCount64() > lastAC && (GetTickCount64() - lastAC) > WD_TIMEOUT_MS) {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog: ACThread suspended or killed\n\nGame will terminate."));
            return 0;
        }
    }
    return 0;
}

// ============================================================
// PIPE DEADLINE THREAD
// ============================================================
static DWORD WINAPI PipeDeadlineThread(LPVOID)
{
    Sleep(WD_CONNECT_DEADLINE_MS);
    if (!s_wdHandshakeDone.load()) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog did not connect (timeout)\n\nThis may be caused by:\n- Invalid EXPECTED_GAME_HASH (rebuild watchdog after game changes)\n- Pre-run patching of game executable\n- WatchdogMain.exe missing or corrupted\n\nGame will terminate."));
    }
    return 0;
}

// ============================================================
// PIPE SERVER THREAD
// ============================================================
static DWORD WINAPI PipeServerThread(LPVOID)
{
    char pipeName[64];
    sprintf_s(pipeName, skStr("\\\\.\\pipe\\TBM_WD_%lu"), GetCurrentProcessId());

    s_hPipe = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, sizeof(WdMsg) * 8, sizeof(WdMsg) * 8,
        5000, nullptr);

    if (s_hPipe == INVALID_HANDLE_VALUE) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Could not create watchdog pipe\n\nGame will terminate."));
        return 0;
    }

    // Block until watchdog connects (deadline thread enforces timeout)
    BOOL connected = ConnectNamedPipe(s_hPipe, nullptr);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog did not connect\n\nGame will terminate."));
        return 0;
    }

    WdMsg handshake = {};
    handshake.magic = WD_MSG_MAGIC;
    handshake.seq = 0;
    handshake.hmac = ComputeHmac(WD_MSG_MAGIC, 0, s_pipeSessionKey);
    handshake._pad = 0;
    DWORD written = 0;
    if (!WriteFile(s_hPipe, &handshake, sizeof(handshake), &written, nullptr)) {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog handshake write failed\n\nGame will terminate."));
        return 0;
    }

    WdMsg resp = {};
    DWORD read = 0;
    if (!ReadFile(s_hPipe, &resp, sizeof(resp), &read, nullptr)
        || read != sizeof(resp)
        || resp.magic != WD_MSG_MAGIC
        || resp.seq != 1
        || resp.hmac != ComputeHmac(WD_MSG_MAGIC, 1, s_pipeSessionKey))
    {
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog handshake failed (bad HMAC)\n\nGame will terminate."));
        return 0;
    }

    // Handshake OK
    s_wdPid.store(resp._pad);
    s_lastPipeTs.store(GetTickCount64());
    s_pipeSeq.store(2);
    s_wdHandshakeDone.store(true);

    // Heartbeat loop
    while (true) {
        WdMsg msg = {};
        DWORD r2 = 0;
        if (!ReadFile(s_hPipe, &msg, sizeof(msg), &r2, nullptr) || r2 != sizeof(msg)) {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog pipe read error\n\nGame will terminate."));
            return 0;
        }

        uint32_t expectedSeq = s_pipeSeq.load();
        uint32_t expectedHmac = ComputeHmac(msg.magic, msg.seq, s_pipeSessionKey);

        if (msg.magic != WD_MSG_MAGIC
            || msg.seq != expectedSeq
            || msg.hmac != expectedHmac)
        {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog heartbeat HMAC invalid (replay/forge)\n\nGame will terminate."));
            return 0;
        }

        s_pipeSeq.store(expectedSeq + 1);
        s_lastPipeTs.store(GetTickCount64());
    }
    return 0;
}

// ============================================================
// CRC THREAD
// ============================================================
static DWORD WINAPI CrcThread(LPVOID)
{
    Sleep(1300);

    while (true) {
        if (g_pCrcThreadCookie) {
            ULONGLONG ts = GetTickCount64();
            g_crcCookieEcho.store(*g_pCrcThreadCookie ^ (uint32_t)ts);
            g_crcEchoTs.store(ts);
        }
        g_crcThreadTs.store(GetTickCount64());

        if (s_codeStart && s_codeSize) {
            DWORD cur = CalcCRC32(s_codeStart, s_codeSize);
            DWORD exp = LoadSplitCrc();
            if (exp != 0 && cur != exp) {
                char buf[128];
                sprintf_s(buf,
                    skStr("[!] CHEAT DETECTED\n\nReason: CRC thread: code integrity (got %08X expected %08X)\n\nGame will terminate."),
                    cur, exp);
                if (s_codeBackup) {
                    DWORD old;
                    if (VirtualProtect(s_codeStart, s_codeSize, PAGE_EXECUTE_READWRITE, &old)) {
                        memcpy(s_codeStart, s_codeBackup, s_codeSize);
                        VirtualProtect(s_codeStart, s_codeSize, old, &old);
                    }
                }
                AcTokenWrite(g_acToken, AC_TOKEN_DETECTED);
                ACGameOverSet(true);
                char* copy = _strdup(buf);
                CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
                    MessageBoxA(nullptr, (const char*)p, skStr("Anti-Cheat"),
                        MB_ICONERROR | MB_OK | MB_TOPMOST | MB_SYSTEMMODAL);
                    free(p);
                    return 0;
                    }, copy, 0, nullptr);
                Sleep(3000);
                TerminateProcess(GetCurrentProcess(), 1);
                // Fallback: direct ntdll call bypasses IAT hooks
                typedef LONG(NTAPI* pNtTerminate)(HANDLE, LONG);
                pNtTerminate ntTerm = (pNtTerminate)GetProcAddress(
                    GetModuleHandleA(skStr("ntdll.dll")), skStr("NtTerminateProcess"));
                if (ntTerm) ntTerm(GetCurrentProcess(), 1);
                ExitProcess(1);
                for (;;) { TerminateProcess(GetCurrentProcess(), 1); Sleep(10); }
            }
        }
        // Refresh cookie after potentially slow CRC computation
        if (g_pCrcThreadCookie) {
            ULONGLONG ts2 = GetTickCount64();
            g_crcCookieEcho.store(*g_pCrcThreadCookie ^ (uint32_t)ts2);
            g_crcEchoTs.store(ts2);
        }
        g_crcThreadTs.store(GetTickCount64());

        DWORD interval = 1800 + (GetTickCount64() % 600);
        Sleep(interval);
    }
    return 0;
}

// ============================================================
// AC MAIN THREAD
// ============================================================
static void ACThread()
{
    int      tick = 0;
    ULONGLONG lastRekeyTs = GetTickCount64();
    ULONGLONG lastDiskCheck = GetTickCount64();

    g_acThreadTs.store(GetTickCount64());
    s_wdReady.store(true);

    while (true) {
        if (g_pAcThreadCookie) {
            ULONGLONG ts = GetTickCount64();
            g_acCookieEcho.store(*g_pAcThreadCookie ^ (uint32_t)ts);
            g_acEchoTs.store(ts);
        }
        g_acThreadTs.store(GetTickCount64());

        ULONGLONG lastWD = g_wdThreadTs.load();
        if (lastWD != 0 && GetTickCount64() > lastWD && (GetTickCount64() - lastWD) > WD_TIMEOUT_MS) {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: ACThread: WatchdogThread suspended or killed\n\nGame will terminate."));
            return;
        }

        // Randomised check order
        uint32_t entropy = (uint32_t)GetTickCount64() ^ (uint32_t)(uintptr_t)&tick;
        int order[7] = { 0, 1, 2, 3, 4, 5, 6 };
        for (int i = 6; i > 0; i--) {
            int j = (entropy >> i) % (i + 1);
            int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
        }

        for (int i = 0; i < 7; i++) {
            switch (order[i]) {
            case 0: ACCheckCanaries();      break;
            case 1: ACCheckHpFreeze();      break;
            case 2: ACCheckAmmoFreeze();    break;
            case 3: ACCheckHooks();         break;
            case 4:
                if (tick % 2 == 0) ACCheckProcesses();
                else               ACCheckWindows();
                break;
            case 5:
                if (tick % 2 == 0) ACCheckDebugger();
                break;
            case 6:
                if (tick % 5 == 0) ACCheckDllInjection();
                break;
            }
        }

        // Mid-loop cookie refresh: keep cookie fresh after expensive checks
        // (DLL injection with Authenticode verification can take seconds)
        if (g_pAcThreadCookie) {
            ULONGLONG ts = GetTickCount64();
            g_acCookieEcho.store(*g_pAcThreadCookie ^ (uint32_t)ts);
            g_acEchoTs.store(ts);
        }
        g_acThreadTs.store(GetTickCount64());

        if (tick % 4 == 0)  ACCheckCodeIntegrity();

        // Refresh cookie between heavy checks
        if (g_pAcThreadCookie) {
            ULONGLONG ts2 = GetTickCount64();
            g_acCookieEcho.store(*g_pAcThreadCookie ^ (uint32_t)ts2);
            g_acEchoTs.store(ts2);
        }
        g_acThreadTs.store(GetTickCount64());

        if (tick % 10 == 0) ACCheckHandles();

        // Refresh cookie after handle scan (can take seconds on busy systems)
        if (g_pAcThreadCookie) {
            ULONGLONG ts3 = GetTickCount64();
            g_acCookieEcho.store(*g_pAcThreadCookie ^ (uint32_t)ts3);
            g_acEchoTs.store(ts3);
        }
        g_acThreadTs.store(GetTickCount64());

        if (tick % 6 == 0)  ACCheckWatchdogLiveness();

        // Redundant token check from AC thread
        ACCheckTokenIntegrity();

        // Redundant pipe heartbeat check from AC thread
        if (tick % 4 == 0) ACCheckPipeHeartbeat();

        // Periodic disk check (every ~15 s)
        {
            ULONGLONG now = GetTickCount64();
            if (now > lastDiskCheck && (now - lastDiskCheck) > 15000) {
                ACCheckDiskIntegrity();
                lastDiskCheck = now;
            }
        }

        // Periodic disk CRC re-key (every ~30 s)
        {
            ULONGLONG now = GetTickCount64();
            if (now > lastRekeyTs && (now - lastRekeyTs) > 30000) {
                ACRekeyDiskCrc();
                lastRekeyTs = now;
            }
        }

        // Final cookie refresh before sleep
        if (g_pAcThreadCookie) {
            ULONGLONG ts4 = GetTickCount64();
            g_acCookieEcho.store(*g_pAcThreadCookie ^ (uint32_t)ts4);
            g_acEchoTs.store(ts4);
        }
        g_acThreadTs.store(GetTickCount64());

        tick++;
        DWORD sleepMs = 800 + (GetTickCount64() % 400);
        Sleep(sleepMs);
    }
}

// ============================================================
//  WATCHDOG READINESS QUERY (for splash screen)
// ============================================================
bool ACIsWatchdogReady()
{
    return s_wdHandshakeDone.load(std::memory_order_acquire);
}

// ============================================================
// TICK
// ============================================================
void ACTick()
{
    g_gameTick.fetch_add(1, std::memory_order_relaxed);

    // ============================================================
    // UNCONDITIONAL CHECKS
    // ============================================================

    // ---- CHECK 1: ACInit MUST have been called ----
    // If the game has been ticking for 300+ frames (~5 seconds)
    // but ACInit was never called, this is a loader that skipped
    // our initialization. Kill immediately.
    {
        uint32_t tick = g_gameTick.load(std::memory_order_relaxed);
        if (tick > 300 && s_acInitTs.load() == 0) {
            ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Anti-cheat initialization bypassed\n\nGame will terminate."));
            return;
        }
    }

    // ---- CHECK 2: Watchdog deadline (moved above s_wdReady gate) ----
    {
        ULONGLONG initTs = s_acInitTs.load();
        if (initTs != 0 && !s_wdHandshakeDone.load()) {
            ULONGLONG elapsed = GetTickCount64() > initTs ? GetTickCount64() - initTs : 0;
            if (elapsed > WD_CONNECT_DEADLINE_MS) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Watchdog not connected (startup deadline exceeded)\n\nThis may be caused by:\n- Invalid EXPECTED_GAME_HASH (rebuild watchdog after game changes)\n- Pre-run patching of game executable\n- WatchdogMain.exe missing or corrupted\n\nGame will terminate."));
                return;
            }
        }
    }

    // ---- CHECK 3: Code page protection (VEH + PAGE_GUARD detection) ----
    // Our .text section must be PAGE_EXECUTE_READ. If someone set
    // PAGE_GUARD or PAGE_NOACCESS (VEH hooking technique), detect it.
    {
        static uint32_t s_pageCheckTick = 0;
        s_pageCheckTick++;
        if (s_pageCheckTick % 240 == 0) {
            MEMORY_BASIC_INFORMATION mbi = {};
            // Check our own function's page protection
            if (VirtualQuery((LPCVOID)&ACTick, &mbi, sizeof(mbi))) {
                DWORD prot = mbi.Protect;
                // PAGE_GUARD (0x100), PAGE_NOACCESS (0x01) should never be set on .text
                if (prot & PAGE_GUARD || prot == PAGE_NOACCESS) {
                    ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Code page protection tampered (VEH hook detected)\n\nGame will terminate."));
                    return;
                }
            }
        }
    }

    // ---- CHECK 4: Unconditional debugger check ----
    {
        static uint32_t s_dbgCheckTick = 0;
        s_dbgCheckTick++;
        if (s_dbgCheckTick % 120 == 0) {
            if (IsDebuggerPresent()) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Debugger attached\n\nGame will terminate."));
                return;
            }
            // Hardware breakpoint check (DR0-DR3)
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(GetCurrentThread(), &ctx)) {
                if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                    ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Hardware breakpoints detected\n\nGame will terminate."));
                    return;
                }
            }
        }
    }

    // ---- GATED CHECKS: require AC threads to be running ----
    if (!s_wdReady.load(std::memory_order_acquire)) return;

    ACCheckTokenIntegrity();

    ULONGLONG now = GetTickCount64();

    // ---- INLINE POWER WEAPON TIMER FREEZE CHECK ----
    // g_powerWeaponTimer is a plain float that can be frozen.
    // Cross-reference against GetTickCount64 which can't be manipulated from R3.
    {
        static ULONGLONG s_lastCbNow = 0;
        ULONGLONG activatedTs = g_powerWeaponActivatedTs.load();

        if (s_lastCbNow != 0 && now > s_lastCbNow && activatedTs != 0) {
            ULONGLONG dt = now - s_lastCbNow;
            if (g_paused || g_gameOver || dt > 1000) {
                activatedTs += dt;
                g_powerWeaponActivatedTs.store(activatedTs);
            }
        }
        s_lastCbNow = now;

        if (activatedTs != 0 && g_powerWeapon && !g_gameOver && !g_paused) {
            ULONGLONG elapsed = now > activatedTs ? now - activatedTs : 0;
            // POWER_WEAPON_DURATION is 10s. Allow 3s tolerance for frame timing / alt-tab.
            if (elapsed > 13000) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Power weapon timer frozen\n\nGame will terminate."));
                return;
            }
        }
    }

    // ---- INLINE HP FREEZE CHECK ----
    // Runs every frame from game loop, independent of ACThread.
    // Catches HP manipulation even if all AC threads are suspended.
    {
        static uint32_t s_inlineCheckTick = 0;
        s_inlineCheckTick++;
        if (s_inlineCheckTick % 60 == 0 && !g_gameOver && !g_paused) {
            int hp = ACReadEnc(g_encHp);
            int dealt = ACCounterRead(g_pDmgCounter);
            int healed = ACCounterRead(g_pHealCounter);
            int expected = 100 - dealt + healed;
            if (expected < 0)   expected = 0;
            if (expected > 100) expected = 100;
            if (hp > expected + 10) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Inline HP integrity fail\n\nGame will terminate."));
                return;
            }

            // ---- COUNTER FREEZE DETECTION ----
            // If HP dropped since last check but dealt counter didn't increase,
            // the counter was frozen (SkibidiJJ's technique from V2).
            {
                static int s_lastHp = 100;
                static int s_lastDealt = 0;
                // Reset tracking on game restart (counters go back to 0)
                if (dealt == 0 && healed == 0) {
                    s_lastHp = hp;
                    s_lastDealt = 0;
                }
                else if (s_lastHp > hp + 5 && dealt <= s_lastDealt && !g_gameOver) {
                    // HP went down but dealt didn't go up = counter is frozen
                    ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Damage counter frozen\n\nGame will terminate."));
                    return;
                }
                s_lastHp = hp;
                s_lastDealt = dealt;
            }

            // Verify canaries are intact (redundant inline check)
            if (g_encHp.canaryLo != AC_CANARY_LO || g_encHp.canaryHi != AC_CANARY_HI) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Inline canary violation (HP)\n\nGame will terminate."));
                return;
            }
            if (!ACVerifyEnc(g_encHp)) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Inline shadow mismatch (HP)\n\nGame will terminate."));
                return;
            }
            if (!ACVerifyEnc(g_encAmmo)) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Inline shadow mismatch (Ammo)\n\nGame will terminate."));
                return;
            }

            // ---- INLINE AMMO EQUATION CHECK ----
            // Mirrors the HP equation: expected = startAmmo - consumed + refilled
            // If ammo is frozen while firing, consumed grows but ammo doesn't decrease
            if (!g_powerWeapon) {
                int ammo = ACReadEnc(g_encAmmo);
                int consumed = ACCounterRead(g_pAmmoConsumedCounter);
                int refilled = ACCounterRead(g_pAmmoRefilledCounter);
                int shotsFired = ACCounterRead(g_pShotsFiredCounter);
                int expectedAmmo = 30 - consumed + refilled;
                if (expectedAmmo < 0)  expectedAmmo = 0;
                if (expectedAmmo > 30) expectedAmmo = 30;
                if (ammo > expectedAmmo + 10) {
                    ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Inline ammo integrity fail\n\nGame will terminate."));
                    return;
                }

                // ---- AMMO COUNTER FREEZE DETECTION ----
                // If shots fired increased but consumed didn't, counter is frozen
                {
                    static int s_lastShotsFired = 0;
                    static int s_lastConsumed = 0;
                    // Reset tracking on game restart
                    if (consumed == 0 && refilled == 0) {
                        s_lastShotsFired = shotsFired;
                        s_lastConsumed = 0;
                    }
                    else if (shotsFired > s_lastShotsFired + 5 && consumed <= s_lastConsumed) {
                        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Ammo consumed counter frozen\n\nGame will terminate."));
                        return;
                    }
                    s_lastShotsFired = shotsFired;
                    s_lastConsumed = consumed;
                }
            }
        }
    }

    // ---- INLINE DEBUGGER CHECK (from main thread) ----
    // Runs periodically from game loop. Even if ACCheckDebugger()
    // in the AC thread is patched to ret, this still fires.
    {
        static uint32_t s_dbgCheckTick = 0;
        s_dbgCheckTick++;
        if (s_dbgCheckTick % 180 == 0) {
            if (IsDebuggerPresent()) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Inline debugger check\n\nGame will terminate."));
                return;
            }
            // Quick hardware breakpoint check
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            GetThreadContext(GetCurrentThread(), &ctx);
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Inline HW breakpoint check\n\nGame will terminate."));
                return;
            }
        }
    }

    // ---- INLINE THREAD COUNT CHECK ----
    // We should have at least 4 threads (main, ACThread, WatchdogThread, CrcThread, PipeServerThread)
    // If threads are killed, count drops below expected.
    {
        static uint32_t s_threadCheckTick = 0;
        s_threadCheckTick++;
        if (s_threadCheckTick % 240 == 0) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te;
                te.dwSize = sizeof(te);
                int myThreads = 0;
                DWORD myPid = GetCurrentProcessId();
                if (Thread32First(snap, &te)) {
                    do {
                        if (te.th32OwnerProcessID == myPid)
                            myThreads++;
                    } while (Thread32Next(snap, &te));
                }
                CloseHandle(snap);
                // We expect at least 4 AC-related threads + main thread = 5
                // (ACThread, WatchdogThread, CrcThread, PipeServerThread, main)
                // Some additional threads may exist (GDI, timers), but fewer than
                // 4 total means someone killed our threads.
                if (myThreads < 4) {
                    ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: AC threads killed (thread count too low)\n\nGame will terminate."));
                    return;
                }
            }
        }
    }

    // ---- INLINE COUNTER INTEGRITY ----
    // Verify encrypted counters haven't been tampered with
    {
        static uint32_t s_ctrCheckTick = 0;
        s_ctrCheckTick++;
        if (s_ctrCheckTick % 120 == 0) {
            if (g_pDmgCounter && !ACCounterVerify(g_pDmgCounter)) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Inline counter tamper (damage)\n\nGame will terminate."));
                return;
            }
            if (g_pHealCounter && !ACCounterVerify(g_pHealCounter)) {
                ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Inline counter tamper (heal)\n\nGame will terminate."));
                return;
            }
        }
    }

    // ---- Shared unfocused tracking (outside lambda to avoid static-in-lambda issues) ----
    static ULONGLONG s_lastUnfocusedAt = 0;
    {
        HWND fg = GetForegroundWindow();
        DWORD fgPid = 0;
        if (fg) GetWindowThreadProcessId(fg, &fgPid);
        if (fgPid != GetCurrentProcessId()) {
            s_lastUnfocusedAt = now;
        }
    }
    // Grace period: skip all cookie checks for 3s after regaining focus
    bool inGracePeriod = (s_lastUnfocusedAt != 0 && now >= s_lastUnfocusedAt && (now - s_lastUnfocusedAt) < 3000);

    auto ValidateCookie = [&](
        uint32_t* pCookie,
        std::atomic<uint32_t>& echoAtom,
        std::atomic<ULONGLONG>& echoTsAtom,
        const char* staleName,
        const char* mismatchName) -> bool
        {
            if (!pCookie) return false;

            // Skip if unfocused or in grace period after regaining focus
            if (s_lastUnfocusedAt == now || inGracePeriod) return false;

            ULONGLONG echoTs = echoTsAtom.load();
            if (echoTs == 0) return false;
            ULONGLONG age = now > echoTs ? now - echoTs : 0;
            if (age > COOKIE_STALE_MS) {
                ACInlineKill(staleName);
                return true;
            }

            // Read echo AFTER echoTs to match write order
            uint32_t echo = echoAtom.load();
            uint32_t decoded = echo ^ (uint32_t)echoTs;
            uint32_t cookie = *pCookie;
            uint32_t drift = (decoded > cookie) ? (decoded - cookie) : (cookie - decoded);
            if (drift > COOKIE_DRIFT_TOLERANCE) {
                // Possible race: retry once after a brief pause
                Sleep(10);
                echoTs = echoTsAtom.load();
                echo = echoAtom.load();
                decoded = echo ^ (uint32_t)echoTs;
                drift = (decoded > cookie) ? (decoded - cookie) : (cookie - decoded);
                if (drift > COOKIE_DRIFT_TOLERANCE) {
                    ACInlineKill(mismatchName);
                    return true;
                }
            }
            return false;
        };

    if (ValidateCookie(
        g_pAcThreadCookie, g_acCookieEcho, g_acEchoTs,
        skStr("[!] CHEAT DETECTED\n\nReason: ACThread cookie stale\n\nGame will terminate."),
        skStr("[!] CHEAT DETECTED\n\nReason: ACThread cookie mismatch\n\nGame will terminate.")))
        return;

    if (ValidateCookie(
        g_pWdThreadCookie, g_wdCookieEcho, g_wdEchoTs,
        skStr("[!] CHEAT DETECTED\n\nReason: WatchdogThread cookie stale\n\nGame will terminate."),
        skStr("[!] CHEAT DETECTED\n\nReason: WatchdogThread cookie mismatch\n\nGame will terminate.")))
        return;

    if (ValidateCookie(
        g_pCrcThreadCookie, g_crcCookieEcho, g_crcEchoTs,
        skStr("[!] CHEAT DETECTED\n\nReason: CrcThread cookie stale\n\nGame will terminate."),
        skStr("[!] CHEAT DETECTED\n\nReason: CrcThread cookie mismatch\n\nGame will terminate.")))
        return;

    // Pipe heartbeat check
    ACCheckPipeHeartbeat();

    // Legacy timestamp fallback
    ULONGLONG lastAC = g_acThreadTs.load();
    ULONGLONG lastWD = g_wdThreadTs.load();
    bool acDead = (lastAC != 0 && now > lastAC && (now - lastAC) > WD_TIMEOUT_MS);
    bool wdDead = (lastWD != 0 && now > lastWD && (now - lastWD) > WD_TIMEOUT_MS);

    // Skip if we're not in the foreground (threads are throttled by Windows)
    if (acDead || wdDead) {
        HWND fg = GetForegroundWindow();
        DWORD fgPid = 0;
        if (fg) GetWindowThreadProcessId(fg, &fgPid);
        if (fgPid != GetCurrentProcessId()) return; // unfocused, don't kill
    }

    if (acDead && wdDead)
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: Both AC threads suspended\n\nGame will terminate."));
    else if (acDead)
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: ACThread suspended\n\nGame will terminate."));
    else if (wdDead)
        ACInlineKill(skStr("[!] CHEAT DETECTED\n\nReason: WatchdogThread suspended\n\nGame will terminate."));
}

// ============================================================
// INIT
// ============================================================
void ACInit()
{
    g_pDiskCrcKey = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));
    g_pDiskCrcEnc = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));
    g_pDiskCrcShadow = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));

    {
        uintptr_t pk = (uintptr_t)g_pDiskCrcKey;
        *g_pDiskCrcKey = (uint32_t)GetTickCount64()
            ^ (uint32_t)GetCurrentProcessId()
            ^ (uint32_t)(pk & 0xFFFFFFFF)
            ^ (uint32_t)(pk >> 32);
        if (*g_pDiskCrcKey == 0) *g_pDiskCrcKey = 0x12345678;
    }

    s_diskCrcEpoch.store(0, std::memory_order_relaxed);
    uint32_t diskCrc = CalcDiskCrc();
    StoreDiskCrc(diskCrc);

    // -------------------------------------------------------
    //  Counter keys
    // -------------------------------------------------------
    g_pCtrKey1 = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));
    g_pCtrKey2 = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));

    uintptr_t cp1 = (uintptr_t)g_pCtrKey1;
    uintptr_t cp2 = (uintptr_t)g_pCtrKey2;
    *g_pCtrKey1 = (uint32_t)GetTickCount64()
        ^ ((uint32_t)GetCurrentProcessId() * 0xBEEF)
        ^ (uint32_t)(cp1 & 0xFFFFFFFF) ^ (uint32_t)(cp1 >> 32);
    if (*g_pCtrKey1 == 0) *g_pCtrKey1 = 0xFACEB00C;
    *g_pCtrKey2 = ((uint32_t)GetTickCount64() >> 5)
        ^ ((uint32_t)GetCurrentProcessId() * 0xCAFE)
        ^ (uint32_t)(cp2 & 0xFFFFFFFF) ^ (uint32_t)(cp2 >> 32);
    if (*g_pCtrKey2 == 0 || *g_pCtrKey2 == *g_pCtrKey1) *g_pCtrKey2 = 0xDEADC0DE;

    auto allocCounter = [&]() -> EncCounter* {
        return (EncCounter*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(EncCounter));
        };
    g_pDmgCounter = allocCounter();
    g_pHealCounter = allocCounter();
    g_pShotsFiredCounter = allocCounter();
    g_pAmmoConsumedCounter = allocCounter();
    g_pAmmoRefilledCounter = allocCounter();
    g_pGameOverFlag = allocCounter();

    ACCounterSet(g_pDmgCounter, 0);
    ACCounterSet(g_pHealCounter, 0);
    ACCounterSet(g_pShotsFiredCounter, 0);
    ACCounterSet(g_pAmmoConsumedCounter, 0);
    ACCounterSet(g_pAmmoRefilledCounter, 0);
    ACCounterSet(g_pGameOverFlag, 0);

    g_pXorKey1 = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));
    g_pXorKey2 = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));

    uintptr_t p1 = (uintptr_t)g_pXorKey1;
    uint32_t  k1 = (uint32_t)GetTickCount64()
        ^ ((uint32_t)GetCurrentProcessId() << 7)
        ^ (uint32_t)(p1 & 0xFFFFFFFF) ^ (uint32_t)(p1 >> 32);
    *g_pXorKey1 = (k1 != 0) ? k1 : 0xCAFEF00D;

    uintptr_t p2 = (uintptr_t)g_pXorKey2;
    uint32_t  k2 = (uint32_t)(GetTickCount64() >> 3)
        ^ ((uint32_t)GetCurrentProcessId() * 0x1337)
        ^ (uint32_t)(p2 & 0xFFFFFFFF) ^ (uint32_t)(p2 >> 32);
    *g_pXorKey2 = (k2 != 0 && k2 != k1) ? k2 : 0xDEADF00D;

    g_pAcThreadCookie = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));
    g_pWdThreadCookie = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));
    g_pCrcThreadCookie = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));

    *g_pAcThreadCookie = (uint32_t)(uintptr_t)g_pAcThreadCookie
        ^ (uint32_t)GetCurrentProcessId() ^ (uint32_t)GetTickCount64();
    *g_pWdThreadCookie = (uint32_t)(uintptr_t)g_pWdThreadCookie
        ^ (uint32_t)(GetCurrentProcessId() * 3) ^ (uint32_t)(GetTickCount64() >> 2);
    *g_pCrcThreadCookie = (uint32_t)(uintptr_t)g_pCrcThreadCookie
        ^ (uint32_t)(GetCurrentProcessId() * 7) ^ (uint32_t)(GetTickCount64() >> 4);
    if (*g_pAcThreadCookie == 0) *g_pAcThreadCookie = 0x11223344;
    if (*g_pWdThreadCookie == 0) *g_pWdThreadCookie = 0x55667788;
    if (*g_pCrcThreadCookie == 0) *g_pCrcThreadCookie = 0x99AABBCC;

    // -------------------------------------------------------
    //  Pipe session key
    //  Derived from process creation time so the watchdog can
    //  independently compute the same value without us sending it.
    // -------------------------------------------------------
    {
        FILETIME ftCreate = {}, ftExit = {}, ftKernel = {}, ftUser = {};
        GetProcessTimes(GetCurrentProcess(), &ftCreate, &ftExit, &ftKernel, &ftUser);
        uint32_t ctLo = ftCreate.dwLowDateTime;
        s_pipeSessionKey = (uint32_t)GetCurrentProcessId() ^ ctLo ^ (ctLo >> 7);
    if (s_pipeSessionKey == 0) s_pipeSessionKey = 0xDEADBEEF;
    }

    AcTokenWrite(g_acToken, AC_TOKEN_CLEAN);

    HMODULE k32 = GetModuleHandleA(skStr("kernel32.dll"));
    if (k32) {
        BYTE* f;
        f = (BYTE*)GetProcAddress(k32, skStr("ReadProcessMemory"));
        if (f) memcpy(s_origRPM, f, 8);
        f = (BYTE*)GetProcAddress(k32, skStr("WriteProcessMemory"));
        if (f) memcpy(s_origWPM, f, 8);
    }

    BYTE* base = (BYTE*)GetModuleHandleA(nullptr);
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, skStr(".text"), 5) == 0) {
            s_codeStart = base + sec->VirtualAddress;
            s_codeSize = sec->Misc.VirtualSize;
            s_codeBackup = (BYTE*)HeapAlloc(GetProcessHeap(), 0, s_codeSize);
            if (s_codeBackup) memcpy(s_codeBackup, s_codeStart, s_codeSize);
            break;
        }
    }

    g_pCrcSessionKey = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));
    g_pCrcSlot0 = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));
    g_pCrcSlot1 = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));
    g_pCrcSlot2 = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(uint32_t));

    *g_pCrcSessionKey = (uint32_t)GetCurrentProcessId() ^ (uint32_t)GetTickCount64();
    if (*g_pCrcSessionKey == 0) *g_pCrcSessionKey = 0x5A5A5A5A;

    ACSetPaused(false);
    ACSetPowerWeapon(false);

    ACWriteEnc(g_encHp, 100);
    ACWriteEnc(g_encAmmo, 30);
    ACWriteEnc(g_encScore, 0);
    ACWriteEnc(g_encKills, 0);
    ACWriteEnc(g_encWave, 1);

    ACCheckDebugger();
    ACCheckProcesses();
    ACCheckWindows();

    ACBuildDllBaseline();

    s_acInitDone.store(true);
    s_acInitTs.store(GetTickCount64());

    if (s_codeStart && s_codeSize) {
        DWORD runtimeCrc = CalcCRC32(s_codeStart, s_codeSize);
        StoreSplitCrc(runtimeCrc);
        // Refresh backup to match settled state
        if (s_codeBackup) memcpy(s_codeBackup, s_codeStart, s_codeSize);
    }

    CreateThread(nullptr, 0, PipeServerThread, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, PipeDeadlineThread, nullptr, 0, nullptr);
    Sleep(100); // brief pause to ensure pipe is created

    // -------------------------------------------------------
    //  Spawn the external watchdog process
    //  WatchdogMain.exe is expected in the same directory.
    //  We pass our PID so it can connect to our named pipe.
    // -------------------------------------------------------
    {
        char myExePath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, myExePath, MAX_PATH);
        char* sep = strrchr(myExePath, '\\');
        if (sep) *(sep + 1) = '\0';

        char wdPath[MAX_PATH];
        sprintf_s(wdPath, skStr("%sWatchdogMain.exe"), myExePath);

        char cmdLine[MAX_PATH + 32];
        sprintf_s(cmdLine, skStr("\"%s\" %lu"), wdPath, GetCurrentProcessId());

        STARTUPINFOA si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;  // hide the watchdog console window
        PROCESS_INFORMATION pi = {};

        if (!CreateProcessA(wdPath, cmdLine, nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        {
            // If watchdog can't be started, the pipe deadline thread
            // will kill the game after WD_CONNECT_DEADLINE_MS.
        }
        else {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    CreateThread(nullptr, 0, [](LPVOID) -> DWORD { ACThread(); return 0; }, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, WatchdogThread, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, CrcThread, nullptr, 0, nullptr);
}