#pragma once

#include "skCrypter.h"
#define skStr(str) ((char*)skCrypt(str))

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <thread>
#include <atomic>
#include <intrin.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ============================================================
// AC STATE TOKEN
// ============================================================
struct AcToken
{
    volatile uint32_t w0;
    volatile uint32_t w1;
    volatile uint32_t w2;
};

static constexpr uint32_t AC_TOKEN_MAGIC0 = 0xC0DECAFE;
static constexpr uint32_t AC_TOKEN_MAGIC1 = 0xDEADB33F;
static constexpr uint32_t AC_TOKEN_MAGIC2 = 0x45670123;
static constexpr uint32_t AC_TOKEN_CLEAN = 0x00000000;
static constexpr uint32_t AC_TOKEN_DETECTED = 0xFFFFFFFF;

inline void AcTokenWrite(AcToken& t, uint32_t payload)
{
    t.w0 = payload ^ AC_TOKEN_MAGIC0;
    t.w1 = (~payload) ^ AC_TOKEN_MAGIC1;
    t.w2 = (payload * AC_TOKEN_MAGIC2) ^ AC_TOKEN_MAGIC0;
}
inline bool AcTokenIsDetected(const AcToken& t)
{
    uint32_t p0 = t.w0 ^ AC_TOKEN_MAGIC0;
    uint32_t p1 = (~(t.w1 ^ AC_TOKEN_MAGIC1));
    uint32_t p2v = (p0 * AC_TOKEN_MAGIC2) ^ AC_TOKEN_MAGIC0;
    if (p0 != p1)    return true;
    if (t.w2 != p2v) return true;
    return (p0 == AC_TOKEN_DETECTED);
}
inline bool AcTokenIsClean(const AcToken& t)
{
    uint32_t p0 = t.w0 ^ AC_TOKEN_MAGIC0;
    uint32_t p1 = (~(t.w1 ^ AC_TOKEN_MAGIC1));
    uint32_t p2v = (p0 * AC_TOKEN_MAGIC2) ^ AC_TOKEN_MAGIC0;
    if (p0 != p1)    return false;
    if (t.w2 != p2v) return false;
    return (p0 == AC_TOKEN_CLEAN);
}

extern AcToken      g_acToken;
extern std::string  g_acReason;

// ============================================================
// ENCRYPTED COUNTER
// ============================================================
struct EncCounter
{
    volatile int32_t enc;    // value ^ *key1
    volatile int32_t shadow; // value ^ *key2
};

extern uint32_t* g_pCtrKey1;
extern uint32_t* g_pCtrKey2;

extern EncCounter* g_pDmgCounter;
extern EncCounter* g_pHealCounter;
extern EncCounter* g_pShotsFiredCounter;
extern EncCounter* g_pAmmoConsumedCounter;
extern EncCounter* g_pAmmoRefilledCounter;
extern EncCounter* g_pGameOverFlag;

inline void ACCounterSet(EncCounter* c, int val)
{
    c->enc = (int32_t)((uint32_t)val ^ *g_pCtrKey1);
    c->shadow = (int32_t)((uint32_t)val ^ *g_pCtrKey2);
}
inline int  ACCounterRead(const EncCounter* c)
{
    return (int)((uint32_t)c->enc ^ *g_pCtrKey1);
}
inline bool ACCounterVerify(const EncCounter* c)
{
    int v1 = (int)((uint32_t)c->enc ^ *g_pCtrKey1);
    int v2 = (int)((uint32_t)c->shadow ^ *g_pCtrKey2);
    return (v1 == v2);
}
inline void ACCounterAdd(EncCounter* c, int delta)
{
    ACCounterSet(c, ACCounterRead(c) + delta);
}

#define g_totalDamageDealt_add(n)   ACCounterAdd(g_pDmgCounter,          (n))
#define g_totalDamageDealt_load()   ACCounterRead(g_pDmgCounter)
#define g_totalDamageDealt_store(n) ACCounterSet(g_pDmgCounter,          (n))
#define g_totalHealed_add(n)        ACCounterAdd(g_pHealCounter,         (n))
#define g_totalHealed_load()        ACCounterRead(g_pHealCounter)
#define g_totalHealed_store(n)      ACCounterSet(g_pHealCounter,         (n))
#define g_shotsFired_add(n)         ACCounterAdd(g_pShotsFiredCounter,   (n))
#define g_shotsFired_load()         ACCounterRead(g_pShotsFiredCounter)
#define g_ammoConsumed_add(n)       ACCounterAdd(g_pAmmoConsumedCounter, (n))
#define g_ammoConsumed_load()       ACCounterRead(g_pAmmoConsumedCounter)
#define g_ammoRefilled_add(n)       ACCounterAdd(g_pAmmoRefilledCounter, (n))
#define g_ammoRefilled_load()       ACCounterRead(g_pAmmoRefilledCounter)

#define g_gameOver         (ACCounterRead(g_pGameOverFlag) != 0)
#define ACGameOverSet(v)   ACCounterSet(g_pGameOverFlag, (v) ? 1 : 0)

// ============================================================
//  GAME HEARTBEAT
// ============================================================
extern std::atomic<uint32_t> g_gameTick;

// ============================================================
// ENCRYPTED GAME VALUES
// ============================================================
struct EncInt
{
    volatile int32_t  value;
    volatile uint32_t _pad1[7];
    volatile uint32_t canaryLo;
    volatile uint32_t _pad2[5];
    volatile uint32_t canaryHi;
    volatile uint32_t _pad3[11];
    volatile uint32_t shadow;
    volatile uint32_t _pad4[3];
};

static constexpr uint32_t AC_CANARY_LO = 0xDEADC0DE;
static constexpr uint32_t AC_CANARY_HI = 0xB16B00B5;

extern uint32_t* g_pXorKey1;
extern uint32_t* g_pXorKey2;

extern EncInt g_encHp;
extern EncInt g_encAmmo;
extern EncInt g_encScore;
extern EncInt g_encKills;
extern EncInt g_encWave;

inline int  ACReadEnc(const EncInt& e)
{
    return (int)(e.value ^ (int32_t)(*g_pXorKey1));
}
inline void ACWriteEnc(EncInt& e, int plainVal)
{
    e.value = (int32_t)((uint32_t)plainVal ^ *g_pXorKey1);
    e.shadow = (uint32_t)((uint32_t)plainVal ^ *g_pXorKey2);
    e.canaryLo = AC_CANARY_LO;
    e.canaryHi = AC_CANARY_HI;
    // Fill padding with pseudo-random noise to look like encrypted data
    uint32_t noise = (uint32_t)plainVal ^ *g_pXorKey1 ^ *g_pXorKey2;
    for (int i = 0; i < 7; i++) { noise = noise * 0x01000193u ^ 0x811c9dc5u; e._pad1[i] = noise; }
    for (int i = 0; i < 5; i++) { noise = noise * 0x01000193u ^ 0x811c9dc5u; e._pad2[i] = noise; }
    for (int i = 0; i < 11; i++) { noise = noise * 0x01000193u ^ 0x811c9dc5u; e._pad3[i] = noise; }
    for (int i = 0; i < 3; i++) { noise = noise * 0x01000193u ^ 0x811c9dc5u; e._pad4[i] = noise; }
}
inline bool ACVerifyEnc(const EncInt& e)
{
    int p1 = (int)(e.value ^ (int32_t)(*g_pXorKey1));
    int p2 = (int)(e.shadow ^ (*g_pXorKey2));
    return (p1 == p2);
}

// ============================================================
// CANARY-PROTECTED FLAGS
// ============================================================
struct GuardedBool
{
    volatile uint32_t guardPre;
    volatile bool     flag;
    volatile uint8_t  _pad[3];
    volatile uint32_t guardPost;
};

extern GuardedBool g_pausedGuard;
extern GuardedBool g_powerWeaponGuard;

extern std::atomic<uint32_t> g_flagWriteCount;
extern std::atomic<bool>     g_shadowPaused;
extern std::atomic<bool>     g_shadowPowerWeapon;

#define g_paused      (g_pausedGuard.flag)
#define g_powerWeapon (g_powerWeaponGuard.flag)

inline void ACSetPaused(bool v)
{
    g_pausedGuard.guardPre = AC_CANARY_LO;
    g_pausedGuard.flag = v;
    g_pausedGuard.guardPost = AC_CANARY_HI;
    g_shadowPaused.store(v);
    g_flagWriteCount.fetch_add(1, std::memory_order_release);
}
extern std::atomic<ULONGLONG> g_powerWeaponActivatedTs;

inline void ACSetPowerWeapon(bool v)
{
    g_powerWeaponGuard.guardPre = AC_CANARY_LO;
    g_powerWeaponGuard.flag = v;
    g_powerWeaponGuard.guardPost = AC_CANARY_HI;
    g_shadowPowerWeapon.store(v);
    g_flagWriteCount.fetch_add(1, std::memory_order_release);
    if (v) g_powerWeaponActivatedTs.store(GetTickCount64());
    else   g_powerWeaponActivatedTs.store(0);
}

// ============================================================
// THREAD LIVENESS COOKIES
// ============================================================
extern uint32_t* g_pAcThreadCookie;
extern uint32_t* g_pWdThreadCookie;
extern uint32_t* g_pCrcThreadCookie;

extern std::atomic<uint32_t>  g_acCookieEcho;
extern std::atomic<uint32_t>  g_wdCookieEcho;
extern std::atomic<uint32_t>  g_crcCookieEcho;

extern std::atomic<ULONGLONG> g_acEchoTs;
extern std::atomic<ULONGLONG> g_wdEchoTs;
extern std::atomic<ULONGLONG> g_crcEchoTs;

static constexpr DWORD    COOKIE_STALE_MS = 15000;
static constexpr uint32_t COOKIE_DRIFT_TOLERANCE = 150;

// ============================================================
// WATCHDOG TIMESTAMPS
// ============================================================
extern std::atomic<ULONGLONG> g_acThreadTs;
extern std::atomic<ULONGLONG> g_wdThreadTs;
extern std::atomic<ULONGLONG> g_crcThreadTs;

// ============================================================
// CRC SPLIT STORAGE
// ============================================================
extern uint32_t* g_pCrcSlot0;
extern uint32_t* g_pCrcSlot1;
extern uint32_t* g_pCrcSlot2;
extern uint32_t* g_pCrcSessionKey;

static constexpr uint32_t CRC_SLOT_MAGIC0 = 0x13375EED;
static constexpr uint32_t CRC_SLOT_MAGIC1 = 0xFEEDF00D;
static constexpr uint32_t CRC_SLOT_MAGIC2 = 0xC001C0DE;

// ============================================================
// DISK CRC
// ============================================================
extern uint32_t* g_pDiskCrcKey;
extern uint32_t* g_pDiskCrcEnc;   // diskCrc ^ *g_pDiskCrcKey
extern uint32_t* g_pDiskCrcShadow;// diskCrc ^ (~*g_pDiskCrcKey)

// ============================================================
//  WATCHDOG PIPE IPC
//
//  The external watchdog process holds the other end.
//  If the pipe goes silent for > WD_PIPE_TIMEOUT_MS the game
//  terminates itself. The watchdog also hashes this .exe on
//  disk before connecting and refuses the handshake if the
//  hash doesn't match a hardcoded expected value.
// ============================================================
static constexpr DWORD WD_PIPE_TIMEOUT_MS = 5000;
static constexpr DWORD WD_PIPE_INTERVAL_MS = 1500;

// Shared pipe name (obfuscated at runtime via skStr)
// #define AC_PIPE_NAME  "\\\\.\\pipe\\TryBypassMe_WD"

// IPC message structure - fixed 16 bytes, both sides verify
struct WdMsg
{
    uint32_t magic;
    uint32_t seq;
    uint32_t hmac;
    uint32_t _pad;
};

static constexpr uint32_t WD_MSG_MAGIC = 0xACBEEF42;

// ============================================================
// DLL INJECTION DEFENCE
// ============================================================
extern std::atomic<bool> g_dllBaselineReady;

// ============================================================
// MISC
// ============================================================
extern bool g_gameOverLegacy;

// ============================================================
// INLINE KILL
// ============================================================
void ACDetect(const std::string& reason);

__forceinline void ACInlineKill(const char* reason)
{
    char* copy = _strdup(reason);
    CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        MessageBoxA(nullptr, (const char*)p, skStr("Anti-Cheat"),
            MB_ICONERROR | MB_OK | MB_TOPMOST | MB_SYSTEMMODAL);
        free(p);
        return 0;
        }, copy, 0, nullptr);
    Sleep(3000);
    // Triple-kill: if TerminateProcess is hooked, fall through to alternatives
    TerminateProcess(GetCurrentProcess(), 1);
    // Direct ntdll call bypasses kernel32 IAT hooks
    typedef LONG(NTAPI* pNtTerminate)(HANDLE, LONG);
    pNtTerminate ntTerm = (pNtTerminate)GetProcAddress(
        GetModuleHandleA(skStr("ntdll.dll")), skStr("NtTerminateProcess"));
    if (ntTerm) ntTerm(GetCurrentProcess(), 1);
    ExitProcess(1);
    // If somehow still alive, infinite terminate loop
    for (;;) { TerminateProcess(GetCurrentProcess(), 1); Sleep(10); }
}

// ============================================================
// AC API
// ============================================================
void ACInit();
void ACTick();
bool ACIsWatchdogReady();