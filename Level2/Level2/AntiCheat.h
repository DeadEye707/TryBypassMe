#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// WIN32_NO_STATUS must be defined before windows.h so that the STATUS_*
// and DBG_* macros are not defined there. ntstatus.h is then included
// afterwards to define them once from the authoritative source.
// Without this ordering the compiler sees hundreds of C4005 redefinitions.
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

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ============================================================
// AC STATE
// ============================================================
extern std::atomic<bool> g_acDetected;
extern std::string       g_acReason;

// ============================================================
// DAMAGE / HEAL ACCOUNTING
// ============================================================
extern std::atomic<int> g_totalDamageDealt;
extern std::atomic<int> g_totalHealed;

// ============================================================
// AMMO ACCOUNTING
// ============================================================
extern std::atomic<int> g_shotsFired;
extern std::atomic<int> g_ammoConsumed;
extern std::atomic<int> g_ammoRefilled;

// ============================================================
// GAME HEARTBEAT
// ============================================================
extern std::atomic<uint32_t> g_gameTick;

// ============================================================
// ENCRYPTED GAME VALUES
// ============================================================
struct EncInt
{
    volatile int32_t  value;
    volatile uint32_t canaryLo;
    volatile uint32_t canaryHi;
};

static constexpr uint32_t AC_CANARY_LO = 0xDEADC0DE;
static constexpr uint32_t AC_CANARY_HI = 0xB16B00B5;

extern uint32_t g_xorKey;

extern EncInt g_encHp;
extern EncInt g_encAmmo;
extern EncInt g_encScore;
extern EncInt g_encKills;
extern EncInt g_encWave;

inline int  ACReadEnc(const EncInt& e) { return (int)(e.value ^ (int32_t)g_xorKey); }
inline void ACWriteEnc(EncInt& e, int plainVal)
{
    e.value = (int32_t)(plainVal ^ (int32_t)g_xorKey);
    e.canaryLo = AC_CANARY_LO;
    e.canaryHi = AC_CANARY_HI;
}

// ============================================================
// CANARY-PROTECTED FLAGS
// ============================================================
struct GuardedBool
{
    volatile uint32_t guardPre;  // must equal AC_CANARY_LO
    volatile bool     flag;
    volatile uint8_t  _pad[3];
    volatile uint32_t guardPost; // must equal AC_CANARY_HI
};

extern GuardedBool g_pausedGuard;
extern GuardedBool g_powerWeaponGuard;

// Legitimate write counter — incremented inside every setter.
// The AC thread reads this and compares against its own shadow
// count to detect writes that bypassed the setter entirely.
extern std::atomic<uint32_t> g_flagWriteCount;

// Shadow copies maintained exclusively by the setter. The AC
// thread compares these against the live flag values. If the
// live value differs from the shadow, a write occurred outside
// the setter path.
extern std::atomic<bool> g_shadowPaused;
extern std::atomic<bool> g_shadowPowerWeapon;

// Macro shims so existing read sites (if (g_paused) ...) compile
// unchanged. Writes must use the setters below.
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
inline void ACSetPowerWeapon(bool v)
{
    g_powerWeaponGuard.guardPre = AC_CANARY_LO;
    g_powerWeaponGuard.flag = v;
    g_powerWeaponGuard.guardPost = AC_CANARY_HI;
    g_shadowPowerWeapon.store(v);
    g_flagWriteCount.fetch_add(1, std::memory_order_release);
}

// ============================================================
// GAME-LOOP WATCHDOG FALLBACK
// ============================================================
extern std::atomic<ULONGLONG> g_acThreadTs;
extern std::atomic<ULONGLONG> g_wdThreadTs;

// ============================================================
// MISC FLAGS
// ============================================================
extern bool g_gameOver;

// ============================================================
// AC API
// ============================================================
void ACInit();
void ACDetect(const std::string& reason);
void ACTick();