#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
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

// AC state accessible by game logic
extern std::atomic<bool> g_acDetected;
extern std::string       g_acReason;

// Cumulative damage and heal tracking (written by game, read by AC)
extern std::atomic<int> g_totalDamageDealt;
extern std::atomic<int> g_totalHealed;

// Ammo consumption tracking (written by game, read by AC)
extern std::atomic<int> g_shotsFired;
extern std::atomic<int> g_ammoConsumed;
extern std::atomic<int> g_ammoRefilled;

// Power weapon state (AC skips ammo check when active)
extern bool  g_powerWeapon;
extern bool  g_gameOver;
extern bool  g_paused;

// Called once at startup before the window is created
void ACInit();

// Fires a detection event, shows popup, and terminates the process
void ACDetect(const std::string& reason);