#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#include "skCrypter.h"
#define skStr(str) ((char*)skCrypt(str))

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")

// ============================================================
// SHARED CONSTANTS
// ============================================================
static constexpr DWORD WD_PIPE_INTERVAL_MS = 1500;
static constexpr DWORD WD_PIPE_TIMEOUT_MS = 5000;
static constexpr uint32_t WD_MSG_MAGIC = 0xACBEEF42;

struct WdMsg {
  uint32_t magic;
  uint32_t seq;
  uint32_t hmac;
  uint32_t _pad; // watchdog puts its own PID here during handshake
};

// ============================================================
// EXPECTED GAME HASH
// ============================================================
static constexpr uint32_t EXPECTED_GAME_HASH = 0x89AF328A;

// ============================================================
// HELPERS
// ============================================================
static uint32_t CalcFileCrc32(const char *path) {
  HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE)
    return 0;

  uint32_t crc = 0xFFFFFFFF;
  BYTE buf[4096];
  DWORD read = 0;
  while (ReadFile(hFile, buf, sizeof(buf), &read, nullptr) && read > 0) {
    for (DWORD i = 0; i < read; i++) {
      crc ^= buf[i];
      for (int j = 0; j < 8; j++)
        crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int)(crc & 1)));
    }
  }
  CloseHandle(hFile);
  return ~crc;
}

static uint32_t ComputeHmac(uint32_t magic, uint32_t seq, uint32_t sessionKey) {
  uint32_t h = magic ^ 0x811C9DC5u;
  h ^= seq;
  h *= 0x01000193u;
  h ^= sessionKey;
  h *= 0x01000193u;
  h ^= (magic >> 16);
  h *= 0x01000193u;
    return h;
}

// ============================================================
// HASH DUMP HELPER
// ============================================================
static void DumpHash(const char *gamePath) {
  uint32_t crc = CalcFileCrc32(gamePath);
  printf(skStr("Game CRC32: 0x%08X\n"), crc);
  printf(skStr("Set EXPECTED_GAME_HASH = 0x%08X in WatchdogMain.cpp and rebuild.\n"),
         crc);
}

// ============================================================
// MAIN
// ============================================================
int main(int argc, char *argv[]) {
  // --dump-hash mode
  if (argc == 3 && strcmp(argv[1], skStr("--dump-hash")) == 0) {
    DumpHash(argv[2]);
    return 0;
  }

  // Normal mode: argv[1] = game PID (decimal string)
  if (argc < 2) {
    fprintf(stderr, skStr("Usage: WatchdogMain.exe <gamePID>\n"));
    return 1;
  }

    DWORD gamePid = (DWORD)strtoul(argv[1], nullptr, 10);
    if (gamePid == 0) {
        fprintf(stderr, skStr("[WD] Invalid game PID\n"));
        return 1;
    }

    char gamePath[MAX_PATH] = {};
  HANDLE hGame = OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, gamePid);
  if (!hGame) {
    fprintf(stderr, skStr("[WD] Cannot open game process (pid=%lu)\n"), gamePid);
    return 1;
  }
  DWORD pathLen = MAX_PATH;
  if (!QueryFullProcessImageNameA(hGame, 0, gamePath, &pathLen)) {
    CloseHandle(hGame);
    fprintf(stderr, skStr("[WD] Cannot query game path\n"));
    return 1;
  }
  CloseHandle(hGame);

  uint32_t diskCrc = CalcFileCrc32(gamePath);

  // Only enforce hash if EXPECTED_GAME_HASH has been set
  if (EXPECTED_GAME_HASH != 0x00000000 && diskCrc != EXPECTED_GAME_HASH) {
    // Patched .exe - refuse to connect
    // The game will kill itself after WD_PIPE_TIMEOUT_MS
    fprintf(
        stderr,
        skStr("[WD] HASH MISMATCH: game .exe is patched (got %08X expected %08X)\n"),
        diskCrc, EXPECTED_GAME_HASH);
    // Give the game a moment to start its pipe wait, then just exit
    Sleep(1000);
    return 2;
  }

  printf(skStr("[WD] Hash OK (0x%08X). Connecting...\n"), diskCrc);

  // --------------------------------------------------------
  //  2. Connect to the game's named pipe
  //     The game creates: \\.\pipe\TBM_WD_<gamePid>
  // --------------------------------------------------------
  char pipeName[64];
  sprintf_s(pipeName, skStr("\\\\.\\pipe\\TBM_WD_%lu"), gamePid);

  // Wait for pipe to be available (game might not have created it yet)
  HANDLE hPipe = INVALID_HANDLE_VALUE;
  for (int attempt = 0; attempt < 20; attempt++) {
    if (!WaitNamedPipeA(pipeName, 3000)) {
      Sleep(500);
      continue;
    }
    hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
    if (hPipe != INVALID_HANDLE_VALUE)
      break;
    Sleep(300);
  }

  if (hPipe == INVALID_HANDLE_VALUE) {
    fprintf(stderr, skStr("[WD] Could not connect to pipe after retries\n"));
    return 1;
  }

  // Switch to message mode
  DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);

    WdMsg handshake = {};
  DWORD read = 0;
  if (!ReadFile(hPipe, &handshake, sizeof(handshake), &read, nullptr) ||
      read != sizeof(handshake) || handshake.magic != WD_MSG_MAGIC ||
      handshake.seq != 0) {
    fprintf(stderr, skStr("[WD] Bad handshake from game\n"));
    CloseHandle(hPipe);
    return 1;
  }

  // Derive session key from game process creation time.
  // The game computes:
  //   s_pipeSessionKey = pid ^ creationTimeLo32 ^ (creationTimeLo32 >> 7)
  // We derive the identical value here without it ever crossing the pipe.
  FILETIME ftCreate = {}, ftExit = {}, ftKernel = {}, ftUser = {};
  uint32_t sessionKey = 0;
  {
    HANDLE hProc =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, gamePid);
    if (hProc) {
      GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser);
      CloseHandle(hProc);
    }
    uint32_t ctLo = ftCreate.dwLowDateTime;
    sessionKey = (uint32_t)gamePid ^ ctLo ^ (ctLo >> 7);
    if (sessionKey == 0)
      sessionKey = 0xDEADBEEF;
  }

  // Verify the HMAC with the derived key
  if (handshake.hmac != ComputeHmac(handshake.magic, 0, sessionKey)) {
    fprintf(stderr, skStr("[WD] Handshake HMAC invalid (key derivation mismatch)\n"));
    CloseHandle(hPipe);
    return 1;
  }

  // Send our response
  WdMsg resp = {};
  resp.magic = WD_MSG_MAGIC;
  resp.seq = 1;
  resp.hmac = ComputeHmac(WD_MSG_MAGIC, 1, sessionKey);
  resp._pad = GetCurrentProcessId(); // our PID so game can monitor us
  DWORD written = 0;
  if (!WriteFile(hPipe, &resp, sizeof(resp), &written, nullptr)) {
    fprintf(stderr, skStr("[WD] Failed to send handshake response\n"));
    CloseHandle(hPipe);
    return 1;
  }

    printf(skStr("[WD] Handshake complete. Sending heartbeats...\n"));

    uint32_t seq = 2;

  while (true) {
    // Check game is still alive before sending
    HANDLE hCheck =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, gamePid);
    if (!hCheck) {
      printf(skStr("[WD] Game process gone. Exiting.\n"));
      break;
    }
    DWORD exitCode = STILL_ACTIVE;
    GetExitCodeProcess(hCheck, &exitCode);
    CloseHandle(hCheck);
    if (exitCode != STILL_ACTIVE) {
      printf(skStr("[WD] Game exited. Exiting.\n"));
      break;
    }

    // Send heartbeat
    WdMsg hb = {};
    hb.magic = WD_MSG_MAGIC;
    hb.seq = seq;
    hb.hmac = ComputeHmac(WD_MSG_MAGIC, seq, sessionKey);
    hb._pad = 0;

    DWORD wr = 0;
    if (!WriteFile(hPipe, &hb, sizeof(hb), &wr, nullptr)) {
      printf(skStr("[WD] Pipe write failed. Game probably terminated.\n"));
      break;
    }

    seq++;
    Sleep(WD_PIPE_INTERVAL_MS);
  }

  CloseHandle(hPipe);
  return 0;
}