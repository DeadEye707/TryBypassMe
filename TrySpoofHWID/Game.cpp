// TrySpoofHWID v1.0 - by DeadEye707 aka @ali123x on UC
// Extended HWID collector - all registry, disk, network, GPU, monitor, EFI, USB, boot identifiers

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x06010000
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#include <winioctl.h>
#include <setupapi.h>
#include <devguid.h>
#include <sddl.h>
#include <ntddscsi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <random>
#include <fstream>
#include <sstream>
#include <map>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================
// SCREEN / UI CONSTANTS
// ============================================================
static const int SCREEN_W = 1280, SCREEN_H = 800, TILE_SIZE = 48;
static const int POP_X = 18, POP_Y = 12, POP_W = SCREEN_W - 36, POP_H = SCREEN_H - 24;
static const int POP_HEADER_H = 74, POP_FOOTER_H = 26;
static const int POP_ROWS_Y = POP_Y + POP_HEADER_H;
static const int POP_ROWS_H = POP_H - POP_HEADER_H - POP_FOOTER_H;
static const int COL_LABEL = POP_X + 10, COL_BANNED = POP_X + 208, COL_CURRENT = POP_X + 686, COL_STATE = POP_X + 1155;
static const int SB_X = POP_X + POP_W - 16;
static const int ROW_H = 17, ROW_FSZ = 12;

// ============================================================
// GAME CONSTANTS
// ============================================================
static const float PI_F = 3.14159265f, PLAYER_SPEED = 220.f, BULLET_SPEED = 650.f, SHOOT_COOLDOWN = 0.15f;
static const int PLAYER_MAX_HP = 100, PLAYER_MAX_AMMO = 30;
static const float RELOAD_TIME = 1.5f, POWER_WEAPON_DURATION = 10.f;
static const char* HWID_FILE = "DontEditTHIS.txt";
static const char* NOT_EXIST = "__NOT_EXIST__";

// ============================================================
// HWID CLASSIFICATION
// ============================================================
enum HwidCategory { CAT_UNIQUE, CAT_NON_UNIQUE };
enum HwidDifficulty { DIFF_EASY, DIFF_MEDIUM, DIFF_HARD };

struct HwidMeta { HwidCategory cat; HwidDifficulty diff; };

static HwidMeta GetMeta(const std::string& label) {
    static const char* nonUnique[] = {
        "GPU-DriverDesc", "GPU-DriverProv", "BuildLab", "BuildLabEx", "BackupProdKey",
        "UserAssistGUIDs", "NeighborMACs", nullptr
    };
    for (int i = 0; nonUnique[i]; i++)
        if (label == nonUnique[i]) return { CAT_NON_UNIQUE, DIFF_EASY };

    // Easy to spoof (registry edits, simple usermode)
    static const char* easy[] = {
        "MachineGuid", "HwProfileGuid", "SQMMachineId", "SQMFirstSession", "SusClientId",
        "SusClientIdVal", "AccountDomainSid", "PingID", "OneSettings-DevId", "HW-LastConfig",
        "HW-SubkeyUUID", "ComputerHwId", "Office-MBoardUUID", "InstallDate", "InstallTime",
        "ActivationTime", "BuildGUID", "ProductId", "SPP-SessionId", "Telemetry-LWT",
        "IEInstallDate", "WATMachineId", "WppTraceGuid", "RestoreMachGuid", "CurrentUserSID",
        "VolumeSerial", "MAC", "AdapterGUID", "NIC-InstallTime", "Dhcpv6DUID", "GfxConfig-GUID",
        "GfxConfigTS", "GfxConnect-GUID", "Video0-Path", "VideoDevPaths", "DigProdId",
        "DigProdId4", "NvidiaClientUUID", "NvidiaPersistId", "NvidiaChipsetId", "NvidiaGPUSerial",
        "GPU-UMDriverGUID", "CachedUSBSerials", "IndexerVolGuid", "UEFI-ESRT", "UEFI-ESRTAll",
        "MountedDevGUIDs", "SetupAPILog", nullptr
    };
    for (int i = 0; easy[i]; i++)
        if (label == easy[i]) return { CAT_UNIQUE, DIFF_EASY };

    // Medium (driver/kernel access needed)
    static const char* medium[] = {
        "DiskSerial", "DiskPeriphId", "VolumeGUIDs", "PartitionGUIDs", "USN-JournalID",
        "SMARTSerial", "MonitorSerial", "BootUUID", "TPM-AIKHash", "TPM-ODUIDSeed",
        "GPU-DriverDesc", "NvidiaGPU-UUID", nullptr
    };
    for (int i = 0; medium[i]; i++)
        if (label == medium[i]) return { CAT_UNIQUE, DIFF_MEDIUM };

    // Hard (firmware/kernel level)
    if (label == "SMBIOS-FP") return { CAT_UNIQUE, DIFF_HARD };
    if (label == "BootUUID")  return { CAT_UNIQUE, DIFF_HARD };

    return { CAT_UNIQUE, DIFF_MEDIUM };
}

// ============================================================
// GARBAGE VALUE CHECK
// ============================================================
static bool IsGarbageValue(const std::string& label, const std::string& val) {
    if (val.empty() || val == NOT_EXIST) return true;

    std::string trimmed = val;
    while (!trimmed.empty() && (trimmed.back() == '.' || trimmed.back() == ' ')) trimmed.pop_back();
    while (!trimmed.empty() && (trimmed.front() == '.' || trimmed.front() == ' ')) trimmed.erase(trimmed.begin());

    bool allzero = true;
    for (char c : trimmed) { if (c != '0' && c != '-' && c != '_' && c != ' ') { allzero = false; break; } }
    if (allzero && trimmed.size() > 4) return true;

    if (val == "00-00-00-00-00-00") return true;
    if (val == "0000000000000000") return true;
    if (val.find("00-00-00-00-00-00") == 0) return true;
    if (val == "{00000000-0000-0000-0000-000000000000}") return true;
    if (val == "{ffffffff-ffff-ffff-ffff-ffffffffffff}") return true;
    if (val == "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}") return true;
    if (val == "ffffffff-ffff-ffff-ffff-ffffffffffff") return true;
    if (val == "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") return true;

    std::string stripped;
    for (char c : val) if (c != '-' && c != '{' && c != '}' && c != '_' && c != ' ') stripped += (char)tolower(c);
    if (stripped.size() >= 8) {
        bool allSame = true;
        for (char c : stripped) if (c != stripped[0]) { allSame = false; break; }
        if (allSame) return true;
    }

    if (label == "UEFI-ESRTAll") {
        std::string v2 = val;
        std::string zeroGuid = "{00000000-0000-0000-0000-000000000000}";
        size_t pos = 0;
        while ((pos = v2.find(zeroGuid)) != std::string::npos) v2.erase(pos, zeroGuid.size());
        while ((pos = v2.find('|')) != std::string::npos) v2.erase(pos, 1);
        auto a = v2.find_first_not_of(" \t");
        return (a == std::string::npos);
    }
    return false;
}

// ============================================================
// SMART STRUCTURES
// ============================================================
#ifndef SMART_GET_VERSION
#define SMART_GET_VERSION   CTL_CODE(IOCTL_DISK_BASE, 0x0020, METHOD_BUFFERED, FILE_READ_ACCESS)
#endif
#ifndef SMART_RCV_DRIVE_DATA
#define SMART_RCV_DRIVE_DATA CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif
#ifndef ID_CMD
#define ID_CMD 0xEC
#endif
#ifndef IDENTIFY_BUFFER_SIZE
#define IDENTIFY_BUFFER_SIZE 512
#endif

#pragma pack(push,1)
typedef struct _IDEREGS2 {
    BYTE bFeaturesReg, bSectorCountReg, bSectorNumberReg, bCylLowReg, bCylHighReg, bDriveHeadReg, bCommandReg, bReserved;
} IDEREGS2;
typedef struct _SENDCMDINPARAMS2 {
    DWORD cBufferSize;
    IDEREGS2 irDriveRegs;
    BYTE bDriveNumber, bReserved[3];
    DWORD dwReserved[4];
    BYTE bBuffer[1];
} SENDCMDINPARAMS2;
typedef struct _DRIVERSTATUS2 { BYTE bDriverError, bIDEError; WORD wReserved; DWORD dwReserved[2]; } DRIVERSTATUS2;
typedef struct _SENDCMDOUTPARAMS2 { DWORD cBufferSize; DRIVERSTATUS2 DriverStatus; BYTE bBuffer[1]; } SENDCMDOUTPARAMS2;
#pragma pack(pop)

// ============================================================
// VEC2 MATH
// ============================================================
struct Vec2 {
    float x, y;
    Vec2(float x = 0, float y = 0) :x(x), y(y) {}
    Vec2 operator+(const Vec2& o)const { return{ x + o.x,y + o.y }; }
    Vec2 operator-(const Vec2& o)const { return{ x - o.x,y - o.y }; }
    Vec2 operator*(float s)const { return{ x * s,y * s }; }
    Vec2& operator+=(const Vec2& o) { x += o.x; y += o.y; return*this; }
    float len()const { return sqrtf(x * x + y * y); }
    Vec2 norm()const { float l = len(); return l > 0 ? Vec2{ x / l,y / l } : Vec2{}; }
    float dot(const Vec2& o)const { return x * o.x + y * o.y; }
};
static float randf(float lo, float hi) { return lo + (float)rand() / (float)RAND_MAX * (hi - lo); }

// ============================================================
// HWID ENTRY & POPUP STATE
// ============================================================
struct HwidEntry { std::string label, banned, current; HwidMeta meta; };
static int g_banScrollOffset = 0;
static bool  g_sbDragging = false;
static int   g_sbDragAnchorY = 0;
static int   g_sbDragAnchorOff = 0;
static int   g_selectedRow = -1;
static float g_copyFlash = 0.f;
static std::string g_copyFlashText;

// ============================================================
// REGISTRY HELPERS
// ============================================================
static std::string RegStr(HKEY root, const char* path, const char* val) {
    HKEY hk;
    if (RegOpenKeyExA(root, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return "";
    char buf[2048] = {}; DWORD sz = sizeof(buf) - 1, type = 0;
    if (RegQueryValueExA(hk, val, nullptr, &type, (LPBYTE)buf, &sz) != ERROR_SUCCESS) { RegCloseKey(hk); return ""; }
    RegCloseKey(hk);
    if (type == REG_BINARY) {
        if (sz >= 4 && buf[1] == 0 && buf[3] == 0) {
            char out[512] = {}; WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)buf, -1, out, sizeof(out), nullptr, nullptr);
            std::string s(out); auto a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
            if (a != std::string::npos) return s.substr(a, b - a + 1);
        }
        std::string out; char tmp[4];
        for (DWORD i = 0; i < std::min(sz, (DWORD)32); i++) { sprintf_s(tmp, "%02X", (unsigned char)buf[i]); out += tmp; }
        return out;
    }
    std::string s(buf, strnlen(buf, sizeof(buf)));
    auto a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
}

static std::string RegStrFB(HKEY root, const char* path, const char* val) {
    std::string s = RegStr(root, path, val);
    if (!s.empty()) return s;
    std::string p2 = path;
    if (p2.find("SOFTWARE\\") == 0) p2 = "SOFTWARE\\WOW6432Node\\" + p2.substr(9);
    return RegStr(root, p2.c_str(), val);
}

static std::string RegDword(HKEY root, const char* path, const char* val) {
    HKEY hk; if (RegOpenKeyExA(root, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return "";
    DWORD v = 0, sz = sizeof(v), type = 0;
    if (RegQueryValueExA(hk, val, nullptr, &type, (LPBYTE)&v, &sz) != ERROR_SUCCESS) { RegCloseKey(hk); return ""; }
    RegCloseKey(hk); char buf[32]; sprintf_s(buf, "%u", v); return buf;
}

static std::string RegQword(HKEY root, const char* path, const char* val) {
    HKEY hk; if (RegOpenKeyExA(root, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return "";
    ULONGLONG v = 0; DWORD sz = sizeof(v), type = 0;
    if (RegQueryValueExA(hk, val, nullptr, &type, (LPBYTE)&v, &sz) != ERROR_SUCCESS || sz < 4) { RegCloseKey(hk); return ""; }
    RegCloseKey(hk); char buf[32]; sprintf_s(buf, "%llu", v); return buf;
}

static std::string RegBinHex(HKEY root, const char* path, const char* val, DWORD maxB = 16) {
    HKEY hk; if (RegOpenKeyExA(root, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return "";
    DWORD sz = 0, type = 0; RegQueryValueExA(hk, val, nullptr, &type, nullptr, &sz);
    if (sz == 0) { RegCloseKey(hk); return ""; }
    std::vector<BYTE> buf(sz, 0); RegQueryValueExA(hk, val, nullptr, &type, buf.data(), &sz); RegCloseKey(hk);
    bool allz = true; for (DWORD i = 0; i < std::min(sz, maxB); i++) if (buf[i]) allz = false;
    if (allz) return "";
    std::string out; char tmp[4]; for (DWORD i = 0; i < std::min(sz, maxB); i++) { sprintf_s(tmp, "%02X", buf[i]); out += tmp; }
    return out;
}

static std::string RegFirstSubkey(HKEY root, const char* path) {
    HKEY hk; if (RegOpenKeyExA(root, path, 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return "";
    char name[512] = {}; DWORD nameSz = sizeof(name);
    LONG r = RegEnumKeyExA(hk, 0, name, &nameSz, nullptr, nullptr, nullptr, nullptr);
    RegCloseKey(hk); return (r == ERROR_SUCCESS) ? std::string(name) : "";
}

static std::string RegAllSubkeys(HKEY root, const char* path) {
    HKEY hk; if (RegOpenKeyExA(root, path, 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return "";
    std::string out; char name[512] = {}; DWORD nameSz = sizeof(name); DWORD idx = 0;
    while (RegEnumKeyExA(hk, idx++, name, &nameSz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        if (!out.empty()) out += "|"; out += name; nameSz = sizeof(name);
    }
    RegCloseKey(hk); return out;
}

static std::string RegFirstSubkeyVal(HKEY root, const char* path, const char* val) {
    std::string sub = RegFirstSubkey(root, path);
    if (sub.empty()) return "";
    std::string full = std::string(path) + "\\" + sub;
    return RegStr(root, full.c_str(), val);
}

static std::string NE(const std::string& s) { return s.empty() ? NOT_EXIST : s; }

// ============================================================
// SMART SERIAL VIA IOCTL
// ============================================================
static void FlipAndConvert(const unsigned short* words, int start, int end, char* out) {
    int j = 0;
    for (int i = start; i <= end; i++) {
        out[j++] = (char)(words[i] >> 8);
        out[j++] = (char)(words[i] & 0xFF);
    }
    out[j] = 0;
    while (j > 0 && (out[j - 1] == ' ' || out[j - 1] == 0 || out[j - 1] == '.')) { out[j - 1] = 0; j--; }
    int lead = 0;
    while (lead < j && (out[lead] == ' ' || out[lead] == '.')) lead++;
    if (lead > 0) { memmove(out, out + lead, j - lead + 1); j -= lead; }
}

static std::string GetSmartSerial(int driveNum) {
    char path[32]; sprintf_s(path, "\\\\.\\PhysicalDrive%d", driveNum);
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        h = CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";

    const DWORD cmdSz = sizeof(SENDCMDINPARAMS2) - 1 + IDENTIFY_BUFFER_SIZE;
    const DWORD outSz = sizeof(SENDCMDOUTPARAMS2) - 1 + IDENTIFY_BUFFER_SIZE;
    std::vector<BYTE> inBuf(cmdSz, 0), outBuf(outSz, 0);
    auto* cmd = (SENDCMDINPARAMS2*)inBuf.data();
    cmd->cBufferSize = IDENTIFY_BUFFER_SIZE;
    cmd->irDriveRegs.bCommandReg = ID_CMD;
    cmd->irDriveRegs.bDriveHeadReg = 0xA0 | ((driveNum & 1) << 4);
    DWORD ret = 0;
    if (DeviceIoControl(h, SMART_RCV_DRIVE_DATA, cmd, cmdSz, outBuf.data(), outSz, &ret, nullptr)) {
        auto* out = (SENDCMDOUTPARAMS2*)outBuf.data();
        if (out->cBufferSize >= IDENTIFY_BUFFER_SIZE) {
            auto* words = (unsigned short*)out->bBuffer;
            char serial[48] = {};
            FlipAndConvert(words, 10, 19, serial);
            std::string s(serial);
            auto a = s.find_first_not_of(" ."), b = s.find_last_not_of(" .");
            if (a != std::string::npos && !s.empty()) {
                CloseHandle(h);
                return s.substr(a, b - a + 1);
            }
        }
    }

    STORAGE_PROPERTY_QUERY q{ StorageDeviceProperty, PropertyStandardQuery };
    char ob[1024] = {}; DWORD bytes = 0;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), ob, sizeof(ob), &bytes, nullptr)) {
        auto* d = (STORAGE_DEVICE_DESCRIPTOR*)ob;
        if (d->SerialNumberOffset && d->SerialNumberOffset < sizeof(ob)) {
            std::string s(ob + d->SerialNumberOffset);
            auto a = s.find_first_not_of(" \t\r\n."), b = s.find_last_not_of(" \t\r\n.");
            if (a != std::string::npos) { CloseHandle(h); return s.substr(a, b - a + 1); }
        }
    }
    CloseHandle(h);
    return "";
}

static std::string GetSMARTSerial() {
    for (int i = 0; i < 4; i++) {
        std::string s = GetSmartSerial(i);
        if (!s.empty()) return s;
    }
    return NOT_EXIST;
}

// ============================================================
// VOLUME GUIDS
// ============================================================
static std::string GetVolumeGUIDs() {
    char vol[MAX_PATH]; HANDLE hFind = FindFirstVolumeA(vol, sizeof(vol));
    if (hFind == INVALID_HANDLE_VALUE) return NOT_EXIST;
    std::string result;
    do {
        std::string sv(vol);
        size_t a = sv.find('{'), b = sv.find('}');
        if (a != std::string::npos && b != std::string::npos)
        {
            if (!result.empty()) result += "|"; result += sv.substr(a, b - a + 1);
        }
    } while (FindNextVolumeA(hFind, vol, sizeof(vol)));
    FindVolumeClose(hFind);
    return result.empty() ? NOT_EXIST : result;
}

static std::string GetMountedDeviceGUIDs() {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\MountedDevices", 0,
        KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return NOT_EXIST;
    std::string result;
    char valname[512] = {}; DWORD vnsz = sizeof(valname);
    DWORD idx = 0;
    while (RegEnumValueA(hk, idx++, valname, &vnsz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        std::string vn(valname, strnlen(valname, sizeof(valname)));
        size_t gb = vn.find('{'), ge = vn.find('}');
        if (gb != std::string::npos && ge != std::string::npos) {
            std::string guid = vn.substr(gb, ge - gb + 1);
            std::string lo = guid;
            for (char& c : lo) c = (char)tolower(c);
            if (lo != "{00000000-0000-0000-0000-000000000000}") {
                if (!result.empty()) result += "|";
                result += guid;
            }
        }
        vnsz = sizeof(valname);
    }
    RegCloseKey(hk);
    return result.empty() ? NOT_EXIST : result;
}

// ============================================================
// PARTITION GUIDS
// ============================================================
static std::string GetPartitionGUIDs() {
    std::string result;
    for (int i = 0; i < 4; i++) {
        char path[32]; sprintf_s(path, "\\\\.\\PhysicalDrive%d", i);
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD outSz = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127;
        std::vector<BYTE> buf(outSz, 0); DWORD ret = 0;
        if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0, buf.data(), outSz, &ret, nullptr)) {
            auto* layout = (DRIVE_LAYOUT_INFORMATION_EX*)buf.data();
            if (layout->PartitionStyle == PARTITION_STYLE_GPT) {
                char tmp[48]; sprintf_s(tmp,
                    "%08X-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X",
                    layout->Gpt.DiskId.Data1, layout->Gpt.DiskId.Data2, layout->Gpt.DiskId.Data3,
                    layout->Gpt.DiskId.Data4[0], layout->Gpt.DiskId.Data4[1],
                    layout->Gpt.DiskId.Data4[2], layout->Gpt.DiskId.Data4[3],
                    layout->Gpt.DiskId.Data4[4], layout->Gpt.DiskId.Data4[5],
                    layout->Gpt.DiskId.Data4[6], layout->Gpt.DiskId.Data4[7]);
                if (!result.empty()) result += "|";
                result += tmp;
            }
        }
        CloseHandle(h);
    }
    return result.empty() ? NOT_EXIST : result;
}

// ============================================================
// NEIGHBOR MACS VIA GETIPNETTABLE2
// ============================================================
static std::string GetNeighborMACs() {
    struct MY_IPNET_ROW2 {
        BYTE  _addr[28];
        ULONG InterfaceIndex;
        ULONGLONG InterfaceLuid;
        BYTE  PhysicalAddress[32];
        ULONG PhysicalAddressLength;
        ULONG State;
        BOOLEAN IsRouter;
        BOOLEAN IsUnreachable;
        BYTE  _pad[2];
        ULONG ReachabilityTime;
    };
    struct MY_IPNET_TABLE2 {
        ULONG NumEntries;
        ULONG _pad;
        MY_IPNET_ROW2 Table[1];
    };

    HMODULE hIp = GetModuleHandleA("iphlpapi.dll");
    if (!hIp) hIp = LoadLibraryA("iphlpapi.dll");
    if (!hIp) return NOT_EXIST;

    typedef DWORD(WINAPI* pfnGetIpNetTable2)(USHORT Family, void** Table);
    typedef void  (WINAPI* pfnFreeMibTable)(void* Memory);
    auto fnGet = (pfnGetIpNetTable2)GetProcAddress(hIp, "GetIpNetTable2");
    auto fnFree = (pfnFreeMibTable)GetProcAddress(hIp, "FreeMibTable");
    if (!fnGet || !fnFree) return NOT_EXIST;

    void* pRaw = nullptr;
    if (fnGet(0, &pRaw) != NO_ERROR || !pRaw) return NOT_EXIST;

    auto* pTable = (MY_IPNET_TABLE2*)pRaw;

    char myMAC[32] = {};
    {
        ULONG sz = sizeof(IP_ADAPTER_INFO) * 4;
        std::vector<BYTE> buf(sz);
        if (GetAdaptersInfo((PIP_ADAPTER_INFO)buf.data(), &sz) == NO_ERROR) {
            auto* a = (PIP_ADAPTER_INFO)buf.data();
            sprintf_s(myMAC, "%02X-%02X-%02X-%02X-%02X-%02X",
                a->Address[0], a->Address[1], a->Address[2],
                a->Address[3], a->Address[4], a->Address[5]);
        }
    }

    std::string result;
    for (ULONG i = 0; i < pTable->NumEntries; i++) {
        auto& row = pTable->Table[i];
        if (row.PhysicalAddressLength != 6) continue;
        bool allZero = true;
        for (int j = 0; j < 6; j++) if (row.PhysicalAddress[j]) { allZero = false; break; }
        if (allZero) continue;
        bool allFF = true;
        for (int j = 0; j < 6; j++) if (row.PhysicalAddress[j] != 0xFF) { allFF = false; break; }
        if (allFF) continue;
        if (row.PhysicalAddress[0] == 0x01 && row.PhysicalAddress[1] == 0x00 && row.PhysicalAddress[2] == 0x5E) continue;
        if (row.PhysicalAddress[0] == 0x33 && row.PhysicalAddress[1] == 0x33) continue;
        if (row.PhysicalAddress[0] & 0x01) continue;
        char mac[32];
        sprintf_s(mac, "%02X-%02X-%02X-%02X-%02X-%02X",
            row.PhysicalAddress[0], row.PhysicalAddress[1],
            row.PhysicalAddress[2], row.PhysicalAddress[3],
            row.PhysicalAddress[4], row.PhysicalAddress[5]);
        if (strcmp(mac, myMAC) == 0) continue;
        bool isDupM = false;
        {
            std::string tokM; std::istringstream ssM(result);
            while (std::getline(ssM, tokM, '|')) if (tokM == mac) { isDupM = true; break; }
        }
        if (isDupM) continue;
        if (!result.empty()) result += "|";
        result += mac;
    }
    fnFree(pRaw);
    return result.empty() ? NOT_EXIST : result;
}

// ============================================================
// MONITOR SERIAL FROM EDID
// ============================================================
static std::string ParseEDIDSerial(const std::vector<BYTE>& edid) {
    for (int d = 0; d < 4; d++) {
        int base = 54 + d * 18;
        if ((int)edid.size() < base + 18) break;
        if (edid[base] == 0 && edid[base + 1] == 0 && edid[base + 2] == 0 && edid[base + 3] == 0xFF) {
            char serial[14] = {}; int len = 0;
            for (int j = 5; j < 18; j++) {
                char c = (char)edid[base + j];
                if (c == '\n' || c == 0) break;
                serial[len++] = c;
            }
            std::string s(serial, len);
            auto a = s.find_first_not_of(" "), b = s.find_last_not_of(" ");
            if (a != std::string::npos) return s.substr(a, b - a + 1);
        }
    }
    return "";
}

static std::string GetMonitorSerial() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsA(&GUID_DEVCLASS_MONITOR, nullptr, nullptr, DIGCF_PRESENT);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA devData = {}; devData.cbSize = sizeof(devData);
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
            HKEY hKey = SetupDiOpenDevRegKey(hDevInfo, &devData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
            if (hKey == INVALID_HANDLE_VALUE) continue;
            DWORD sz = 0, type = 0;
            RegQueryValueExA(hKey, "EDID", nullptr, &type, nullptr, &sz);
            if (sz > 0) {
                std::vector<BYTE> edid(sz, 0);
                if (RegQueryValueExA(hKey, "EDID", nullptr, &type, edid.data(), &sz) == ERROR_SUCCESS) {
                    std::string s = ParseEDIDSerial(edid);
                    if (!s.empty()) { SetupDiDestroyDeviceInfoList(hDevInfo); RegCloseKey(hKey); return s; }
                }
            }
            RegCloseKey(hKey);
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }

    HKEY hDisplay;
    const char* dispPath = "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, dispPath, 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hDisplay) == ERROR_SUCCESS) {
        char monClass[256] = {}; DWORD mcsz = sizeof(monClass); DWORD idx = 0;
        while (RegEnumKeyExA(hDisplay, idx++, monClass, &mcsz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::string classPath = std::string(dispPath) + "\\" + monClass;
            HKEY hClass;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, classPath.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hClass) == ERROR_SUCCESS) {
                char inst[512] = {}; DWORD isz = sizeof(inst); DWORD idx2 = 0;
                while (RegEnumKeyExA(hClass, idx2++, inst, &isz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                    std::string paramPath = classPath + "\\" + inst + "\\Device Parameters";
                    std::string edidHex = RegBinHex(HKEY_LOCAL_MACHINE, paramPath.c_str(), "EDID", 128);
                    if (!edidHex.empty()) {
                        HKEY hParam;
                        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, paramPath.c_str(), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hParam) == ERROR_SUCCESS) {
                            DWORD sz2 = 0, type2 = 0;
                            RegQueryValueExA(hParam, "EDID", nullptr, &type2, nullptr, &sz2);
                            if (sz2 >= 128) {
                                std::vector<BYTE> edid(sz2, 0);
                                if (RegQueryValueExA(hParam, "EDID", nullptr, &type2, edid.data(), &sz2) == ERROR_SUCCESS) {
                                    std::string s = ParseEDIDSerial(edid);
                                    if (!s.empty()) { RegCloseKey(hParam); RegCloseKey(hClass); RegCloseKey(hDisplay); return s; }
                                }
                            }
                            RegCloseKey(hParam);
                        }
                    }
                    isz = sizeof(inst);
                }
                RegCloseKey(hClass);
            }
            mcsz = sizeof(monClass);
        }
        RegCloseKey(hDisplay);
    }
    return NOT_EXIST;
}

// ============================================================
// GRAPHICS DRIVER CONFIG TIMESTAMP
// ============================================================
static std::string GetGfxConfigTimestamp() {
    HKEY hk;
    const char* base = "SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, base, 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return NOT_EXIST;
    std::string result;
    char name[512] = {}; DWORD nameSz = sizeof(name); DWORD idx = 0;
    while (RegEnumKeyExA(hk, idx++, name, &nameSz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        std::string sub = std::string(base) + "\\" + name;
        std::string ts = RegQword(HKEY_LOCAL_MACHINE, sub.c_str(), "Timestamp");
        if (!ts.empty() && ts != "0") { result = ts; break; }
        nameSz = sizeof(name);
    }
    RegCloseKey(hk);
    return result.empty() ? NOT_EXIST : result;
}

// ============================================================
// VIDEO DEVICE PATHS
// ============================================================
static std::string GetVideoDevicePaths() {
    HKEY hk; std::string result;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\VIDEO", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return NOT_EXIST;
    for (int i = 0; i <= 4; i++) {
        char valname[32]; sprintf_s(valname, "\\Device\\Video%d", i);
        char buf[1024] = {}; DWORD sz = sizeof(buf) - 1, type = 0;
        if (RegQueryValueExA(hk, valname, nullptr, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS && sz > 0) {
            if (!result.empty()) result += "|";
            result += std::string(valname) + "=" + std::string(buf, strnlen(buf, sz));
        }
    }
    RegCloseKey(hk);
    return result.empty() ? NOT_EXIST : result;
}

// ============================================================
// USB CACHED SERIALS
// ============================================================
static std::string GetCachedUSBSerials() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsA(nullptr, "USB", nullptr, DIGCF_ALLCLASSES);
    if (hDevInfo == INVALID_HANDLE_VALUE) return NOT_EXIST;
    SP_DEVINFO_DATA devData = {}; devData.cbSize = sizeof(devData);
    std::string result;
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData) && i < 32; i++) {
        char instId[512] = {};
        if (SetupDiGetDeviceInstanceIdA(hDevInfo, &devData, instId, sizeof(instId), nullptr)) {
            std::string s(instId);
            size_t p1 = s.find('\\'), p2 = (p1 != std::string::npos) ? s.find('\\', p1 + 1) : std::string::npos;
            if (p2 != std::string::npos) {
                std::string serial = s.substr(p2 + 1);
                if (serial.size() > 4 && serial.find('&') == std::string::npos) {
                    bool isDup = false;
                    std::string chk = result;
                    std::string tok;
                    std::istringstream ss2(chk);
                    while (std::getline(ss2, tok, '|'))
                        if (tok == serial) { isDup = true; break; }
                    if (!isDup) {
                        if (!result.empty()) result += "|";
                        result += serial;
                    }
                }
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return result.empty() ? NOT_EXIST : result;
}

// ============================================================
// BOOT UUID
// ============================================================
typedef LONG(WINAPI* pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);
static std::string GetBootUUID() {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) return NOT_EXIST;
    auto fn = (pfnNtQSI)GetProcAddress(hNt, "NtQuerySystemInformation");
    if (!fn) return NOT_EXIST;
    struct SYSTEM_BOOT_ENV_INFO { GUID BootIdentifier; ULONGLONG FirmwareType; ULONGLONG BootFlags; };
    SYSTEM_BOOT_ENV_INFO info = {};
    ULONG needed = 0;
    LONG r = fn(0x5A, &info, sizeof(info), &needed);
    if (r != 0) return NOT_EXIST;
    char buf[64];
    sprintf_s(buf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        info.BootIdentifier.Data1, info.BootIdentifier.Data2, info.BootIdentifier.Data3,
        info.BootIdentifier.Data4[0], info.BootIdentifier.Data4[1],
        info.BootIdentifier.Data4[2], info.BootIdentifier.Data4[3],
        info.BootIdentifier.Data4[4], info.BootIdentifier.Data4[5],
        info.BootIdentifier.Data4[6], info.BootIdentifier.Data4[7]);
    return buf;
}

// ============================================================
// CURRENT USER SID
// ============================================================
static std::string GetCurrentUserSID() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return NOT_EXIST;
    DWORD sz = 0; GetTokenInformation(hToken, TokenUser, nullptr, 0, &sz);
    std::vector<BYTE> buf(sz, 0);
    if (!GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz)) { CloseHandle(hToken); return NOT_EXIST; }
    CloseHandle(hToken);
    auto* tu = (TOKEN_USER*)buf.data();
    LPSTR sidStr = nullptr;
    if (!ConvertSidToStringSidA(tu->User.Sid, &sidStr)) return NOT_EXIST;
    std::string s(sidStr); LocalFree(sidStr);
    return s;
}

// ============================================================
// HWID COLLECTORS
// ============================================================
static std::string GetMAC() {
    ULONG sz = sizeof(IP_ADAPTER_INFO) * 16; std::vector<BYTE> buf(sz);
    DWORD r = GetAdaptersInfo((PIP_ADAPTER_INFO)buf.data(), &sz);
    if (r == ERROR_BUFFER_OVERFLOW) { buf.resize(sz); r = GetAdaptersInfo((PIP_ADAPTER_INFO)buf.data(), &sz); }
    if (r != NO_ERROR) return NOT_EXIST;
    auto* a = (PIP_ADAPTER_INFO)buf.data();
    char out[32]; sprintf_s(out, "%02X-%02X-%02X-%02X-%02X-%02X",
        a->Address[0], a->Address[1], a->Address[2], a->Address[3], a->Address[4], a->Address[5]);
    return out;
}

static std::string GetAdapterGUID() {
    ULONG sz = sizeof(IP_ADAPTER_INFO) * 16; std::vector<BYTE> buf(sz);
    DWORD r = GetAdaptersInfo((PIP_ADAPTER_INFO)buf.data(), &sz);
    if (r == ERROR_BUFFER_OVERFLOW) { buf.resize(sz); r = GetAdaptersInfo((PIP_ADAPTER_INFO)buf.data(), &sz); }
    if (r != NO_ERROR) return NOT_EXIST;
    return std::string(((PIP_ADAPTER_INFO)buf.data())->AdapterName);
}

static std::string GetNICInstallTS() {
    for (int i = 0; i <= 9; i++) {
        char p[256]; sprintf_s(p, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\%04d", i);
        std::string s = RegQword(HKEY_LOCAL_MACHINE, p, "NetworkInterfaceInstallTimestamp");
        if (!s.empty() && s != "0") return s;
    }
    return NOT_EXIST;
}

static std::string GetDhcpv6DUID() { return NE(RegBinHex(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", "Dhcpv6DUID", 12)); }
static std::string GetMachineGuid() { return NE(RegStrFB(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid")); }
static std::string GetHwProfileGuid() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", "HwProfileGuid")); }
static std::string GetSQMMachineId() { return NE(RegStrFB(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SQMClient", "MachineId")); }
static std::string GetSQMFirstSession() {
    std::string s = RegQword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SQMClient", "WinSqmFirstSessionStartTime");
    if (s.empty()) s = RegQword(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\SQMClient", "WinSqmFirstSessionStartTime");
    return NE(s);
}

static std::string GetWATMachineId() {
    static const char* p[] = {
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows Activation Technologies\\AdminObject\\Store",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows Activation Technologies\\AdministrativeTools\\Store",
        nullptr
    };
    for (int i = 0; p[i]; i++) { std::string s = RegStr(HKEY_LOCAL_MACHINE, p[i], "MachineId"); if (!s.empty()) return s; }
    return NOT_EXIST;
}

static std::string GetSusClientId() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", "SusClientId")); }
static std::string GetSusClientIdVal() { return NE(RegBinHex(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", "SusClientIdValidation", 16)); }
static std::string GetAccountDomainSid() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", "AccountDomainSid")); }
static std::string GetPingID() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", "PingID")); }
static std::string GetOneSettingsDevId() {
    std::string s = RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\WSD\\UpdateAgent\\QueryParameters", "deviceId");
    if (s.empty()) s = RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\WSD\\Setup360\\QueryParameters", "deviceId");
    return NE(s);
}

static std::string GetHWLastConfig() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SYSTEM\\HardwareConfig", "LastConfig")); }
static std::string GetHWSubkeyUUID() { return NE(RegFirstSubkey(HKEY_LOCAL_MACHINE, "SYSTEM\\HardwareConfig")); }
static std::string GetComputerHardwareId() {
    std::string s = RegStr(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "ComputerHardwareId");
    if (s.empty()) s = RegStr(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "ComputerHardwareIds");
    return NE(s);
}

static std::string GetOfficeMBoardUUID() {
    std::string s = RegStr(HKEY_USERS, ".DEFAULT\\Software\\Microsoft\\Office\\Common\\ClientTelemetry", "MotherboardUUID");
    if (s.empty()) s = RegStr(HKEY_USERS, "S-1-5-18\\Software\\Microsoft\\Office\\Common\\ClientTelemetry", "MotherboardUUID");
    return NE(s);
}

static std::string GetInstallDate() { return NE(RegDword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate")); }
static std::string GetInstallTime() { return NE(RegQword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallTime")); }
static std::string GetActivationTime() { return NE(RegQword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform\\Activation", "ProductActivationTime")); }
static std::string GetBuildGUID() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "BuildGUID")); }
static std::string GetProductId() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId")); }
static std::string GetSPPSessionId() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", "ServiceSessionId")); }
static std::string GetTelemetryLWT() { return NE(RegQword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SevilleEventlogManager", "LastEventlogWrittenTime")); }
static std::string GetIEInstallDate() { return NE(RegBinHex(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Internet Explorer\\Migration", "IE Installed Date", 8)); }

static std::string GetDiskSerial() {
    for (int port = 0; port <= 4; port++) for (int bus = 0; bus <= 1; bus++) {
        char p[256]; sprintf_s(p, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d\\Scsi Bus %d\\Target Id 0\\Logical Unit Id 0", port, bus);
        std::string s = RegStr(HKEY_LOCAL_MACHINE, p, "SerialNumber");
        if (!s.empty()) { auto a = s.find_first_not_of(" \t\r\n."), b = s.find_last_not_of(" \t\r\n."); if (a != std::string::npos) return s.substr(a, b - a + 1); }
    }
    HANDLE h = CreateFileA("\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY q{ StorageDeviceProperty, PropertyStandardQuery };
        char ob[1024] = {}; DWORD ret = 0;
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), ob, sizeof(ob), &ret, nullptr)) {
            auto* d = (STORAGE_DEVICE_DESCRIPTOR*)ob;
            if (d->SerialNumberOffset && d->SerialNumberOffset < sizeof(ob)) {
                std::string s(ob + d->SerialNumberOffset); CloseHandle(h);
                auto a = s.find_first_not_of(" \t\r\n."), b = s.find_last_not_of(" \t\r\n.");
                if (a != std::string::npos) return s.substr(a, b - a + 1);
            }
        }
        CloseHandle(h);
    }
    return NOT_EXIST;
}

static std::string GetDiskPeriphId() {
    for (int i = 0; i <= 3; i++) {
        char p[256]; sprintf_s(p, "HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\%d", i);
        std::string s = RegStr(HKEY_LOCAL_MACHINE, p, "Identifier");
        if (!s.empty()) return s;
    }
    return NOT_EXIST;
}

static std::string GetVolumeSerial() {
    DWORD s = 0; GetVolumeInformationA("C:\\", nullptr, 0, &s, nullptr, nullptr, nullptr, 0);
    if (!s) return NOT_EXIST; char b[16]; sprintf_s(b, "%08X", s); return b;
}

static std::string GetIndexerVolumeGuid() {
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(drives & (1 << i))) continue;
        char drv = 'A' + i;
        char path[MAX_PATH]; sprintf_s(path, "%c:\\System Volume Information\\IndexerVolumeGuid", drv);
        std::ifstream f(path);
        if (!f.is_open()) continue;
        std::string s; std::getline(f, s);
        auto a = s.find_first_not_of(" \t\r\n{"), b = s.find_last_not_of(" \t\r\n}");
        if (a != std::string::npos) return s.substr(a, b - a + 1);
    }
    return NOT_EXIST;
}

static std::string GetUSNJournalId() {
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(drives & (1 << i))) continue;
        char path[16]; sprintf_s(path, "\\\\.\\%c:", 'A' + i);
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        USN_JOURNAL_DATA jd = {}; DWORD ret = 0;
        bool ok = !!DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &jd, sizeof(jd), &ret, nullptr);
        CloseHandle(h);
        if (ok && jd.UsnJournalID != 0) {
            char buf[32]; sprintf_s(buf, "%016llX", (unsigned long long)jd.UsnJournalID); return buf;
        }
    }
    return NOT_EXIST;
}

// ============================================================
// NVIDIA GPU VIA NVAPI
// ============================================================
static std::string GetNvidiaGPUUUID_nvapi() {
    HMODULE hNvApi = LoadLibraryA("nvapi64.dll");
    if (!hNvApi) hNvApi = LoadLibraryA("nvapi.dll");
    if (!hNvApi) return "";
    typedef void* (*pfnQI)(unsigned int);
    auto QI = (pfnQI)GetProcAddress(hNvApi, "nvapi_QueryInterface");
    if (!QI) { FreeLibrary(hNvApi); return ""; }
    typedef int(*pfnInit)();
    auto Init = (pfnInit)QI(0x0150E828);
    if (!Init || Init() != 0) { FreeLibrary(hNvApi); return ""; }
    typedef int(*pfnEnum)(void**, int*);
    auto EnumGPUs = (pfnEnum)QI(0xE5AC921F);
    if (!EnumGPUs) { FreeLibrary(hNvApi); return ""; }
    void* gpuHandles[64] = {}; int gpuCount = 0;
    if (EnumGPUs(gpuHandles, &gpuCount) != 0 || gpuCount == 0) { FreeLibrary(hNvApi); return ""; }
    typedef int(*pfnBoardInfo)(void*, void*);
    auto GetBoardInfo = (pfnBoardInfo)QI(0x22D54523);
    std::string uuid;
    if (GetBoardInfo) {
        BYTE boardInfo[2048] = {};
        *(DWORD*)boardInfo = 0x00010054;
        if (GetBoardInfo(gpuHandles[0], boardInfo) == 0) {
            char hex[48] = {}; int len = 0;
            for (int i = 4; i < 20; i++) { char t[4]; sprintf_s(t, "%02X", boardInfo[i]); strcat_s(hex, t); }
            if (hex[0]) uuid = hex;
        }
    }
    FreeLibrary(hNvApi);
    return uuid;
}

static std::string GetNvidiaClientUUID() {
    std::string s = RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\NVIDIA Corporation\\Global", "ClientUUID");
    if (s.empty()) s = GetNvidiaGPUUUID_nvapi();
    return NE(s);
}

static std::string GetNvidiaPersistId() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\NVIDIA Corporation\\Global", "PersistenceIdentifier")); }
static std::string GetNvidiaChipsetId() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager", "ChipsetMatchID")); }
static std::string GetGPUDriverDesc() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc")); }
static std::string GetGPUDriverProvInfo() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "_DriverProviderInfo")); }
static std::string GetGPUUserModeDriverGUID() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "UserModeDriverGUID")); }
static std::string GetVideo0Path() { return NE(RegStr(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\VIDEO", "\\Device\\Video0")); }
static std::string GetGfxConfigGUID() {
    std::string s = RegFirstSubkey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration");
    if (s.empty()) s = RegFirstSubkey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\GraphicsDrivers\\Configuration");
    return NE(s);
}

static std::string GetGfxConnectGUID() {
    std::string s = RegFirstSubkey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Connectivity");
    if (s.empty()) s = RegFirstSubkey(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\GraphicsDrivers\\Connectivity");
    return NE(s);
}

static std::string GetSMBIOSFP() {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return NOT_EXIST;
    DWORD sz = 0, type = 0; RegQueryValueExA(hk, "SMBiosData", nullptr, &type, nullptr, &sz);
    if (sz < 24) { RegCloseKey(hk); return NOT_EXIST; }
    std::vector<BYTE> buf(sz, 0); RegQueryValueExA(hk, "SMBiosData", nullptr, &type, buf.data(), &sz); RegCloseKey(hk);
    bool allz = true; for (int i = 8; i < 24 && i < (int)sz; i++) if (buf[i]) allz = false;
    if (allz) return NOT_EXIST;
    std::string out; char tmp[4];
    for (int i = 8; i < std::min((int)sz, 24); i++) { sprintf_s(tmp, "%02X", buf[i]); out += tmp; }
    return out;
}

static std::string GetTPMAIKHash() { return NE(RegBinHex(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", "WindowsAIKHash", 8)); }

static std::string GetTPMODUIDSeed() {
    std::string s = RegBinHex(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID", "RandomSeed", 8);
    if (!s.empty()) return s;

    struct MY_UNICODE_STRING {
        USHORT  Length;
        USHORT  MaximumLength;
        PWSTR   Buffer;
    };
    typedef LONG(WINAPI* pfnQSEV)(MY_UNICODE_STRING*, GUID*, PVOID, PULONG, PULONG);

    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) return NOT_EXIST;
    auto fn = (pfnQSEV)GetProcAddress(hNt, "ZwQuerySystemEnvironmentValueEx");
    if (!fn) return NOT_EXIST;

    GUID guid = { 0xbb966a3b, 0x03a6, 0x4be5, { 0x9a, 0x85, 0x7d, 0x7d, 0x47, 0x86, 0xe5, 0x5c } };
    wchar_t varName[] = L"OfflineUniqueIDRandomSeed";
    MY_UNICODE_STRING us;
    us.Length = (USHORT)(wcslen(varName) * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    us.Buffer = varName;

    BYTE buf[32] = {}; ULONG sz = sizeof(buf), attr = 0;
    LONG r = fn(&us, &guid, buf, &sz, &attr);
    if (r != 0 || sz == 0) return NOT_EXIST;

    std::string out; char tmp[4];
    for (ULONG i = 0; i < std::min(sz, (ULONG)8); i++) { sprintf_s(tmp, "%02X", buf[i]); out += tmp; }
    return out.empty() ? NOT_EXIST : out;
}

static std::string GetUEFIESRT() { return NE(RegFirstSubkey(HKEY_LOCAL_MACHINE, "HARDWARE\\UEFI\\ESRT")); }

static std::string GetUEFIESRTAllKeys() {
    std::string raw = RegAllSubkeys(HKEY_LOCAL_MACHINE, "HARDWARE\\UEFI\\ESRT");
    if (raw.empty()) return NOT_EXIST;
    std::string result;
    std::string token;
    std::istringstream ss(raw);
    while (std::getline(ss, token, '|')) {
        std::string lo = token;
        for (char& c : lo) c = (char)tolower(c);
        if (lo == "{00000000-0000-0000-0000-000000000000}") continue;
        if (!result.empty()) result += "|";
        result += token;
    }
    return result.empty() ? NOT_EXIST : result;
}

static std::string GetDigProdId4() { return NE(RegBinHex(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DigitalProductId4", 16)); }
static std::string GetDigProdId() { return NE(RegBinHex(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DigitalProductId", 8)); }

static std::string GetSetupAPIUSBLog() {
    char windir[MAX_PATH] = {}; GetWindowsDirectoryA(windir, sizeof(windir));
    const char* logs[] = { "\\INF\\setupapi.dev.log", "\\INF\\setupapi.setup.log", nullptr };
    std::string result;
    for (int li = 0; logs[li]; li++) {
        std::string path = std::string(windir) + logs[li];
        std::ifstream f(path);
        if (!f.is_open()) continue;
        std::string line;
        while (std::getline(f, line)) {
            size_t pos = line.find("Serial=");
            if (pos == std::string::npos) pos = line.find("SERIALNUMBER=");
            if (pos == std::string::npos) continue;
            size_t start = line.find('=', pos) + 1;
            size_t end = line.find_first_of(" \t\r\n,]", start);
            if (end == std::string::npos) end = line.size();
            std::string serial = line.substr(start, end - start);
            if (serial.size() < 8 || serial.find(' ') != std::string::npos) continue;
            bool dup = false;
            std::string tok; std::istringstream ss(result);
            while (std::getline(ss, tok, '|')) if (tok == serial) { dup = true; break; }
            if (!dup) { if (!result.empty()) result += "|"; result += serial; }
            if (result.size() > 512) break;
        }
    }
    return result.empty() ? NOT_EXIST : result;
}

static std::string GetRestoreMachGuid() {
    DWORD drives = GetLogicalDrives(); char drv = 'C';
    for (int i = 0; i < 26; i++, drv++) {
        if (!(drives & (1 << i))) continue;
        char path[MAX_PATH]; sprintf_s(path, "%c:\\Windows\\System32\\restore\\MachineGuid.txt", drv);
        std::ifstream f(path);
        if (f.is_open()) {
            std::string s; std::getline(f, s);
            auto a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
            if (a != std::string::npos) return s.substr(a, b - a + 1);
        }
    }
    return NOT_EXIST;
}

static std::string GetWppTraceGuid() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Win32kWPP\\Parameters", "WppRecorder_TraceGuid")); }
static std::string GetBuildLab() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "BuildLab")); }
static std::string GetBuildLabEx() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "BuildLabEx")); }
static std::string GetBackupProductKey() { return NE(RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", "BackupProductKeyDefault")); }
static std::string GetUserAssistGUIDs() { return NE(RegAllSubkeys(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")); }

static std::string GetNvidiaGPUUUID() {
    const char* devPaths[] = {
        "\\\\.\\NvidiaControlDeprecated0",
        "\\\\.\\GPU-0",
        "\\\\.\\NvidiaControl",
        nullptr
    };
    for (int di = 0; devPaths[di]; di++) {
        HANDLE h = CreateFileA(devPaths[di], GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        std::vector<BYTE> outBuf(0x400, 0);
        DWORD ret = 0;
        if (DeviceIoControl(h, 0x8DE0008, nullptr, 0, outBuf.data(), (DWORD)outBuf.size(), &ret, nullptr)) {
            for (size_t i = 0; i + 4 < outBuf.size(); i++) {
                if (memcmp(&outBuf[i], "GPU-", 4) == 0) {
                    std::string uuid((char*)&outBuf[i], strnlen((char*)&outBuf[i], 64));
                    if (uuid.size() > 8) { CloseHandle(h); return uuid; }
                }
            }
        }
        CloseHandle(h);
    }
    return NOT_EXIST;
}

static std::string GetNvidiaGPUSerial() {
    std::string s = RegStr(HKEY_LOCAL_MACHINE, "SOFTWARE\\NVIDIA Corporation\\Global", "GpuSerialNumber");
    if (!s.empty()) return s;
    s = RegStr(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "GPU Serial Number");
    if (!s.empty()) return s;
    return NOT_EXIST;
}

// ============================================================
// COLLECT ALL HWIDS
// ============================================================
static std::vector<std::pair<std::string, std::string>> CollectAll() {
    std::vector<std::pair<std::string, std::string>> v;
    v.push_back({ "MAC",              GetMAC() });
    v.push_back({ "AdapterGUID",      GetAdapterGUID() });
    v.push_back({ "NIC-InstallTime",  GetNICInstallTS() });
    v.push_back({ "Dhcpv6DUID",       GetDhcpv6DUID() });
    v.push_back({ "NeighborMACs",     GetNeighborMACs() });
    v.push_back({ "MachineGuid",      GetMachineGuid() });
    v.push_back({ "HwProfileGuid",    GetHwProfileGuid() });
    v.push_back({ "SQMMachineId",     GetSQMMachineId() });
    v.push_back({ "SQMFirstSession",  GetSQMFirstSession() });
    v.push_back({ "WATMachineId",     GetWATMachineId() });
    v.push_back({ "SusClientId",      GetSusClientId() });
    v.push_back({ "SusClientIdVal",   GetSusClientIdVal() });
    v.push_back({ "AccountDomainSid", GetAccountDomainSid() });
    v.push_back({ "PingID",           GetPingID() });
    v.push_back({ "OneSettings-DevId",GetOneSettingsDevId() });
    v.push_back({ "HW-LastConfig",    GetHWLastConfig() });
    v.push_back({ "HW-SubkeyUUID",    GetHWSubkeyUUID() });
    v.push_back({ "ComputerHwId",     GetComputerHardwareId() });
    v.push_back({ "Office-MBoardUUID",GetOfficeMBoardUUID() });
    v.push_back({ "InstallDate",      GetInstallDate() });
    v.push_back({ "InstallTime",      GetInstallTime() });
    v.push_back({ "ActivationTime",   GetActivationTime() });
    v.push_back({ "BuildGUID",        GetBuildGUID() });
    v.push_back({ "ProductId",        GetProductId() });
    v.push_back({ "SPP-SessionId",    GetSPPSessionId() });
    v.push_back({ "Telemetry-LWT",    GetTelemetryLWT() });
    v.push_back({ "IEInstallDate",    GetIEInstallDate() });
    v.push_back({ "BackupProdKey",    GetBackupProductKey() });
    v.push_back({ "UserAssistGUIDs",  GetUserAssistGUIDs() });
    v.push_back({ "CurrentUserSID",   GetCurrentUserSID() });
    v.push_back({ "DiskSerial",       GetDiskSerial() });
    v.push_back({ "SMARTSerial",      GetSMARTSerial() });
    v.push_back({ "DiskPeriphId",     GetDiskPeriphId() });
    v.push_back({ "VolumeSerial",     GetVolumeSerial() });
    v.push_back({ "VolumeGUIDs",      GetVolumeGUIDs() });
    v.push_back({ "PartitionGUIDs",   GetPartitionGUIDs() });
    v.push_back({ "IndexerVolGuid",   GetIndexerVolumeGuid() });
    v.push_back({ "USN-JournalID",    GetUSNJournalId() });
    v.push_back({ "NvidiaClientUUID", GetNvidiaClientUUID() });
    v.push_back({ "NvidiaPersistId",  GetNvidiaPersistId() });
    v.push_back({ "NvidiaChipsetId",  GetNvidiaChipsetId() });
    v.push_back({ "NvidiaGPUSerial",  GetNvidiaGPUSerial() });
    v.push_back({ "GPU-DriverDesc",   GetGPUDriverDesc() });
    v.push_back({ "GPU-DriverProv",   GetGPUDriverProvInfo() });
    v.push_back({ "GPU-UMDriverGUID", GetGPUUserModeDriverGUID() });
    v.push_back({ "Video0-Path",      GetVideo0Path() });
    v.push_back({ "VideoDevPaths",    GetVideoDevicePaths() });
    v.push_back({ "GfxConfig-GUID",   GetGfxConfigGUID() });
    v.push_back({ "GfxConfigTS",      GetGfxConfigTimestamp() });
    v.push_back({ "GfxConnect-GUID",  GetGfxConnectGUID() });
    v.push_back({ "SMBIOS-FP",        GetSMBIOSFP() });
    v.push_back({ "TPM-AIKHash",      GetTPMAIKHash() });
    v.push_back({ "TPM-ODUIDSeed",    GetTPMODUIDSeed() });
    v.push_back({ "UEFI-ESRT",        GetUEFIESRT() });
    v.push_back({ "UEFI-ESRTAll",     GetUEFIESRTAllKeys() });
    v.push_back({ "BootUUID",         GetBootUUID() });
    v.push_back({ "MonitorSerial",    GetMonitorSerial() });
    v.push_back({ "CachedUSBSerials", GetCachedUSBSerials() });
    v.push_back({ "DigProdId4",       GetDigProdId4() });
    v.push_back({ "DigProdId",        GetDigProdId() });
    v.push_back({ "RestoreMachGuid",  GetRestoreMachGuid() });
    v.push_back({ "SetupAPILog",      GetSetupAPIUSBLog() });
    v.push_back({ "MountedDevGUIDs",  GetMountedDeviceGUIDs() });
    v.push_back({ "NvidiaGPU-UUID",   GetNvidiaGPUUUID() });
    v.push_back({ "WppTraceGuid",     GetWppTraceGuid() });
    v.push_back({ "BuildLab",         GetBuildLab() });
    v.push_back({ "BuildLabEx",       GetBuildLabEx() });
    return v;
}

// ============================================================
// FILE I/O
// ============================================================
static std::map<std::string, std::string> LoadBanned() {
    std::map<std::string, std::string> m; std::ifstream f(HWID_FILE);
    if (!f.is_open()) return m; std::string line;
    while (std::getline(f, line)) {
        size_t t = line.rfind("(BANNED)");
        if (t == std::string::npos) continue;
        size_t c = line.find(':');
        if (c == std::string::npos || c >= t) continue;
        m[line.substr(0, c)] = line.substr(c + 1, t - c - 1);
    }
    return m;
}

static void SaveBanned(const std::vector<std::pair<std::string, std::string>>& hwids) {
    std::ofstream f(HWID_FILE, std::ios::trunc);
    for (auto& kv : hwids) f << kv.first << ":" << kv.second << "(BANNED)\n";
}

// ============================================================
// BAN STATE MANAGEMENT
// ============================================================
static std::vector<HwidEntry> g_hwidEntries;
static std::vector<int> g_sortedIdx;
static bool g_banned = false, g_mrClean = false;

static void RunHwidCheck() {
    g_hwidEntries.clear(); g_banned = false; g_mrClean = false;
    auto banned = LoadBanned(); auto current = CollectAll();
    if (banned.empty()) { SaveBanned(current); banned = LoadBanned(); }
    bool anyBanned = false;
    for (auto& kv : current) {
        HwidEntry e; e.label = kv.first; e.current = kv.second;
        e.meta = GetMeta(kv.first);
        if (IsGarbageValue(e.label, e.current)) e.current = NOT_EXIST;
        auto it = banned.find(kv.first); if (it != banned.end()) e.banned = it->second;
        if (IsGarbageValue(e.label, e.banned))  e.banned = NOT_EXIST;
        bool curReal = (e.current != NOT_EXIST && !e.current.empty());
        bool banReal = (e.banned != NOT_EXIST && !e.banned.empty());
        if (curReal && banReal && e.banned == e.current && e.meta.cat == CAT_UNIQUE) anyBanned = true;
        g_hwidEntries.push_back(e);
    }
    g_banned = anyBanned;
    bool allSpoofed = true;
    bool anyUniqueFound = false;
    for (auto& e : g_hwidEntries) {
        if (e.meta.cat != CAT_UNIQUE) continue;
        bool curReal = (e.current != NOT_EXIST && !e.current.empty());
        bool banReal = (e.banned != NOT_EXIST && !e.banned.empty());
        if (!curReal || !banReal) continue;
        anyUniqueFound = true;
        if (e.banned == e.current) { allSpoofed = false; break; }
    }
    if (!anyUniqueFound) allSpoofed = false;
    g_mrClean = allSpoofed && !g_banned;
}

static void ReBan() { auto c = CollectAll(); SaveBanned(c); RunHwidCheck(); g_banScrollOffset = 0; g_selectedRow = -1; }

// ============================================================
// GAME ENTITIES
// ============================================================
struct Bullet { Vec2 pos, vel; bool active = false, fromPlayer = true; float radius = 5.f; int damage = 15; };
struct Enemy { Vec2 pos; float radius = 18.f; int hp = 60, maxHp = 60; float shootCd = 0.f, speed = 0.f; bool alive = true; int type = 0; };
struct Particle { Vec2 pos, vel; float life = 0.f, maxLife = 0.f; COLORREF color = 0; float size = 0.f; bool active = false; };
struct FloatingText { Vec2 pos; std::string text; float life = 0.f; COLORREF color = 0; bool active = false; };
enum DropType { DROP_HEALTH = 0, DROP_AMMO = 1, DROP_WEAPON = 2 };
struct Drop { Vec2 pos; DropType type = DROP_HEALTH; float radius = 18.f, lifetime = 10.f; bool active = false; int weaponId = 0; float pulseT = 0.f; };

// ============================================================
// GAME STATE GLOBALS
// ============================================================
static Vec2 g_playerPos = { SCREEN_W / 2.f, SCREEN_H / 2.f }; static float g_playerAngle = 0.f;
volatile int g_playerHp = PLAYER_MAX_HP, g_playerAmmo = PLAYER_MAX_AMMO, g_playerScore = 0, g_playerKills = 0, g_wave = 1;
static float g_shootCd = 0.f, g_reloadCd = 0.f; static bool g_reloading = false, g_gameOver = false, g_paused = false;
static std::vector<Enemy> g_enemies; static std::vector<Bullet> g_bullets; static std::vector<Particle> g_particles; static std::vector<FloatingText> g_floatTexts; static std::vector<Drop> g_drops;
static bool g_powerWeapon = false; static int g_powerWeaponId = 0; static float g_powerWeaponTimer = 0.f;
static float g_waveTimer = 0.f, g_waveDelay = 3.f; static bool g_waveSpawning = false; static int g_enemiesToSpawn = 0; static float g_spawnTimer = 0.f, g_totalTime = 0.f; static int g_highScore = 0;
static bool g_keys[256] = {}; static bool g_mouseLeft = false; static POINT g_mousePos = { SCREEN_W / 2, SCREEN_H / 2 };
static HWND g_hwnd = nullptr; static HDC g_hdc = nullptr; static HBITMAP g_hbmp = nullptr; static HDC g_memDC = nullptr; static int g_fps = 0;

// ============================================================
// DRAWING FUNCTIONS
// ============================================================
static void DrawCircle(HDC dc, int x, int y, int r, COLORREF fill, COLORREF outline) { HBRUSH br = CreateSolidBrush(fill); HPEN pn = CreatePen(PS_SOLID, 2, outline); SelectObject(dc, br); SelectObject(dc, pn); Ellipse(dc, x - r, y - r, x + r, y + r); DeleteObject(br); DeleteObject(pn); }
static void DrawRect(HDC dc, int x, int y, int w, int h, COLORREF fill) { HBRUSH br = CreateSolidBrush(fill); SelectObject(dc, br); SelectObject(dc, GetStockObject(NULL_PEN)); Rectangle(dc, x, y, x + w, y + h); DeleteObject(br); }
static void DrawText_(HDC dc, const char* txt, int x, int y, COLORREF col, int sz, bool bold, bool center) { HFONT f = CreateFontA(sz, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, DEFAULT_PITCH, "Consolas"); SelectObject(dc, f); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, col); if (center) { SIZE s; GetTextExtentPoint32A(dc, txt, (int)strlen(txt), &s); x -= s.cx / 2; } TextOutA(dc, x, y, txt, (int)strlen(txt)); DeleteObject(f); }
static void DrawBar(HDC dc, int x, int y, int w, int h, float frac, COLORREF fill, COLORREF bg) { DrawRect(dc, x, y, w, h, bg); int fw = (int)(w * std::max(0.f, std::min(1.f, frac))); if (fw > 0) DrawRect(dc, x, y, fw, h, fill); HPEN pn = CreatePen(PS_SOLID, 1, RGB(80, 80, 80)); SelectObject(dc, pn); SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, x, y, x + w, y + h); DeleteObject(pn); }
static void AlphaOverlay(HDC dc, BYTE alpha) { HDC tmp = CreateCompatibleDC(dc); HBITMAP bmp = CreateCompatibleBitmap(dc, SCREEN_W, SCREEN_H); SelectObject(tmp, bmp); DrawRect(tmp, 0, 0, SCREEN_W, SCREEN_H, RGB(0, 0, 0)); BLENDFUNCTION bf{ AC_SRC_OVER,0,alpha,0 }; AlphaBlend(dc, 0, 0, SCREEN_W, SCREEN_H, tmp, 0, 0, SCREEN_W, SCREEN_H, bf); DeleteDC(tmp); DeleteObject(bmp); }
static std::string Trunc(const std::string& s, int n) { if ((int)s.size() > n) return s.substr(0, n - 2) + ".."; return s; }
static void SpawnParticles(Vec2 pos, COLORREF col, int count, float speed, float life) { for (int i = 0; i < count; i++) for (auto& p : g_particles) if (!p.active) { float a = randf(0, 2 * PI_F), s = randf(speed * .3f, speed); p.pos = pos; p.vel = { cosf(a) * s,sinf(a) * s }; p.life = p.maxLife = randf(life * .5f, life); p.color = col; p.size = randf(2.f, 5.f); p.active = true; break; } }
static void SpawnFloatText(Vec2 pos, const std::string& text, COLORREF col) { for (auto& f : g_floatTexts) if (!f.active) { f.pos = pos; f.text = text; f.color = col; f.life = 1.2f; f.active = true; return; } }
static void StartWave(int wave) { g_enemiesToSpawn = 5 + wave * 3; g_waveSpawning = true; g_spawnTimer = 0.f; g_waveTimer = 0.f; char buf[32]; sprintf_s(buf, "WAVE %d", wave); SpawnFloatText({ SCREEN_W / 2.f,SCREEN_H / 2.f - 60.f }, buf, RGB(255, 220, 0)); }
static void SpawnEnemy(int wave) { Enemy e; int side = rand() % 4; switch (side) { case 0:e.pos = { randf(0,SCREEN_W),-30.f }; break; case 1:e.pos = { randf(0,SCREEN_W),SCREEN_H + 30.f }; break; case 2:e.pos = { -30.f,randf(0,SCREEN_H) }; break; default:e.pos = { SCREEN_W + 30.f,randf(0,SCREEN_H) }; } float r = randf(0, 1); if (wave < 3 || r < 0.5f) { e.type = 0; e.hp = e.maxHp = 50; e.speed = randf(70, 110); } else if (r < 0.8f) { e.type = 1; e.hp = e.maxHp = 40; e.speed = randf(55, 85); e.shootCd = randf(1.5f, 3.f); } else { e.type = 2; e.hp = e.maxHp = 150; e.speed = randf(40, 60); e.radius = 26.f; } e.speed += wave * 4.f; e.alive = true; g_enemies.push_back(e); }
static bool CircleCollide(Vec2 a, float ra, Vec2 b, float rb) { Vec2 d = a - b; return d.dot(d) < (ra + rb) * (ra + rb); }
static void DealDamageToPlayer(int dmg) { if (g_playerHp <= 0) return; g_playerHp -= dmg; if (g_playerHp <= 0) { g_playerHp = 0; g_gameOver = true; g_highScore = std::max(g_highScore, (int)g_playerScore); } }
static void RestartGame() { g_playerPos = { SCREEN_W / 2.f,SCREEN_H / 2.f }; g_playerHp = PLAYER_MAX_HP; g_playerAmmo = PLAYER_MAX_AMMO; g_playerScore = 0; g_playerKills = 0; g_wave = 1; g_shootCd = 0.f; g_reloadCd = 0.f; g_reloading = false; g_gameOver = false; g_totalTime = 0.f; g_waveTimer = 0.f; g_waveSpawning = false; g_powerWeapon = false; g_powerWeaponTimer = 0.f; g_drops.clear(); g_enemies.clear(); g_bullets.clear(); g_particles.clear(); g_floatTexts.clear(); g_particles.resize(512); g_floatTexts.resize(32); StartWave(1); }

// ============================================================
// UPDATE LOGIC
// ============================================================
static void Update(float dt) { if (g_gameOver || g_paused) return; g_totalTime += dt; Vec2 dir = {}; if (g_keys['W'] || g_keys[VK_UP]) dir.y -= 1; if (g_keys['S'] || g_keys[VK_DOWN]) dir.y += 1; if (g_keys['A'] || g_keys[VK_LEFT]) dir.x -= 1; if (g_keys['D'] || g_keys[VK_RIGHT]) dir.x += 1; dir = dir.norm(); g_playerPos += dir * (PLAYER_SPEED * dt); g_playerPos.x = std::max(20.f, std::min((float)SCREEN_W - 20.f, g_playerPos.x)); g_playerPos.y = std::max(20.f, std::min((float)SCREEN_H - 20.f, g_playerPos.y)); Vec2 tom = { (float)g_mousePos.x - g_playerPos.x,(float)g_mousePos.y - g_playerPos.y }; g_playerAngle = atan2f(tom.y, tom.x); if (g_reloading) { g_reloadCd -= dt; if (g_reloadCd <= 0.f) { g_playerAmmo = PLAYER_MAX_AMMO; g_reloading = false; SpawnFloatText(g_playerPos - Vec2(0, 40), "RELOADED", RGB(100, 255, 100)); } } if (g_keys['R'] && !g_reloading && g_playerAmmo < PLAYER_MAX_AMMO) { g_reloading = true; g_reloadCd = RELOAD_TIME; } g_shootCd -= dt; if (!g_powerWeapon && g_mouseLeft && g_shootCd <= 0.f && !g_reloading && g_playerAmmo > 0 && !g_gameOver) { g_shootCd = SHOOT_COOLDOWN; g_playerAmmo--; Bullet* slot = nullptr; for (auto& b : g_bullets) if (!b.active) { slot = &b; break; } if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); } float sp = randf(-0.04f, 0.04f); slot->pos = g_playerPos; slot->vel = { cosf(g_playerAngle + sp) * BULLET_SPEED,sinf(g_playerAngle + sp) * BULLET_SPEED }; slot->active = true; slot->fromPlayer = true; slot->damage = 20; slot->radius = 5.f; SpawnParticles(g_playerPos + Vec2{ cosf(g_playerAngle) * 28,sinf(g_playerAngle) * 28 }, RGB(255, 200, 50), 5, 150.f, 0.1f); if (g_playerAmmo == 0) { g_reloading = true; g_reloadCd = RELOAD_TIME; } } int alive = 0; for (auto& e : g_enemies) if (e.alive) alive++; if (g_waveSpawning) { g_spawnTimer -= dt; if (g_spawnTimer <= 0.f && g_enemiesToSpawn > 0) { SpawnEnemy(g_wave); g_enemiesToSpawn--; g_spawnTimer = randf(.3f, .7f); } if (g_enemiesToSpawn == 0) g_waveSpawning = false; } if (!g_waveSpawning && alive == 0) { g_waveTimer += dt; if (g_waveTimer >= g_waveDelay) { g_wave++; StartWave(g_wave); int bonus = 10; g_playerHp = std::min((int)g_playerHp + bonus, PLAYER_MAX_HP); SpawnFloatText(g_playerPos - Vec2(0, 60), "+" + std::to_string(bonus) + " HP", RGB(80, 255, 80)); } } for (auto& e : g_enemies) { if (!e.alive) continue; e.pos += (g_playerPos - e.pos).norm() * (e.speed * dt); if (e.type == 1) { e.shootCd -= dt; if (e.shootCd <= 0.f) { e.shootCd = std::max(randf(1.5f, 3.5f) - (g_wave * .1f), 0.6f); Bullet* slot = nullptr; for (auto& b : g_bullets) if (!b.active) { slot = &b; break; } if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); } slot->pos = e.pos; slot->vel = (g_playerPos - e.pos).norm() * 280.f; slot->active = true; slot->fromPlayer = false; slot->damage = 12; slot->radius = 6.f; } } if (CircleCollide(g_playerPos, 16.f, e.pos, e.radius)) { int dmg = (e.type == 2) ? 20 : 10; DealDamageToPlayer(dmg); g_playerPos += (g_playerPos - e.pos).norm() * 30.f; SpawnParticles(g_playerPos, RGB(255, 50, 50), 8, 200.f, .3f); SpawnFloatText(g_playerPos - Vec2(0, 40), "-" + std::to_string(dmg), RGB(255, 80, 80)); } } for (auto& b : g_bullets) { if (!b.active) continue; b.pos += b.vel * dt; if (b.pos.x < -50 || b.pos.x > SCREEN_W + 50 || b.pos.y < -50 || b.pos.y > SCREEN_H + 50) { b.active = false; continue; } if (b.fromPlayer) { for (auto& e : g_enemies) { if (!e.alive) continue; if (CircleCollide(b.pos, b.radius, e.pos, e.radius)) { b.active = false; e.hp -= b.damage; SpawnParticles(b.pos, RGB(255, 100, 0), 6, 120.f, .25f); SpawnFloatText(e.pos - Vec2(0, 20), "-" + std::to_string(b.damage), RGB(255, 180, 50)); if (e.hp <= 0) { e.alive = false; g_playerKills++; int pts = (e.type == 2) ? 300 : (e.type == 1) ? 200 : 100; pts += g_wave * 10; g_playerScore += pts; SpawnParticles(e.pos, RGB(255, 60, 60), 16, 220.f, .6f); SpawnFloatText(e.pos, "+" + std::to_string(pts), RGB(255, 255, 50)); float dr = randf(0, 1); Drop d; d.pos = e.pos; d.active = true; d.lifetime = 10.f; d.pulseT = 0.f; if (dr < 0.05f) { d.type = DROP_WEAPON; d.weaponId = rand() % 3; g_drops.push_back(d); } else if (dr < 0.13f) { d.type = DROP_HEALTH; g_drops.push_back(d); } else if (dr < 0.25f) { d.type = DROP_AMMO; g_drops.push_back(d); } } break; } } } else { if (CircleCollide(b.pos, b.radius, g_playerPos, 16.f)) { b.active = false; DealDamageToPlayer(b.damage); SpawnParticles(g_playerPos, RGB(255, 50, 50), 8, 180.f, .25f); SpawnFloatText(g_playerPos - Vec2(0, 40), "-" + std::to_string(b.damage), RGB(255, 80, 80)); } } } if (g_powerWeapon) { g_powerWeaponTimer -= dt; if (g_powerWeaponTimer <= 0.f) { g_powerWeapon = false; g_shootCd = 0.f; SpawnFloatText(g_playerPos - Vec2(0, 50), "WEAPON EXPIRED", RGB(255, 100, 50)); } } for (auto& d : g_drops) { if (!d.active) continue; d.lifetime -= dt; d.pulseT += dt * 3.f; if (d.lifetime <= 0.f) { d.active = false; continue; } if (CircleCollide(g_playerPos, 20.f, d.pos, d.radius)) { d.active = false; if (d.type == DROP_HEALTH) { int h = 30; g_playerHp = std::min((int)g_playerHp + h, PLAYER_MAX_HP); SpawnFloatText(d.pos, "+" + std::to_string(h) + " HP", RGB(80, 255, 80)); SpawnParticles(d.pos, RGB(50, 255, 80), 10, 150.f, 0.5f); } else if (d.type == DROP_AMMO) { g_playerAmmo = PLAYER_MAX_AMMO; g_reloading = false; SpawnFloatText(d.pos, "AMMO REFILLED", RGB(100, 200, 255)); SpawnParticles(d.pos, RGB(100, 180, 255), 10, 150.f, 0.5f); } else { g_powerWeapon = true; g_powerWeaponId = d.weaponId; g_powerWeaponTimer = POWER_WEAPON_DURATION; g_shootCd = 0.f; const char* names[] = { "SHOTGUN","MINIGUN","ROCKET LAUNCHER" }; SpawnFloatText(d.pos, std::string("GOT ") + names[d.weaponId] + "!", RGB(255, 220, 50)); SpawnParticles(d.pos, RGB(255, 200, 50), 20, 200.f, 0.8f); } } } if (g_powerWeapon && g_mouseLeft && g_shootCd <= 0.f && !g_gameOver) { if (g_powerWeaponId == 0) { g_shootCd = 0.5f; for (int si = 0; si < 6; si++) { Bullet* slot = nullptr; for (auto& b : g_bullets) if (!b.active) { slot = &b; break; } if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); } float sp = randf(-0.35f, 0.35f); slot->pos = g_playerPos; slot->vel = { cosf(g_playerAngle + sp) * BULLET_SPEED * 0.8f,sinf(g_playerAngle + sp) * BULLET_SPEED * 0.8f }; slot->active = true; slot->fromPlayer = true; slot->damage = 25; slot->radius = 6.f; } SpawnParticles(g_playerPos + Vec2{ cosf(g_playerAngle) * 28,sinf(g_playerAngle) * 28 }, RGB(255, 140, 0), 10, 200.f, 0.15f); } else if (g_powerWeaponId == 1) { g_shootCd = 0.05f; Bullet* slot = nullptr; for (auto& b : g_bullets) if (!b.active) { slot = &b; break; } if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); } float sp = randf(-0.06f, 0.06f); slot->pos = g_playerPos; slot->vel = { cosf(g_playerAngle + sp) * BULLET_SPEED * 1.2f,sinf(g_playerAngle + sp) * BULLET_SPEED * 1.2f }; slot->active = true; slot->fromPlayer = true; slot->damage = 10; slot->radius = 4.f; SpawnParticles(g_playerPos + Vec2{ cosf(g_playerAngle) * 28,sinf(g_playerAngle) * 28 }, RGB(255, 255, 100), 3, 100.f, 0.05f); } else { g_shootCd = 0.8f; Bullet* slot = nullptr; for (auto& b : g_bullets) if (!b.active) { slot = &b; break; } if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); } slot->pos = g_playerPos; slot->vel = { cosf(g_playerAngle) * 300.f,sinf(g_playerAngle) * 300.f }; slot->active = true; slot->fromPlayer = true; slot->damage = 120; slot->radius = 14.f; SpawnParticles(g_playerPos + Vec2{ cosf(g_playerAngle) * 28,sinf(g_playerAngle) * 28 }, RGB(255, 80, 20), 12, 250.f, 0.2f); } } for (auto& p : g_particles) { if (!p.active) continue; p.pos += p.vel * dt; p.vel = p.vel * (1.f - dt * 3.f); p.life -= dt; if (p.life <= 0) p.active = false; } for (auto& f : g_floatTexts) { if (!f.active) continue; f.pos.y -= 55.f * dt; f.life -= dt; if (f.life <= 0) f.active = false; } }

// ============================================================
// CLIPBOARD / HITTEST
// ============================================================
static void CopyToClipboard(const std::string& text) {
    if (!OpenClipboard(g_hwnd)) return;
    EmptyClipboard();
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (hg) { memcpy(GlobalLock(hg), text.c_str(), text.size() + 1); GlobalUnlock(hg); SetClipboardData(CF_TEXT, hg); }
    CloseClipboard();
}

static int HitTestRow(int my) {
    if (my < POP_ROWS_Y || my >= POP_ROWS_Y + POP_ROWS_H) return -1;
    int idx = g_banScrollOffset + (my - POP_ROWS_Y) / ROW_H;
    if (idx < 0 || idx >= (int)g_hwidEntries.size()) return -1;
    return idx;
}

static bool HitTestScrollThumb(int mx, int my, int total, int vis, int& thumbY, int& thumbH) {
    if (total <= 0) return false;
    thumbH = std::max(16, (int)(POP_ROWS_H * ((float)vis / total)));
    thumbY = POP_ROWS_Y + (int)(POP_ROWS_H * ((float)g_banScrollOffset / total));
    return mx >= SB_X && mx < SB_X + 14 && my >= thumbY && my < thumbY + thumbH;
}

static std::string RowToString(const HwidEntry& e) {
    bool curNE = (e.current == NOT_EXIST || e.current.empty());
    bool banNE = (e.banned == NOT_EXIST || e.banned.empty());
    bool isNU = (e.meta.cat == CAT_NON_UNIQUE);
    std::string b = banNE ? "N/A" : e.banned;
    std::string c = curNE ? "N/A" : e.current;
    bool isBanned = !isNU && !curNE && !banNE && (e.banned == e.current);
    bool isSpoofed = !isNU && !curNE && !banNE && (e.banned != e.current);
    const char* st = curNE ? "N/A" : isNU ? "COLLECTED" : isSpoofed ? "SPOOFED" : isBanned ? "BANNED" : "N/A";
    return e.label + " | " + b + " | " + c + " | " + st;
}

static std::string AllRowsToString() {
    std::string out = "IDENTIFIER | BANNED VALUE | CURRENT VALUE | STATE\n";
    out += std::string(60, '-') + "\n";
    for (auto& e : g_hwidEntries) out += RowToString(e) + "\n";
    return out;
}

// ============================================================
// BAN POPUP RENDERING
// ============================================================
static void RenderBanPopup(HDC dc) {
    AlphaOverlay(dc, 218);
    DrawRect(dc, POP_X, POP_Y, POP_W, POP_H, RGB(6, 0, 0));
    HPEN border = CreatePen(PS_SOLID, 2, RGB(200, 0, 0));
    SelectObject(dc, border); SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, POP_X, POP_Y, POP_X + POP_W, POP_Y + POP_H);
    DeleteObject(border);

    DrawText_(dc, "YOU HAVE BEEN PERMANENTLY BANNED FROM THE GAME DUE TO CHEATING.",
        SCREEN_W / 2, POP_Y + 6, RGB(230, 0, 0), 19, true, true);
    DrawText_(dc, "Click row = copy current value.  Ctrl+C = copy row.  Ctrl+A = copy all.  Right-click = menu.",
        SCREEN_W / 2, POP_Y + 30, RGB(150, 40, 40), 11, false, true);

    HPEN div = CreatePen(PS_SOLID, 1, RGB(100, 0, 0));
    SelectObject(dc, div); MoveToEx(dc, POP_X + 8, POP_Y + 50, nullptr); LineTo(dc, SB_X - 2, POP_Y + 50);
    DeleteObject(div);

    int HY = POP_Y + 53;
    DrawText_(dc, "IDENTIFIER", COL_LABEL, HY, RGB(255, 200, 0), 13, true, false);
    DrawText_(dc, "BANNED VALUE", COL_BANNED, HY, RGB(255, 200, 0), 13, true, false);
    DrawText_(dc, "CURRENT VALUE", COL_CURRENT, HY, RGB(255, 200, 0), 13, true, false);
    DrawText_(dc, "STATE", COL_STATE, HY, RGB(255, 200, 0), 13, true, false);

    HPEN hdiv = CreatePen(PS_SOLID, 1, RGB(70, 0, 0));
    SelectObject(dc, hdiv); MoveToEx(dc, POP_X + 8, POP_Y + 68, nullptr); LineTo(dc, SB_X - 2, POP_Y + 68);
    DeleteObject(hdiv);

    HRGN clip = CreateRectRgn(POP_X, POP_ROWS_Y, SB_X, POP_ROWS_Y + POP_ROWS_H);
    SelectClipRgn(dc, clip);

    g_sortedIdx.clear();
    std::vector<int> sortedIdx;
    std::vector<int> bannedIdx, spoofedIdx, nonUniqueIdx, naIdx;
    for (int i = 0; i < (int)g_hwidEntries.size(); i++) {
        auto& ee = g_hwidEntries[i];
        bool curNE2 = (ee.current == NOT_EXIST || ee.current.empty());
        bool banNE2 = (ee.banned == NOT_EXIST || ee.banned.empty());
        if (curNE2) {
            naIdx.push_back(i);
        }
        else if (ee.meta.cat == CAT_NON_UNIQUE) {
            nonUniqueIdx.push_back(i);
        }
        else if (!banNE2 && ee.banned == ee.current) {
            bannedIdx.push_back(i);
        }
        else {
            spoofedIdx.push_back(i);
        }
    }
    for (int x : bannedIdx)     sortedIdx.push_back(x);
    for (int x : spoofedIdx)    sortedIdx.push_back(x);
    for (int x : nonUniqueIdx)  sortedIdx.push_back(x);
    for (int x : naIdx)         sortedIdx.push_back(x);
    g_sortedIdx = sortedIdx;

    int total = (int)sortedIdx.size(), vis = POP_ROWS_H / ROW_H;
    g_banScrollOffset = std::max(0, std::min(g_banScrollOffset, total - vis));

    int hoverSorted = -1;
    if (g_mousePos.y >= POP_ROWS_Y && g_mousePos.y < POP_ROWS_Y + POP_ROWS_H) {
        int scanY = POP_ROWS_Y, scanPrevH = -1;
        for (int _si = g_banScrollOffset; _si < total; _si++) {
            int _i = sortedIdx[_si];
            auto& _hh = g_hwidEntries[_i];
            bool _cn = (_hh.current == NOT_EXIST || _hh.current.empty());
            bool _bn = (_hh.banned == NOT_EXIST || _hh.banned.empty());
            int _sec = _cn ? 3 : (_hh.meta.cat == CAT_NON_UNIQUE) ? 2
                : (!_bn && _hh.banned == _hh.current) ? 0 : 1;
            if (_sec != scanPrevH) { scanPrevH = _sec; scanY += ROW_H + 4; }
            if (g_mousePos.y >= scanY && g_mousePos.y < scanY + ROW_H) {
                hoverSorted = _si; break;
            }
            scanY += ROW_H;
            if (scanY >= POP_ROWS_Y + POP_ROWS_H) break;
        }
    }

    auto GetSection = [&](int realIdx) -> int {
        auto& ee = g_hwidEntries[realIdx];
        bool cn = (ee.current == NOT_EXIST || ee.current.empty());
        bool bn = (ee.banned == NOT_EXIST || ee.banned.empty());
        if (cn) return 3;
        if (ee.meta.cat == CAT_NON_UNIQUE) return 2;
        if (!bn && ee.banned == ee.current) return 0;
        return 1;
        };
    static const struct { const char* title; COLORREF col; } kSectionInfo[] = {
        { "[ BANNED - Needs Spoofing ]",         RGB(220,  50,  50) },
        { "[ SPOOFED - Successfully Changed ]",  RGB(50, 200,  50) },
        { "[ COLLECTED - Non-Unique Info ]",      RGB(60, 160, 200) },
        { "[ N/A - Not Present On This System Or Zero/Garbage Value ]", RGB(80,  80,  80) },
    };

    int row = POP_ROWS_Y;
    int prevSection = -1;
    for (int si = g_banScrollOffset; si < total; si++) {
        if (row >= POP_ROWS_Y + POP_ROWS_H) break;
        int i = sortedIdx[si];
        int curSection = GetSection(i);

        if (curSection != prevSection) {
            prevSection = curSection;
            if (row + ROW_H + 2 < POP_ROWS_Y + POP_ROWS_H) {
                DrawRect(dc, POP_X + 1, row, SB_X - POP_X - 2, ROW_H + 4, RGB(15, 3, 3));

                const char* secTitle = kSectionInfo[curSection].title;
                COLORREF    secCol = kSectionInfo[curSection].col;
                int lineY = row + (ROW_H + 4) / 2;

                HFONT tmpFont = CreateFontA(ROW_FSZ + 1, 0, 0, 0, FW_BOLD, 0, 0, 0,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                    ANTIALIASED_QUALITY, DEFAULT_PITCH, "Consolas");
                SIZE textSz = {};
                SelectObject(dc, tmpFont);
                GetTextExtentPoint32A(dc, secTitle, (int)strlen(secTitle), &textSz);
                DeleteObject(tmpFont);

                int textX = (POP_X + SB_X) / 2 - textSz.cx / 2;
                int pad = 8;

                HPEN sp = CreatePen(PS_SOLID, 1, secCol);
                SelectObject(dc, sp);
                MoveToEx(dc, POP_X + 10, lineY, nullptr);
                LineTo(dc, textX - pad, lineY);
                MoveToEx(dc, textX + textSz.cx + pad, lineY, nullptr);
                LineTo(dc, SB_X - 10, lineY);
                DeleteObject(sp);

                DrawText_(dc, secTitle, textX, row + 2, secCol, ROW_FSZ + 1, true, false);
                row += ROW_H + 4;
                if (row >= POP_ROWS_Y + POP_ROWS_H) break;
            }
        }

        COLORREF rowBg = (si % 2 == 0) ? RGB(12, 0, 0) : RGB(6, 0, 0);
        if (si == hoverSorted) rowBg = RGB(35, 10, 10);
        if (i == g_selectedRow) rowBg = RGB(50, 20, 5);
        DrawRect(dc, POP_X + 1, row, SB_X - POP_X - 2, ROW_H, rowBg);

        auto& e = g_hwidEntries[i];
        bool curNE = (e.current == NOT_EXIST || e.current.empty());
        bool banNE = (e.banned == NOT_EXIST || e.banned.empty());
        bool isNonUnique = (e.meta.cat == CAT_NON_UNIQUE);
        bool isBanned = !isNonUnique && !curNE && !banNE && (e.banned == e.current);
        bool isSpoofed = !isNonUnique && !curNE && !banNE && (e.banned != e.current);
        std::string dispB = banNE ? "N/A" : e.banned;
        std::string dispC = curNE ? "N/A" : e.current;

        COLORREF rc, sc;
        const char* stateStr;
        if (curNE) {
            stateStr = "N/A";
            rc = sc = RGB(70, 70, 70);
        }
        else if (isNonUnique) {
            stateStr = "COLLECTED";
            rc = sc = RGB(90, 90, 90);
        }
        else if (isSpoofed) {
            stateStr = "SPOOFED";
            rc = sc = RGB(60, 220, 60);
        }
        else if (isBanned) {
            stateStr = "BANNED";
            rc = RGB(255, 70, 70);
            sc = RGB(255, 50, 50);
        }
        else {
            stateStr = "N/A";
            rc = sc = RGB(70, 70, 70);
        }

        DrawText_(dc, e.label.c_str(), COL_LABEL, row, rc, ROW_FSZ, isBanned, false);
        DrawText_(dc, Trunc(dispB, 56).c_str(), COL_BANNED, row, rc, ROW_FSZ, false, false);
        DrawText_(dc, Trunc(dispC, 56).c_str(), COL_CURRENT, row, sc, ROW_FSZ, false, false);
        DrawText_(dc, stateStr, COL_STATE, row, sc, ROW_FSZ, true, false);
        row += ROW_H;
    }
    SelectClipRgn(dc, nullptr); DeleteObject(clip);

    // --- scrollbar ---
    DrawRect(dc, SB_X, POP_ROWS_Y, 14, POP_ROWS_H, RGB(25, 0, 0));
    if (total > 0) {
        int thumbH = std::max(16, (int)(POP_ROWS_H * ((float)vis / total)));
        int thumbY = POP_ROWS_Y + (int)(POP_ROWS_H * ((float)g_banScrollOffset / total));
        // Highlight thumb if dragging or hovered
        bool thumbHov = (g_mousePos.x >= SB_X && g_mousePos.x < SB_X + 14 &&
            g_mousePos.y >= thumbY && g_mousePos.y < thumbY + thumbH);
        COLORREF thumbCol = g_sbDragging ? RGB(220, 60, 60) : thumbHov ? RGB(180, 30, 30) : RGB(150, 0, 0);
        DrawRect(dc, SB_X + 1, thumbY, 12, thumbH, thumbCol);
    }
    DrawText_(dc, "^", SB_X + 3, POP_ROWS_Y + 1, RGB(200, 60, 60), 11, true, false);
    DrawText_(dc, "v", SB_X + 3, POP_ROWS_Y + POP_ROWS_H - 14, RGB(200, 60, 60), 11, true, false);

    // --- footer ---
    HPEN bdiv = CreatePen(PS_SOLID, 1, RGB(100, 0, 0));
    SelectObject(dc, bdiv);
    MoveToEx(dc, POP_X + 8, POP_Y + POP_H - POP_FOOTER_H, nullptr);
    LineTo(dc, POP_X + POP_W - 8, POP_Y + POP_H - POP_FOOTER_H);
    DeleteObject(bdiv);
    DrawText_(dc, "[ F5 ] Refresh  [ F6 ] Ban Again  [ WHEEL/DRAG ] Scroll  [ Click ] Copy Value  [ Ctrl+A ] Copy All  [ ESC ] Quit",
        SCREEN_W / 2, POP_Y + POP_H - POP_FOOTER_H + 6, RGB(130, 130, 130), 11, false, true);

    // --- COPIED! flash banner ---
    if (g_copyFlash > 0.f) {
        int bw = 500, bh = 32, bx = SCREEN_W / 2 - bw / 2, by = POP_Y + POP_H - POP_FOOTER_H - 38;
        DrawRect(dc, bx, by, bw, bh, RGB(0, 80, 20));
        HPEN fp = CreatePen(PS_SOLID, 1, RGB(0, 200, 80));
        SelectObject(dc, fp); SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, bx, by, bx + bw, by + bh); DeleteObject(fp);
        std::string msg = "COPIED: " + Trunc(g_copyFlashText, 48);
        DrawText_(dc, msg.c_str(), SCREEN_W / 2, by + 8, RGB(100, 255, 130), 13, true, true);
    }
}

static void RenderMrCleanPopup(HDC dc) { AlphaOverlay(dc, 190); int pw = 700, ph = 250; int px = SCREEN_W / 2 - pw / 2, py = SCREEN_H / 2 - ph / 2; DrawRect(dc, px, py, pw, ph, RGB(5, 20, 5)); HPEN border = CreatePen(PS_SOLID, 2, RGB(0, 200, 80)); SelectObject(dc, border); SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, px, py, px + pw, py + ph); DeleteObject(border); DrawText_(dc, "WELCOME, MR. CLEAN!", SCREEN_W / 2, py + 16, RGB(0, 255, 100), 34, true, true); DrawText_(dc, "All identifiers successfully spoofed.", SCREEN_W / 2, py + 66, RGB(80, 220, 80), 16, false, true); DrawText_(dc, "You have proven yourself worthy.", SCREEN_W / 2, py + 90, RGB(80, 180, 80), 15, false, true); DrawText_(dc, "The game awaits. Good luck.", SCREEN_W / 2, py + 112, RGB(60, 160, 60), 14, false, true); HPEN div = CreatePen(PS_SOLID, 1, RGB(0, 100, 40)); SelectObject(dc, div); MoveToEx(dc, px + 20, py + 142, nullptr); LineTo(dc, px + pw - 20, py + 142); DeleteObject(div); DrawText_(dc, "[ ENTER ] Enter the game", SCREEN_W / 2, py + 152, RGB(100, 255, 100), 15, false, true); DrawText_(dc, "[  F6  ] Ban Again (re-snap HWIDs)", SCREEN_W / 2, py + 174, RGB(255, 160, 50), 13, false, true); DrawText_(dc, "Created by DeadEye707 aka @ali123x on UC", SCREEN_W / 2, py + ph - 20, RGB(40, 100, 40), 11, false, true); }

static void RenderGame() {
    HDC dc = g_memDC;
    DrawRect(dc, 0, 0, SCREEN_W, SCREEN_H, RGB(18, 22, 18));
    HPEN gp = CreatePen(PS_SOLID, 1, RGB(28, 35, 28)); SelectObject(dc, gp);
    for (int x = 0; x < SCREEN_W; x += TILE_SIZE) MoveToEx(dc, x, 0, nullptr), LineTo(dc, x, SCREEN_H);
    for (int y = 0; y < SCREEN_H; y += TILE_SIZE) MoveToEx(dc, 0, y, nullptr), LineTo(dc, SCREEN_W, y);
    DeleteObject(gp);
    for (auto& p : g_particles) { if (!p.active) continue; float t = p.life / p.maxLife; COLORREF c = RGB((int)(GetRValue(p.color) * t), (int)(GetGValue(p.color) * t), (int)(GetBValue(p.color) * t)); int s = (int)(p.size * t); if (s < 1) s = 1; DrawRect(dc, (int)p.pos.x - s / 2, (int)p.pos.y - s / 2, s, s, c); }
    for (auto& b : g_bullets) if (b.active && !b.fromPlayer) DrawCircle(dc, (int)b.pos.x, (int)b.pos.y, (int)b.radius, RGB(255, 80, 80), RGB(255, 30, 30));
    for (auto& b : g_bullets) if (b.active && b.fromPlayer) DrawCircle(dc, (int)b.pos.x, (int)b.pos.y, (int)b.radius, RGB(255, 240, 80), RGB(255, 200, 30));
    for (auto& e : g_enemies) { if (!e.alive) continue; int ix = (int)e.pos.x, iy = (int)e.pos.y, ir = (int)e.radius; COLORREF fill, out; switch (e.type) { case 0:fill = RGB(200, 40, 40); out = RGB(255, 80, 80); break; case 1:fill = RGB(180, 60, 200); out = RGB(220, 100, 255); break; default:fill = RGB(40, 100, 200); out = RGB(80, 160, 255); } DrawCircle(dc, ix, iy, ir, fill, out); DrawBar(dc, ix - ir, iy - ir - 8, ir * 2, 4, (float)e.hp / e.maxHp, RGB(50, 230, 50), RGB(60, 20, 20)); const char* lbl = e.type == 1 ? "S" : (e.type == 2 ? "T" : ""); if (lbl[0]) DrawText_(dc, lbl, ix, iy - 8, RGB(255, 255, 255), 12, true, true); }
    if (!g_gameOver) { int px2 = (int)g_playerPos.x, py2 = (int)g_playerPos.y; DrawCircle(dc, px2 + 3, py2 + 3, 18, RGB(0, 0, 0), RGB(0, 0, 0)); DrawCircle(dc, px2, py2, 18, RGB(50, 180, 255), RGB(100, 220, 255)); HPEN bp = CreatePen(PS_SOLID, 6, RGB(80, 220, 255)); SelectObject(dc, bp); MoveToEx(dc, px2 + (int)(cosf(g_playerAngle) * 14), py2 + (int)(sinf(g_playerAngle) * 14), nullptr); LineTo(dc, px2 + (int)(cosf(g_playerAngle) * 26), py2 + (int)(sinf(g_playerAngle) * 26)); DeleteObject(bp); DrawCircle(dc, px2, py2, 5, RGB(255, 255, 255), RGB(200, 200, 200)); }
    for (auto& d : g_drops) { if (!d.active) continue; if (d.lifetime < 3.f && ((int)(d.lifetime * 6)) % 2 == 0) continue; float pulse = 0.15f * sinf(d.pulseT) + 0.85f; int r = (int)(d.radius * pulse), ix = (int)d.pos.x, iy = (int)d.pos.y; COLORREF fill, outline; const char* label = ""; switch (d.type) { case DROP_HEALTH:fill = RGB(40, 200, 60); outline = RGB(100, 255, 100); label = "HP"; break; case DROP_AMMO:fill = RGB(40, 100, 220); outline = RGB(100, 180, 255); label = "AMO"; break; case DROP_WEAPON:switch (d.weaponId) { case 0:fill = RGB(220, 140, 0); outline = RGB(255, 200, 50); label = "SHG"; break; case 1:fill = RGB(200, 50, 200); outline = RGB(255, 100, 255); label = "MG"; break; default:fill = RGB(220, 50, 50); outline = RGB(255, 100, 80); label = "RKT"; }break; }DrawCircle(dc, ix, iy, r, fill, outline); DrawText_(dc, label, ix, iy - 6, RGB(255, 255, 255), 11, true, true); }
    for (auto& f : g_floatTexts) { if (!f.active) continue; float a = f.life > .3f ? 1.f : f.life / .3f; DrawText_(dc, f.text.c_str(), (int)f.pos.x, (int)f.pos.y, RGB((int)(GetRValue(f.color) * a), (int)(GetGValue(f.color) * a), (int)(GetBValue(f.color) * a)), 15, true, true); }
    DrawText_(dc, "HP", 14, 14, RGB(150, 150, 150), 14, false, false); DrawBar(dc, 44, 14, 200, 18, (float)g_playerHp / PLAYER_MAX_HP, RGB(50, 220, 80), RGB(40, 20, 20)); char hpstr[16]; sprintf_s(hpstr, "%d/%d", (int)g_playerHp, PLAYER_MAX_HP); DrawText_(dc, hpstr, 252, 14, RGB(180, 180, 180), 13, false, false);
    if (g_reloading) { char rl[32]; sprintf_s(rl, "RELOADING %.1fs", g_reloadCd); DrawText_(dc, rl, 14, 38, RGB(255, 200, 50), 14, true, false); }
    else { char am[32]; sprintf_s(am, "AMMO %d/%d", (int)g_playerAmmo, PLAYER_MAX_AMMO); DrawText_(dc, am, 14, 38, g_playerAmmo > 5 ? RGB(180, 220, 180) : RGB(255, 80, 80), 14, true, false); }
    char sc[64]; sprintf_s(sc, "SCORE  %d", (int)g_playerScore); DrawText_(dc, sc, SCREEN_W - 220, 14, RGB(255, 220, 50), 16, true, false);
    char wv[32]; sprintf_s(wv, "WAVE   %d", (int)g_wave); DrawText_(dc, wv, SCREEN_W - 220, 34, RGB(100, 200, 255), 15, true, false);
    char kl[32]; sprintf_s(kl, "KILLS  %d", (int)g_playerKills); DrawText_(dc, kl, SCREEN_W - 220, 52, RGB(180, 180, 180), 14, false, false);
    if (g_powerWeapon) { const char* wn[] = { "SHOTGUN","MINIGUN","ROCKET" }; COLORREF wc[] = { RGB(255,180,50),RGB(200,100,255),RGB(255,80,50) }; char wb[64]; sprintf_s(wb, "[%s] %.1fs", wn[g_powerWeaponId], g_powerWeaponTimer); DrawText_(dc, wb, SCREEN_W / 2, 14, wc[g_powerWeaponId], 18, true, true); DrawBar(dc, SCREEN_W / 2 - 100, 36, 200, 8, g_powerWeaponTimer / POWER_WEAPON_DURATION, wc[g_powerWeaponId], RGB(40, 20, 20)); }
    char fps[32]; sprintf_s(fps, "FPS:%d", g_fps); DrawText_(dc, fps, SCREEN_W - 66, SCREEN_H - 18, RGB(60, 80, 60), 11, false, false);
    if (!g_waveSpawning) { int ac = 0; for (auto& e : g_enemies) if (e.alive) ac++; if (ac == 0 && g_waveTimer < g_waveDelay) { char buf[64]; sprintf_s(buf, "NEXT WAVE IN %.1f...", g_waveDelay - g_waveTimer); DrawText_(dc, buf, SCREEN_W / 2, 80, RGB(255, 220, 100), 22, true, true); } }
    if (g_paused && !g_gameOver) { AlphaOverlay(dc, 180); int pw2 = 420, ph2 = 380; int px2 = SCREEN_W / 2 - pw2 / 2, py2 = SCREEN_H / 2 - ph2 / 2; DrawRect(dc, px2, py2, pw2, ph2, RGB(15, 20, 15)); HPEN pp = CreatePen(PS_SOLID, 2, RGB(50, 180, 50)); SelectObject(dc, pp); SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, px2, py2, px2 + pw2, py2 + ph2); DeleteObject(pp); DrawText_(dc, "PAUSED", SCREEN_W / 2, py2 + 18, RGB(100, 220, 100), 36, true, true); DrawText_(dc, "TrySpoofHWID v1.1", SCREEN_W / 2, py2 + 62, RGB(60, 120, 60), 14, false, true); HPEN dp = CreatePen(PS_SOLID, 1, RGB(40, 80, 40)); SelectObject(dc, dp); MoveToEx(dc, px2 + 20, py2 + 86, nullptr); LineTo(dc, px2 + pw2 - 20, py2 + 86); DeleteObject(dp); char sc3[64]; sprintf_s(sc3, "Score  %d", (int)g_playerScore); char wv3[32]; sprintf_s(wv3, "Wave   %d", (int)g_wave); char kl3[32]; sprintf_s(kl3, "Kills  %d", (int)g_playerKills); char hp3[32]; sprintf_s(hp3, "Health %d/%d", (int)g_playerHp, PLAYER_MAX_HP); DrawText_(dc, sc3, SCREEN_W / 2, py2 + 100, RGB(255, 220, 50), 16, false, true); DrawText_(dc, wv3, SCREEN_W / 2, py2 + 124, RGB(100, 200, 255), 16, false, true); DrawText_(dc, kl3, SCREEN_W / 2, py2 + 148, RGB(180, 180, 180), 16, false, true); DrawText_(dc, hp3, SCREEN_W / 2, py2 + 172, RGB(80, 220, 80), 16, false, true); HPEN dp2 = CreatePen(PS_SOLID, 1, RGB(40, 80, 40)); SelectObject(dc, dp2); MoveToEx(dc, px2 + 20, py2 + 200, nullptr); LineTo(dc, px2 + pw2 - 20, py2 + 200); DeleteObject(dp2); DrawText_(dc, "[ ESC ]  Resume", SCREEN_W / 2, py2 + 214, RGB(120, 220, 120), 16, false, true); DrawText_(dc, "[  R  ]  Restart", SCREEN_W / 2, py2 + 238, RGB(120, 180, 220), 16, false, true); DrawText_(dc, "[  F6 ]  Ban Again", SCREEN_W / 2, py2 + 262, RGB(255, 140, 50), 15, false, true); DrawText_(dc, "[ALT+F4] Quit", SCREEN_W / 2, py2 + 286, RGB(140, 80, 80), 16, false, true); DrawText_(dc, "Created by DeadEye707 aka @ali123x on UC", SCREEN_W / 2, py2 + ph2 - 18, RGB(80, 130, 80), 11, false, true); }
    if (g_gameOver) { AlphaOverlay(dc, 160); DrawText_(dc, "GAME OVER", SCREEN_W / 2, SCREEN_H / 2 - 120, RGB(255, 60, 60), 48, true, true); DrawText_(dc, "TrySpoofHWID v1.1", SCREEN_W / 2, SCREEN_H / 2 - 68, RGB(100, 180, 255), 18, false, true); char sc2[64]; sprintf_s(sc2, "SCORE:  %d", (int)g_playerScore); char hi[64]; sprintf_s(hi, "BEST:   %d", g_highScore); char wv2[32]; sprintf_s(wv2, "WAVE:   %d", (int)g_wave); char kl2[32]; sprintf_s(kl2, "KILLS:  %d", (int)g_playerKills); DrawText_(dc, sc2, SCREEN_W / 2, SCREEN_H / 2 - 30, RGB(255, 220, 50), 26, true, true); DrawText_(dc, hi, SCREEN_W / 2, SCREEN_H / 2 + 10, RGB(100, 200, 255), 22, false, true); DrawText_(dc, wv2, SCREEN_W / 2, SCREEN_H / 2 + 40, RGB(180, 180, 180), 20, false, true); DrawText_(dc, kl2, SCREEN_W / 2, SCREEN_H / 2 + 66, RGB(180, 180, 180), 20, false, true); DrawText_(dc, "Press R to restart", SCREEN_W / 2, SCREEN_H / 2 + 110, RGB(150, 150, 150), 18, false, true); DrawText_(dc, "Press ESC to quit", SCREEN_W / 2, SCREEN_H / 2 + 136, RGB(100, 100, 100), 15, false, true); }
    if (g_banned) RenderBanPopup(dc);
    if (g_mrClean) RenderMrCleanPopup(dc);
}

static void Present() { HDC hdc = GetDC(g_hwnd); BitBlt(hdc, 0, 0, SCREEN_W, SCREEN_H, g_memDC, 0, 0, SRCCOPY); ReleaseDC(g_hwnd, hdc); }

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_DESTROY: PostQuitMessage(0); return 0;
    case WM_MOUSEWHEEL: if (g_banned) { int d = GET_WHEEL_DELTA_WPARAM(wp); g_banScrollOffset += (d < 0 ? 3 : -3); if (g_banScrollOffset < 0) g_banScrollOffset = 0; } return 0;
    case WM_KEYDOWN:
        g_keys[wp & 0xFF] = true;
        if (wp == VK_F5) RunHwidCheck();
        // Ctrl+C: copy selected row; Ctrl+A: copy all rows
        if (g_banned && wp == 'C' && (GetKeyState(VK_CONTROL) & 0x8000)) {
            if (g_selectedRow >= 0 && g_selectedRow < (int)g_hwidEntries.size()) {
                std::string s = RowToString(g_hwidEntries[g_selectedRow]);
                CopyToClipboard(s);
                g_copyFlashText = Trunc(s, 40);
                g_copyFlash = 2.0f;
            }
        }
        if (g_banned && wp == 'A' && (GetKeyState(VK_CONTROL) & 0x8000)) {
            std::string s = AllRowsToString();
            CopyToClipboard(s);
            g_copyFlashText = "All rows";
            g_copyFlash = 2.0f;
        }
        if (wp == VK_F6) { ReBan(); RestartGame(); }
        if (wp == VK_RETURN && g_mrClean) { g_mrClean = false; }
        if (g_banned) { if (wp == VK_DOWN) g_banScrollOffset += 1; if (wp == VK_UP) g_banScrollOffset = std::max(0, g_banScrollOffset - 1); if (wp == VK_NEXT) g_banScrollOffset += 8; if (wp == VK_PRIOR) g_banScrollOffset = std::max(0, g_banScrollOffset - 8); }
        if (wp == VK_ESCAPE) { if (g_mrClean) { g_mrClean = false; return 0; } if (g_banned) { PostQuitMessage(0); return 0; } if (g_gameOver) PostQuitMessage(0); else g_paused = !g_paused; }
        if (wp == 'R' && g_gameOver && !g_banned) RestartGame();
        if (wp == 'R' && g_paused) { g_paused = false; RestartGame(); }
        return 0;
    case WM_KEYUP: g_keys[wp & 0xFF] = false; return 0;
    case WM_LBUTTONDOWN: {
        int mx = (short)LOWORD(lp), my = (short)HIWORD(lp);
        // Only set shooting mouseLeft when NOT in ban popup
        if (!g_banned) g_mouseLeft = true;
        if (g_banned) {
            int total = (int)g_hwidEntries.size(), vis = POP_ROWS_H / ROW_H;
            int thumbY, thumbH;
            if (HitTestScrollThumb(mx, my, total, vis, thumbY, thumbH)) {
                // Start scrollbar drag
                g_sbDragging = true;
                g_sbDragAnchorY = my;
                g_sbDragAnchorOff = g_banScrollOffset;
            }
            else if (mx >= SB_X && mx < SB_X + 14) {
                // Click on scrollbar track (not thumb) - jump
                float rel = (float)(my - POP_ROWS_Y) / POP_ROWS_H;
                g_banScrollOffset = (int)(rel * total);
            }
            else {
                // Click on a row
                // Map click Y to sorted row index, walking section headers
                int idx = -1;
                if (my >= POP_ROWS_Y && my < POP_ROWS_Y + POP_ROWS_H && !g_sortedIdx.empty()) {
                    int scanY2 = POP_ROWS_Y, scanPrev2 = -1;
                    int total2 = (int)g_sortedIdx.size();
                    for (int _si = g_banScrollOffset; _si < total2; _si++) {
                        int _i2 = g_sortedIdx[_si];
                        auto& _ee = g_hwidEntries[_i2];
                        bool _cn = (_ee.current == NOT_EXIST || _ee.current.empty());
                        bool _bn = (_ee.banned == NOT_EXIST || _ee.banned.empty());
                        int _sec = _cn ? 3 : (_ee.meta.cat == CAT_NON_UNIQUE) ? 2
                            : (!_bn && _ee.banned == _ee.current) ? 0 : 1;
                        if (_sec != scanPrev2) { scanPrev2 = _sec; scanY2 += ROW_H + 4; }
                        if (my >= scanY2 && my < scanY2 + ROW_H) { idx = _i2; break; }
                        scanY2 += ROW_H;
                        if (scanY2 >= POP_ROWS_Y + POP_ROWS_H) break;
                    }
                }
                if (idx >= 0 && idx < (int)g_hwidEntries.size()) {
                    g_selectedRow = idx;
                    auto& e = g_hwidEntries[idx];
                    // Copy current value (or banned if current is N/A)
                    bool curNE = (e.current == NOT_EXIST || e.current.empty());
                    std::string toCopy = curNE ? e.banned : e.current;
                    if (toCopy == NOT_EXIST || toCopy.empty()) toCopy = "N/A";
                    CopyToClipboard(toCopy);
                    g_copyFlashText = toCopy;
                    g_copyFlash = 2.0f;
                }
            }
        }
        return 0;
    }
    case WM_LBUTTONUP:
        g_mouseLeft = false;
        g_sbDragging = false;
        return 0;
    case WM_MOUSEMOVE: {
        int mx = (short)LOWORD(lp), my = (short)HIWORD(lp);
        g_mousePos.x = mx; g_mousePos.y = my;
        if (g_banned && g_sbDragging) {
            int total = (int)g_hwidEntries.size(), vis = POP_ROWS_H / ROW_H;
            int dy = my - g_sbDragAnchorY;
            int maxOff = std::max(0, total - vis);
            float scrollPerPx = (float)total / POP_ROWS_H;
            g_banScrollOffset = std::max(0, std::min(maxOff,
                g_sbDragAnchorOff + (int)(dy * scrollPerPx)));
        }
        return 0;
    }
    case WM_RBUTTONDOWN: {
        if (!g_banned) return 0;
        int mx = (short)LOWORD(lp), my = (short)HIWORD(lp);
        // Map right-click Y to sorted row index, walking section headers
        int idx = -1;
        if (my >= POP_ROWS_Y && my < POP_ROWS_Y + POP_ROWS_H && !g_sortedIdx.empty()) {
            int scanY3 = POP_ROWS_Y, scanPrev3 = -1;
            int total3 = (int)g_sortedIdx.size();
            for (int _si = g_banScrollOffset; _si < total3; _si++) {
                int _i3 = g_sortedIdx[_si];
                auto& _ee3 = g_hwidEntries[_i3];
                bool _cn3 = (_ee3.current == NOT_EXIST || _ee3.current.empty());
                bool _bn3 = (_ee3.banned == NOT_EXIST || _ee3.banned.empty());
                int _sec3 = _cn3 ? 3 : (_ee3.meta.cat == CAT_NON_UNIQUE) ? 2
                    : (!_bn3 && _ee3.banned == _ee3.current) ? 0 : 1;
                if (_sec3 != scanPrev3) { scanPrev3 = _sec3; scanY3 += ROW_H + 4; }
                if (my >= scanY3 && my < scanY3 + ROW_H) { idx = _i3; break; }
                scanY3 += ROW_H;
                if (scanY3 >= POP_ROWS_Y + POP_ROWS_H) break;
            }
        }
        if (idx >= 0 && idx < (int)g_hwidEntries.size()) {
            g_selectedRow = idx;
            auto& e = g_hwidEntries[idx];
            bool curNE = (e.current == NOT_EXIST || e.current.empty());
            bool banNE = (e.banned == NOT_EXIST || e.banned.empty());

            // Build context menu
            HMENU hMenu = CreatePopupMenu();
            AppendMenuA(hMenu, MF_STRING, 1, "Copy Current Value");
            AppendMenuA(hMenu, MF_STRING, 2, "Copy Banned Value");
            AppendMenuA(hMenu, MF_STRING, 3, "Copy Full Row");
            AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuA(hMenu, MF_STRING, 4, "Copy ALL Rows");

            if (curNE) EnableMenuItem(hMenu, 1, MF_BYCOMMAND | MF_GRAYED);
            if (banNE) EnableMenuItem(hMenu, 2, MF_BYCOMMAND | MF_GRAYED);

            POINT pt = { mx, my }; ClientToScreen(hwnd, &pt);
            int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(hMenu);

            std::string copied;
            if (cmd == 1) copied = curNE ? "N/A" : e.current;
            else if (cmd == 2) copied = banNE ? "N/A" : e.banned;
            else if (cmd == 3) copied = RowToString(e);
            else if (cmd == 4) { copied = AllRowsToString(); }

            if (!copied.empty() && cmd > 0) {
                CopyToClipboard(copied);
                g_copyFlashText = (cmd == 4) ? "All rows" : Trunc(copied, 40);
                g_copyFlash = 2.0f;
            }
        }
        return 0;
    }
    case WM_SETCURSOR:
        if (g_banned && LOWORD(lp) == HTCLIENT) {
            POINT pt; GetCursorPos(&pt); ScreenToClient(hwnd, &pt);
            int total = (int)g_hwidEntries.size(), vis = POP_ROWS_H / ROW_H;
            int thumbY, thumbH;
            bool onThumb = HitTestScrollThumb(pt.x, pt.y, total, vis, thumbY, thumbH);
            bool onRow = HitTestRow(pt.y) >= 0 && pt.x < SB_X;
            if (onThumb || pt.x >= SB_X) SetCursor(LoadCursor(nullptr, IDC_ARROW));
            else if (onRow)              SetCursor(LoadCursor(nullptr, IDC_HAND));
            else                         SetCursor(LoadCursor(nullptr, IDC_ARROW));
            return TRUE;
        }
        SetCursor(LoadCursor(nullptr, IDC_CROSS));
        return TRUE;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int WINAPI WinMain(_In_ HINSTANCE hInst, _In_opt_ HINSTANCE, _In_ LPSTR, _In_ int) {
    srand((unsigned)time(nullptr)); RunHwidCheck();
    WNDCLASSEXA wc{}; wc.cbSize = sizeof(WNDCLASSEXA); wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.lpszClassName = "TrySpoofHWID"; wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH); wc.hCursor = LoadCursor(nullptr, IDC_CROSS); wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION); wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION); RegisterClassExA(&wc);
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX; RECT rc = { 0,0,SCREEN_W,SCREEN_H }; AdjustWindowRect(&rc, style, FALSE);
    g_hwnd = CreateWindowA("TrySpoofHWID", "TrySpoofHWID v1.0 | Spoof your HWIDs to enter", style, CW_USEDEFAULT, CW_USEDEFAULT, rc.right - rc.left, rc.bottom - rc.top, nullptr, nullptr, hInst, nullptr);
    ShowWindow(g_hwnd, SW_SHOW); g_hdc = GetDC(g_hwnd); g_memDC = CreateCompatibleDC(g_hdc); g_hbmp = CreateCompatibleBitmap(g_hdc, SCREEN_W, SCREEN_H); SelectObject(g_memDC, g_hbmp);
    g_particles.resize(512); g_floatTexts.resize(32); StartWave(1);
    LARGE_INTEGER freq, prev, now; QueryPerformanceFrequency(&freq); QueryPerformanceCounter(&prev); int frameCount = 0; float fpsTimer = 0.f;
    MSG msg2{};
    while (true) {
        while (PeekMessageA(&msg2, nullptr, 0, 0, PM_REMOVE)) { if (msg2.message == WM_QUIT) goto done; TranslateMessage(&msg2); DispatchMessageA(&msg2); }
        QueryPerformanceCounter(&now); float dt = (float)(now.QuadPart - prev.QuadPart) / freq.QuadPart; prev = now; dt = std::min(dt, .05f); fpsTimer += dt; frameCount++; if (fpsTimer >= 1.f) { g_fps = frameCount; frameCount = 0; fpsTimer = 0.f; }
        // Tick copy flash timer always
        if (g_copyFlash > 0.f) { g_copyFlash -= dt; if (g_copyFlash < 0.f) g_copyFlash = 0.f; }
        if (!g_banned && !g_mrClean) Update(dt); RenderGame(); Present(); Sleep(1);
    }
done: return 0;
}