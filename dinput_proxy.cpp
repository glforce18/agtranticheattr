/*
 * AGTR Anti-Cheat Client v8.0
 * ===========================
 * - Screenshot capture
 * - Memory scanner  
 * - Hook/DLL detector
 * - Auto-update
 * - 2 dakikada bir tarama
 * - Detaylı process/file loglama
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <set>
#include <map>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "gdi32.lib")

// ============================================
// CONFIGURATION
// ============================================
#define AGTR_VERSION "8.0"
#define API_HOST L"185.171.25.137"
#define API_PORT 5000
#define SCAN_INTERVAL_MS 120000  // 2 dakika
#define SCREENSHOT_ON_SUSPICIOUS true

// ============================================
// GLOBALS
// ============================================
static HMODULE g_hModule = NULL;
static HANDLE g_hScanThread = NULL;
static bool g_bRunning = true;
static char g_szHWID[64] = {0};
static char g_szGameDir[MAX_PATH] = {0};
static char g_szServerIP[64] = {0};
static int g_iServerPort = 0;

// Detaylı bilgi için
struct SuspiciousItem {
    std::string type;      // "process", "window", "registry", "module", "memory"
    std::string name;
    std::string path;
    std::string details;
};
static std::vector<SuspiciousItem> g_SuspiciousItems;

// ============================================
// CHEAT SIGNATURES
// ============================================
const char* CHEAT_PROCESSES[] = {
    "cheatengine", "artmoney", "ollydbg", "x64dbg", "x32dbg",
    "ida.exe", "ida64.exe", "ghidra", "processhacker", "procexp",
    "wireshark", "fiddler", "charles", "httpdebugger",
    "wemod", "trainer", "hack", "inject", "aimbot",
    "wallhack", "esp", "cheat", "hake", "gamekiller",
    NULL
};

const char* CHEAT_WINDOWS[] = {
    "cheat engine", "artmoney", "[aimbot]", "[wallhack]", "[esp]",
    "game trainer", "wemod", "hack tool", "injector",
    NULL
};

const char* CHEAT_REGISTRY[] = {
    "SOFTWARE\\Cheat Engine",
    "SOFTWARE\\Dark Byte\\Cheat Engine",
    "SOFTWARE\\ArtMoney",
    "SOFTWARE\\Process Hacker",
    "SOFTWARE\\x64dbg",
    NULL
};

// Memory signatures (cheat patterns)
struct MemorySignature {
    const char* name;
    BYTE pattern[16];
    int length;
};

const MemorySignature MEMORY_SIGS[] = {
    {"AimBot Pattern 1", {0x8B, 0x45, 0x08, 0x89, 0x45, 0xFC, 0x8B, 0x4D}, 8},
    {"WallHack Pattern 1", {0x74, 0x00, 0x8B, 0x45, 0xF8, 0x50, 0xFF, 0x15}, 8},
    {"SpeedHack Pattern 1", {0xD9, 0x05, 0x00, 0x00, 0x00, 0x00, 0xD8, 0x0D}, 8},
    {NULL, {0}, 0}
};

// Suspicious DLLs injected into hl.exe
const char* SUSPICIOUS_DLLS[] = {
    "opengl32.dll",  // Custom opengl hook
    "d3d9.dll",      // DirectX hook
    "dinput.dll",    // Input hook (not ours)
    "hook.dll", "inject.dll", "cheat.dll", "hack.dll",
    "aimbot.dll", "wallhack.dll", "esp.dll",
    NULL
};

// ============================================
// UTILITY FUNCTIONS
// ============================================
void LogToFile(const char* format, ...) {
    char szPath[MAX_PATH];
    if (g_szGameDir[0]) {
        sprintf(szPath, "%s\\agtr_client.log", g_szGameDir);
    } else {
        strcpy(szPath, "agtr_client.log");
    }
    
    FILE* f = fopen(szPath, "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        
        va_list args;
        va_start(args, format);
        vfprintf(f, format, args);
        va_end(args);
        
        fprintf(f, "\n");
        fclose(f);
    }
}

void GenerateHWID() {
    char volumeName[MAX_PATH], fileSystem[MAX_PATH];
    DWORD serialNumber = 0, maxLen, flags;
    
    GetVolumeInformationA("C:\\", volumeName, MAX_PATH, &serialNumber, &maxLen, &flags, fileSystem, MAX_PATH);
    
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    
    sprintf(g_szHWID, "%08X%s%08X", serialNumber, computerName, GetCurrentProcessId() ^ 0x12345678);
    
    // Hash it
    DWORD hash = 0;
    for (int i = 0; g_szHWID[i]; i++) {
        hash = hash * 31 + g_szHWID[i];
    }
    sprintf(g_szHWID, "%08X%08X%08X", serialNumber, hash, GetTickCount() & 0xFFFF0000);
}

bool ContainsCI(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;
    char h[512], n[256];
    strncpy(h, haystack, 511); h[511] = 0;
    strncpy(n, needle, 255); n[255] = 0;
    _strlwr(h); _strlwr(n);
    return strstr(h, n) != NULL;
}

// ============================================
// SCREENSHOT CAPTURE
// ============================================
std::string CaptureScreenshot() {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    // Küçült (1/4 boyut)
    int newWidth = width / 4;
    int newHeight = height / 4;
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, newWidth, newHeight);
    SelectObject(hdcMem, hBitmap);
    
    SetStretchBltMode(hdcMem, HALFTONE);
    StretchBlt(hdcMem, 0, 0, newWidth, newHeight, hdcScreen, 0, 0, width, height, SRCCOPY);
    
    // BMP header
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = newWidth;
    bi.biHeight = -newHeight; // Top-down
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    
    int rowSize = ((newWidth * 3 + 3) & ~3);
    int dataSize = rowSize * newHeight;
    
    std::vector<BYTE> pixels(dataSize);
    GetDIBits(hdcMem, hBitmap, 0, newHeight, pixels.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    // Base64 encode
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    
    // BMP file header + info header + data
    BITMAPFILEHEADER bf = {0};
    bf.bfType = 0x4D42;
    bf.bfSize = sizeof(bf) + sizeof(bi) + dataSize;
    bf.bfOffBits = sizeof(bf) + sizeof(bi);
    
    std::vector<BYTE> bmpData;
    bmpData.insert(bmpData.end(), (BYTE*)&bf, (BYTE*)&bf + sizeof(bf));
    bmpData.insert(bmpData.end(), (BYTE*)&bi, (BYTE*)&bi + sizeof(bi));
    bmpData.insert(bmpData.end(), pixels.begin(), pixels.end());
    
    // Base64
    for (size_t i = 0; i < bmpData.size(); i += 3) {
        BYTE b1 = bmpData[i];
        BYTE b2 = (i + 1 < bmpData.size()) ? bmpData[i + 1] : 0;
        BYTE b3 = (i + 2 < bmpData.size()) ? bmpData[i + 2] : 0;
        
        result += b64[b1 >> 2];
        result += b64[((b1 & 3) << 4) | (b2 >> 4)];
        result += (i + 1 < bmpData.size()) ? b64[((b2 & 15) << 2) | (b3 >> 6)] : '=';
        result += (i + 2 < bmpData.size()) ? b64[b3 & 63] : '=';
    }
    
    return result;
}

// ============================================
// PROCESS SCANNER
// ============================================
int ScanProcesses() {
    int susCount = 0;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            char exeName[MAX_PATH];
            strcpy(exeName, pe.szExeFile);
            _strlwr(exeName);
            
            for (int i = 0; CHEAT_PROCESSES[i]; i++) {
                if (ContainsCI(exeName, CHEAT_PROCESSES[i])) {
                    SuspiciousItem item;
                    item.type = "process";
                    item.name = pe.szExeFile;
                    item.details = "Cheat-related process detected";
                    
                    // Get full path
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProc) {
                        char path[MAX_PATH];
                        DWORD size = MAX_PATH;
                        if (QueryFullProcessImageNameA(hProc, 0, path, &size)) {
                            item.path = path;
                        }
                        CloseHandle(hProc);
                    }
                    
                    g_SuspiciousItems.push_back(item);
                    susCount++;
                    LogToFile("SUSPICIOUS PROCESS: %s (PID: %d)", pe.szExeFile, pe.th32ProcessID);
                    break;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return susCount;
}

// ============================================
// WINDOW SCANNER
// ============================================
static int g_WindowSusCount = 0;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    char title[256];
    GetWindowTextA(hwnd, title, sizeof(title));
    
    if (strlen(title) > 0) {
        for (int i = 0; CHEAT_WINDOWS[i]; i++) {
            if (ContainsCI(title, CHEAT_WINDOWS[i])) {
                SuspiciousItem item;
                item.type = "window";
                item.name = title;
                
                DWORD pid;
                GetWindowThreadProcessId(hwnd, &pid);
                char details[128];
                sprintf(details, "Suspicious window (PID: %d)", pid);
                item.details = details;
                
                g_SuspiciousItems.push_back(item);
                g_WindowSusCount++;
                LogToFile("SUSPICIOUS WINDOW: %s", title);
                break;
            }
        }
    }
    return TRUE;
}

int ScanWindows() {
    g_WindowSusCount = 0;
    EnumWindows(EnumWindowsProc, 0);
    return g_WindowSusCount;
}

// ============================================
// REGISTRY SCANNER
// ============================================
int ScanRegistry() {
    int susCount = 0;
    
    for (int i = 0; CHEAT_REGISTRY[i]; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, CHEAT_REGISTRY[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            SuspiciousItem item;
            item.type = "registry";
            item.name = CHEAT_REGISTRY[i];
            item.path = "HKEY_CURRENT_USER";
            item.details = "Cheat software registry key found";
            
            g_SuspiciousItems.push_back(item);
            susCount++;
            LogToFile("SUSPICIOUS REGISTRY: %s", CHEAT_REGISTRY[i]);
            RegCloseKey(hKey);
        }
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, CHEAT_REGISTRY[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            SuspiciousItem item;
            item.type = "registry";
            item.name = CHEAT_REGISTRY[i];
            item.path = "HKEY_LOCAL_MACHINE";
            item.details = "Cheat software registry key found";
            
            g_SuspiciousItems.push_back(item);
            susCount++;
            RegCloseKey(hKey);
        }
    }
    
    return susCount;
}

// ============================================
// MODULE/DLL SCANNER (Hook Detection)
// ============================================
int ScanModules() {
    int susCount = 0;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    
    std::set<std::string> loadedDlls;
    
    if (Module32First(hSnapshot, &me)) {
        do {
            char dllName[MAX_PATH];
            strcpy(dllName, me.szModule);
            _strlwr(dllName);
            
            loadedDlls.insert(dllName);
            
            // Check suspicious DLLs
            for (int i = 0; SUSPICIOUS_DLLS[i]; i++) {
                if (ContainsCI(dllName, SUSPICIOUS_DLLS[i])) {
                    // opengl32.dll özel durum - sistem DLL'i mi kontrol et
                    if (strcmp(SUSPICIOUS_DLLS[i], "opengl32.dll") == 0) {
                        char sysDir[MAX_PATH];
                        GetSystemDirectoryA(sysDir, MAX_PATH);
                        if (ContainsCI(me.szExePath, sysDir)) continue; // Sistem DLL'i, OK
                    }
                    
                    SuspiciousItem item;
                    item.type = "module";
                    item.name = me.szModule;
                    item.path = me.szExePath;
                    item.details = "Suspicious DLL loaded in game process";
                    
                    g_SuspiciousItems.push_back(item);
                    susCount++;
                    LogToFile("SUSPICIOUS MODULE: %s (%s)", me.szModule, me.szExePath);
                    break;
                }
            }
        } while (Module32Next(hSnapshot, &me));
    }
    
    CloseHandle(hSnapshot);
    return susCount;
}

// ============================================
// MEMORY SCANNER
// ============================================
int ScanMemory() {
    int susCount = 0;
    
    HANDLE hProcess = GetCurrentProcess();
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = (BYTE*)si.lpMinimumApplicationAddress;
    
    while (addr < si.lpMaximumApplicationAddress) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_READWRITE)) {
                
                // Sadece makul boyuttaki bölgeleri tara (< 10MB)
                if (mbi.RegionSize < 10 * 1024 * 1024) {
                    std::vector<BYTE> buffer(mbi.RegionSize);
                    SIZE_T bytesRead;
                    
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                        // Signature ara
                        for (int s = 0; MEMORY_SIGS[s].name; s++) {
                            for (SIZE_T i = 0; i < bytesRead - MEMORY_SIGS[s].length; i++) {
                                bool match = true;
                                for (int j = 0; j < MEMORY_SIGS[s].length; j++) {
                                    if (MEMORY_SIGS[s].pattern[j] != 0x00 && 
                                        buffer[i + j] != MEMORY_SIGS[s].pattern[j]) {
                                        match = false;
                                        break;
                                    }
                                }
                                if (match) {
                                    SuspiciousItem item;
                                    item.type = "memory";
                                    item.name = MEMORY_SIGS[s].name;
                                    char details[128];
                                    sprintf(details, "Found at 0x%p", (void*)((BYTE*)mbi.BaseAddress + i));
                                    item.details = details;
                                    
                                    g_SuspiciousItems.push_back(item);
                                    susCount++;
                                    LogToFile("SUSPICIOUS MEMORY: %s at 0x%p", MEMORY_SIGS[s].name, (void*)((BYTE*)mbi.BaseAddress + i));
                                    break; // Bir kez bulduysa yeter
                                }
                            }
                        }
                    }
                }
            }
            addr += mbi.RegionSize;
        } else {
            addr += 4096;
        }
    }
    
    return susCount;
}

// ============================================
// FILE HASH SCANNER
// ============================================
struct FileHashInfo {
    std::string path;
    std::string hash;
};
static std::vector<FileHashInfo> g_FileHashes;

DWORD ComputeFileHash(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    DWORD hash = 0x12345678;
    BYTE buffer[4096];
    size_t read;
    
    while ((read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        for (size_t i = 0; i < read; i++) {
            hash = ((hash << 5) + hash) + buffer[i];
        }
    }
    
    fclose(f);
    return hash;
}

int ScanGameFiles() {
    g_FileHashes.clear();
    
    if (!g_szGameDir[0]) return 0;
    
    char searchPath[MAX_PATH];
    sprintf(searchPath, "%s\\*.dll", g_szGameDir);
    
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            char fullPath[MAX_PATH];
            sprintf(fullPath, "%s\\%s", g_szGameDir, fd.cFileName);
            
            DWORD hash = ComputeFileHash(fullPath);
            if (hash) {
                FileHashInfo info;
                info.path = fd.cFileName;
                char hashStr[16];
                sprintf(hashStr, "%08X", hash);
                info.hash = hashStr;
                g_FileHashes.push_back(info);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    
    // cl_dlls de tara
    sprintf(searchPath, "%s\\cl_dlls\\*.dll", g_szGameDir);
    hFind = FindFirstFileA(searchPath, &fd);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            char fullPath[MAX_PATH];
            sprintf(fullPath, "%s\\cl_dlls\\%s", g_szGameDir, fd.cFileName);
            
            DWORD hash = ComputeFileHash(fullPath);
            if (hash) {
                FileHashInfo info;
                info.path = std::string("cl_dlls\\") + fd.cFileName;
                char hashStr[16];
                sprintf(hashStr, "%08X", hash);
                info.hash = hashStr;
                g_FileHashes.push_back(info);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    
    return g_FileHashes.size();
}

// ============================================
// API COMMUNICATION
// ============================================
bool SendToAPI(const char* jsonData, char* response, int responseSize) {
    HINTERNET hSession = WinHttpOpen(L"AGTR/8.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/v1/scan", NULL, NULL, NULL, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    const wchar_t* headers = L"Content-Type: application/json";
    bool result = WinHttpSendRequest(hRequest, headers, -1, (LPVOID)jsonData, strlen(jsonData), strlen(jsonData), 0);
    
    if (result) {
        result = WinHttpReceiveResponse(hRequest, NULL);
        
        if (result && response && responseSize > 0) {
            DWORD bytesRead;
            WinHttpReadData(hRequest, response, responseSize - 1, &bytesRead);
            response[bytesRead] = 0;
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result;
}

bool CheckForUpdate() {
    HINTERNET hSession = WinHttpOpen(L"AGTR/8.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/v1/client/version", NULL, NULL, NULL, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    bool result = WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
    
    if (result) {
        result = WinHttpReceiveResponse(hRequest, NULL);
        
        if (result) {
            char response[256];
            DWORD bytesRead;
            WinHttpReadData(hRequest, response, sizeof(response) - 1, &bytesRead);
            response[bytesRead] = 0;
            
            // {"version":"8.0","update_url":"..."}
            if (strstr(response, "\"version\"")) {
                char* ver = strstr(response, "\"version\":\"");
                if (ver) {
                    ver += 11;
                    char* end = strchr(ver, '"');
                    if (end) {
                        *end = 0;
                        if (strcmp(ver, AGTR_VERSION) != 0) {
                            LogToFile("UPDATE AVAILABLE: %s (current: %s)", ver, AGTR_VERSION);
                            // TODO: Download and update
                        }
                    }
                }
            }
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result;
}

// ============================================
// BUILD JSON PAYLOAD
// ============================================
std::string BuildScanPayload(bool includeScreenshot) {
    std::string json = "{";
    
    // Basic info
    json += "\"hwid\":\""; json += g_szHWID; json += "\",";
    json += "\"version\":\"" AGTR_VERSION "\",";
    json += "\"server_ip\":\""; json += g_szServerIP; json += "\",";
    
    char portStr[16];
    sprintf(portStr, "%d", g_iServerPort);
    json += "\"server_port\":"; json += portStr; json += ",";
    
    // Scan results
    int totalSus = g_SuspiciousItems.size();
    json += "\"passed\":"; json += (totalSus == 0) ? "true" : "false"; json += ",";
    
    char susStr[16];
    sprintf(susStr, "%d", totalSus);
    json += "\"sus_count\":"; json += susStr; json += ",";
    json += "\"reg_sus\":0,";
    
    // File hashes
    json += "\"hashes\":[";
    for (size_t i = 0; i < g_FileHashes.size(); i++) {
        if (i > 0) json += ",";
        json += "{\"file\":\""; json += g_FileHashes[i].path; json += "\",";
        json += "\"hash\":\""; json += g_FileHashes[i].hash; json += "\"}";
    }
    json += "],";
    
    // Suspicious items (DETAYLI)
    json += "\"suspicious\":[";
    for (size_t i = 0; i < g_SuspiciousItems.size(); i++) {
        if (i > 0) json += ",";
        json += "{";
        json += "\"type\":\""; json += g_SuspiciousItems[i].type; json += "\",";
        json += "\"name\":\""; json += g_SuspiciousItems[i].name; json += "\",";
        json += "\"path\":\""; 
        // Escape backslashes
        for (char c : g_SuspiciousItems[i].path) {
            if (c == '\\') json += "\\\\";
            else json += c;
        }
        json += "\",";
        json += "\"details\":\""; json += g_SuspiciousItems[i].details; json += "\"";
        json += "}";
    }
    json += "]";
    
    // Screenshot (if suspicious)
    if (includeScreenshot && totalSus > 0 && SCREENSHOT_ON_SUSPICIOUS) {
        std::string screenshot = CaptureScreenshot();
        if (!screenshot.empty()) {
            json += ",\"screenshot\":\""; json += screenshot; json += "\"";
        }
    }
    
    json += "}";
    return json;
}

// ============================================
// MAIN SCAN THREAD
// ============================================
DWORD WINAPI ScanThread(LPVOID param) {
    // İlk tarama için 10 saniye bekle
    Sleep(10000);
    
    LogToFile("AGTR v%s Scan Thread Started", AGTR_VERSION);
    
    // Update kontrolü
    CheckForUpdate();
    
    while (g_bRunning) {
        g_SuspiciousItems.clear();
        
        LogToFile("=== Starting Scan ===");
        
        // Tüm taramaları yap
        int procSus = ScanProcesses();
        int winSus = ScanWindows();
        int regSus = ScanRegistry();
        int modSus = ScanModules();
        int memSus = ScanMemory();
        int fileCount = ScanGameFiles();
        
        int totalSus = procSus + winSus + regSus + modSus + memSus;
        
        LogToFile("Scan complete: Proc=%d Win=%d Reg=%d Mod=%d Mem=%d Files=%d Total=%d",
            procSus, winSus, regSus, modSus, memSus, fileCount, totalSus);
        
        // API'ye gönder
        std::string payload = BuildScanPayload(totalSus > 0);
        char response[1024];
        
        if (SendToAPI(payload.c_str(), response, sizeof(response))) {
            LogToFile("API Response: %s", response);
            
            // Kick komutu geldi mi?
            if (strstr(response, "\"action\":\"kick\"")) {
                LogToFile("KICKED BY SERVER");
                // TODO: Oyundan çık
            }
        } else {
            LogToFile("API Connection Failed");
        }
        
        // 2 dakika bekle
        for (int i = 0; i < SCAN_INTERVAL_MS / 1000 && g_bRunning; i++) {
            Sleep(1000);
        }
    }
    
    return 0;
}

// ============================================
// GET SERVER INFO
// ============================================
void UpdateServerInfo() {
    // TODO: hl.exe'den server IP al
    // Şimdilik boş bırak, SMA'dan gelecek
}

// ============================================
// DLL ENTRY POINT
// ============================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        
        // Game directory bul
        GetModuleFileNameA(NULL, g_szGameDir, MAX_PATH);
        char* lastSlash = strrchr(g_szGameDir, '\\');
        if (lastSlash) *lastSlash = 0;
        
        // HWID oluştur
        GenerateHWID();
        
        LogToFile("=== AGTR v%s Loaded ===", AGTR_VERSION);
        LogToFile("HWID: %s", g_szHWID);
        LogToFile("Game Dir: %s", g_szGameDir);
        
        // Scan thread başlat
        g_hScanThread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        g_bRunning = false;
        if (g_hScanThread) {
            WaitForSingleObject(g_hScanThread, 3000);
            CloseHandle(g_hScanThread);
        }
        LogToFile("=== AGTR Unloaded ===");
    }
    
    return TRUE;
}

// ============================================
// EXPORTS (Proxy için)
// ============================================
extern "C" {
    __declspec(dllexport) void __cdecl DirectInputCreateA() {}
    __declspec(dllexport) void __cdecl DirectInputCreateW() {}
    __declspec(dllexport) void __cdecl DirectInputCreateEx() {}
}
