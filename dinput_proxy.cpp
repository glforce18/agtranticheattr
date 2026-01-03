#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <map>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")

#define AGTR_VERSION "7.1"
#define AGTR_HASH_LENGTH 8
#define AGTR_SCAN_INTERVAL 120000
#define AGTR_INITIAL_DELAY 10000

// ============================================
// API CONFIGURATION - DEĞİŞTİR!
// ============================================
#define API_HOST L"185.171.25.137"    // VDS IP
#define API_PORT 5000                  // Python API port
#define API_PATH L"/api/v1/scan"       // Endpoint
#define API_USE_HTTPS false            // HTTP

// ============================================
// OBFUSCATED KEY
// ============================================
#define OBF_XOR 0x5A
static const unsigned char OBF_KEY[] = {0x1B,0x3D,0x2E,0x28,0x6F,0x6A,0x6F,0x75,0x29,0x3F,0x39,0x28,0x3F,0x2E}; // "AGTR2025Secret"
#define OBF_KEY_LEN 14
static void Deobf(const unsigned char* s, int len, char* d) { for(int i=0;i<len;i++) d[i]=s[i]^OBF_XOR; d[len]=0; }

// ============================================
// DINPUT FORWARDING
// ============================================
HMODULE g_hOriginal = NULL;
typedef HRESULT(WINAPI* pfnDirectInputCreateA)(HINSTANCE, DWORD, LPVOID*, LPVOID);
typedef HRESULT(WINAPI* pfnDirectInputCreateW)(HINSTANCE, DWORD, LPVOID*, LPVOID);
typedef HRESULT(WINAPI* pfnDirectInputCreateEx)(HINSTANCE, DWORD, REFGUID, LPVOID*, LPVOID);
pfnDirectInputCreateA oDirectInputCreateA = NULL;
pfnDirectInputCreateW oDirectInputCreateW = NULL;
pfnDirectInputCreateEx oDirectInputCreateEx = NULL;

bool LoadOriginal() {
    if (g_hOriginal) return true;
    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat(sysPath, "\\dinput.dll");
    g_hOriginal = LoadLibraryA(sysPath);
    if (!g_hOriginal) return false;
    oDirectInputCreateA = (pfnDirectInputCreateA)GetProcAddress(g_hOriginal, "DirectInputCreateA");
    oDirectInputCreateW = (pfnDirectInputCreateW)GetProcAddress(g_hOriginal, "DirectInputCreateW");
    oDirectInputCreateEx = (pfnDirectInputCreateEx)GetProcAddress(g_hOriginal, "DirectInputCreateEx");
    return true;
}

extern "C" {
    __declspec(dllexport) HRESULT WINAPI DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPVOID* ppDI, LPVOID punkOuter) {
        if (!LoadOriginal() || !oDirectInputCreateA) return E_FAIL;
        return oDirectInputCreateA(hinst, dwVersion, ppDI, punkOuter);
    }
    __declspec(dllexport) HRESULT WINAPI DirectInputCreateW(HINSTANCE hinst, DWORD dwVersion, LPVOID* ppDI, LPVOID punkOuter) {
        if (!LoadOriginal() || !oDirectInputCreateW) return E_FAIL;
        return oDirectInputCreateW(hinst, dwVersion, ppDI, punkOuter);
    }
    __declspec(dllexport) HRESULT WINAPI DirectInputCreateEx(HINSTANCE hinst, DWORD dwVersion, REFGUID riid, LPVOID* ppvOut, LPVOID punkOuter) {
        if (!LoadOriginal() || !oDirectInputCreateEx) return E_FAIL;
        return oDirectInputCreateEx(hinst, dwVersion, riid, ppvOut, punkOuter);
    }
}

// ============================================
// MD5 HASH
// ============================================
class MD5 {
public:
    MD5() { Init(); }
    void Init() { count[0]=count[1]=0; state[0]=0x67452301; state[1]=0xefcdab89; state[2]=0x98badcfe; state[3]=0x10325476; }
    void Update(const unsigned char* input, unsigned int length) {
        unsigned int index=(count[0]>>3)&0x3F; count[0]+=length<<3;
        if(count[0]<(length<<3))count[1]++; count[1]+=length>>29;
        unsigned int partLen=64-index,i=0;
        if(length>=partLen){memcpy(&buffer[index],input,partLen);Transform(state,buffer);for(i=partLen;i+63<length;i+=64)Transform(state,&input[i]);index=0;}
        memcpy(&buffer[index],&input[i],length-i);
    }
    void Final(unsigned char digest[16]) {
        unsigned char bits[8]; Encode(bits,count,8);
        unsigned int index=(count[0]>>3)&0x3f,padLen=(index<56)?(56-index):(120-index);
        static unsigned char PADDING[64]={0x80}; Update(PADDING,padLen); Update(bits,8); Encode(digest,state,16);
    }
    std::string GetHashString() { 
        unsigned char d[16]; Final(d); 
        char h[33]; 
        for(int i=0;i<16;i++) sprintf(h+i*2,"%02X",d[i]);
        return std::string(h); 
    }
    std::string GetShortHash() { return GetHashString().substr(0, AGTR_HASH_LENGTH); }
private:
    unsigned int state[4],count[2]; unsigned char buffer[64];
    void Encode(unsigned char* o,const unsigned int* in,unsigned int len){for(unsigned int i=0,j=0;j<len;i++,j+=4){o[j]=in[i]&0xff;o[j+1]=(in[i]>>8)&0xff;o[j+2]=(in[i]>>16)&0xff;o[j+3]=(in[i]>>24)&0xff;}}
    void Decode(unsigned int* o,const unsigned char* in,unsigned int len){for(unsigned int i=0,j=0;j<len;i++,j+=4)o[i]=in[j]|(in[j+1]<<8)|(in[j+2]<<16)|(in[j+3]<<24);}
    void Transform(unsigned int st[4],const unsigned char block[64]) {
        unsigned int a=st[0],b=st[1],c=st[2],d=st[3],x[16]; Decode(x,block,64);
        #define F(x,y,z)(((x)&(y))|((~x)&(z)))
        #define G(x,y,z)(((x)&(z))|((y)&(~z)))
        #define H(x,y,z)((x)^(y)^(z))
        #define I(x,y,z)((y)^((x)|(~z)))
        #define RL(x,n)(((x)<<(n))|((x)>>(32-(n))))
        #define FF(a,b,c,d,x,s,ac){a+=F(b,c,d)+x+ac;a=RL(a,s);a+=b;}
        #define GG(a,b,c,d,x,s,ac){a+=G(b,c,d)+x+ac;a=RL(a,s);a+=b;}
        #define HH(a,b,c,d,x,s,ac){a+=H(b,c,d)+x+ac;a=RL(a,s);a+=b;}
        #define II(a,b,c,d,x,s,ac){a+=I(b,c,d)+x+ac;a=RL(a,s);a+=b;}
        FF(a,b,c,d,x[0],7,0xd76aa478);FF(d,a,b,c,x[1],12,0xe8c7b756);FF(c,d,a,b,x[2],17,0x242070db);FF(b,c,d,a,x[3],22,0xc1bdceee);
        FF(a,b,c,d,x[4],7,0xf57c0faf);FF(d,a,b,c,x[5],12,0x4787c62a);FF(c,d,a,b,x[6],17,0xa8304613);FF(b,c,d,a,x[7],22,0xfd469501);
        FF(a,b,c,d,x[8],7,0x698098d8);FF(d,a,b,c,x[9],12,0x8b44f7af);FF(c,d,a,b,x[10],17,0xffff5bb1);FF(b,c,d,a,x[11],22,0x895cd7be);
        FF(a,b,c,d,x[12],7,0x6b901122);FF(d,a,b,c,x[13],12,0xfd987193);FF(c,d,a,b,x[14],17,0xa679438e);FF(b,c,d,a,x[15],22,0x49b40821);
        GG(a,b,c,d,x[1],5,0xf61e2562);GG(d,a,b,c,x[6],9,0xc040b340);GG(c,d,a,b,x[11],14,0x265e5a51);GG(b,c,d,a,x[0],20,0xe9b6c7aa);
        GG(a,b,c,d,x[5],5,0xd62f105d);GG(d,a,b,c,x[10],9,0x02441453);GG(c,d,a,b,x[15],14,0xd8a1e681);GG(b,c,d,a,x[4],20,0xe7d3fbc8);
        GG(a,b,c,d,x[9],5,0x21e1cde6);GG(d,a,b,c,x[14],9,0xc33707d6);GG(c,d,a,b,x[3],14,0xf4d50d87);GG(b,c,d,a,x[8],20,0x455a14ed);
        GG(a,b,c,d,x[13],5,0xa9e3e905);GG(d,a,b,c,x[2],9,0xfcefa3f8);GG(c,d,a,b,x[7],14,0x676f02d9);GG(b,c,d,a,x[12],20,0x8d2a4c8a);
        HH(a,b,c,d,x[5],4,0xfffa3942);HH(d,a,b,c,x[8],11,0x8771f681);HH(c,d,a,b,x[11],16,0x6d9d6122);HH(b,c,d,a,x[14],23,0xfde5380c);
        HH(a,b,c,d,x[1],4,0xa4beea44);HH(d,a,b,c,x[4],11,0x4bdecfa9);HH(c,d,a,b,x[7],16,0xf6bb4b60);HH(b,c,d,a,x[10],23,0xbebfbc70);
        HH(a,b,c,d,x[13],4,0x289b7ec6);HH(d,a,b,c,x[0],11,0xeaa127fa);HH(c,d,a,b,x[3],16,0xd4ef3085);HH(b,c,d,a,x[6],23,0x04881d05);
        HH(a,b,c,d,x[9],4,0xd9d4d039);HH(d,a,b,c,x[12],11,0xe6db99e5);HH(c,d,a,b,x[15],16,0x1fa27cf8);HH(b,c,d,a,x[2],23,0xc4ac5665);
        II(a,b,c,d,x[0],6,0xf4292244);II(d,a,b,c,x[7],10,0x432aff97);II(c,d,a,b,x[14],15,0xab9423a7);II(b,c,d,a,x[5],21,0xfc93a039);
        II(a,b,c,d,x[12],6,0x655b59c3);II(d,a,b,c,x[3],10,0x8f0ccc92);II(c,d,a,b,x[10],15,0xffeff47d);II(b,c,d,a,x[1],21,0x85845dd1);
        II(a,b,c,d,x[8],6,0x6fa87e4f);II(d,a,b,c,x[15],10,0xfe2ce6e0);II(c,d,a,b,x[6],15,0xa3014314);II(b,c,d,a,x[13],21,0x4e0811a1);
        II(a,b,c,d,x[4],6,0xf7537e82);II(d,a,b,c,x[11],10,0xbd3af235);II(c,d,a,b,x[2],15,0x2ad7d2bb);II(b,c,d,a,x[9],21,0xeb86d391);
        st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;
    }
};

// ============================================
// GLOBALS
// ============================================
HANDLE g_hThread = NULL;
bool g_bRunning = false;
bool g_bThreadStarted = false;
char g_szGameDir[MAX_PATH] = {0};
char g_szValveDir[MAX_PATH] = {0};
char g_szHWID[64] = {0};
char g_szDLLHash[33] = {0};
char g_szServerIP[64] = {0};  // Bağlı olunan server
int g_iServerPort = 0;
int g_iSusCount = 0;
int g_iRegistrySus = 0;
bool g_bPassed = true;

// File cache
struct CachedFile { std::string shortHash, fullHash; DWORD modTime; };
std::map<std::string, CachedFile> g_FileCache;

// Suspicious lists
const char* g_SusProc[] = { 
    "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe", 
    "artmoney.exe", "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", 
    "processhacker.exe", "extreme injector.exe", "wemod.exe", 
    "ida.exe", "ida64.exe", "ghidra.exe", "reclass.exe", NULL 
};
const char* g_SusWin[] = { 
    "cheat engine", "artmoney", "process hacker", 
    "extreme injector", "[aimbot]", "[wallhack]", "[esp]", NULL 
};
const char* g_SusFile[] = { 
    "aimbot", "wallhack", "speedhack", "norecoil", "triggerbot", 
    "ssw", "plwh", "ogc", NULL 
};
const char* g_SusReg[] = {
    "SOFTWARE\\Cheat Engine", "SOFTWARE\\CheatEngine", "SOFTWARE\\ArtMoney",
    "SOFTWARE\\Process Hacker", "SOFTWARE\\x64dbg", "SOFTWARE\\OllyDbg", NULL
};

// ============================================
// LOGGING
// ============================================
void Log(const char* fmt, ...) {
    char path[MAX_PATH];
    sprintf(path, "%s\\agtr_anticheat.log", g_szValveDir);
    FILE* f = fopen(path, "a");
    if (f) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        va_list args; va_start(args, fmt); vfprintf(f, fmt, args); va_end(args);
        fprintf(f, "\n"); fclose(f);
    }
}

void ToLower(char* s) { for(int i=0;s[i];i++) if(s[i]>='A'&&s[i]<='Z') s[i]+=32; }

// ============================================
// HWID & HASH
// ============================================
void GenHWID() {
    int cpu[4]={0}; __cpuid(cpu,0);
    DWORD vol=0; GetVolumeInformationA("C:\\",NULL,0,&vol,NULL,NULL,NULL,0);
    char pc[MAX_COMPUTERNAME_LENGTH+1]={0}; DWORD sz=sizeof(pc); GetComputerNameA(pc,&sz);
    sprintf(g_szHWID, "%08X%08X%08X", cpu[0]^cpu[1], vol, (pc[0]<<24)|(pc[1]<<16)|(pc[2]<<8)|pc[3]);
    Log("HWID: %s", g_szHWID);
}

void GetFileHash(const char* filepath, char* shortHash, char* fullHash) {
    shortHash[0] = fullHash[0] = 0;
    HANDLE h = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    MD5 md5; unsigned char buf[32768]; DWORD rd;
    while(ReadFile(h, buf, sizeof(buf), &rd, NULL) && rd > 0) md5.Update(buf, rd);
    CloseHandle(h);
    std::string hash = md5.GetHashString();
    strncpy(fullHash, hash.c_str(), 32); fullHash[32] = 0;
    strncpy(shortHash, hash.c_str(), AGTR_HASH_LENGTH); shortHash[AGTR_HASH_LENGTH] = 0;
}

void ComputeDLLHash() {
    char path[MAX_PATH];
    sprintf(path, "%s\\dinput.dll", g_szGameDir);
    char shortH[16];
    GetFileHash(path, shortH, g_szDLLHash);
    Log("DLL Hash: %s", g_szDLLHash);
}

// ============================================
// SCANNING
// ============================================
int ScanProc() {
    int sus = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            char name[MAX_PATH]; strcpy(name, pe.szExeFile); ToLower(name);
            for (int i = 0; g_SusProc[i]; i++) {
                if (strcmp(name, g_SusProc[i]) == 0) { Log("SUS PROC: %s", pe.szExeFile); sus++; break; }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return sus;
}

static int g_WinSus = 0;
BOOL CALLBACK EnumWinCB(HWND hwnd, LPARAM) {
    char title[256] = {0}; GetWindowTextA(hwnd, title, 256);
    if (title[0]) { ToLower(title); for (int i = 0; g_SusWin[i]; i++) { if (strstr(title, g_SusWin[i])) { g_WinSus++; break; } } }
    return TRUE;
}
int ScanWin() { g_WinSus = 0; EnumWindows(EnumWinCB, 0); return g_WinSus; }

int ScanRegistry() {
    int sus = 0;
    for (int i = 0; g_SusReg[i]; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) { Log("SUS REG: HKCU\\%s", g_SusReg[i]); RegCloseKey(hKey); sus++; }
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) { Log("SUS REG: HKLM\\%s", g_SusReg[i]); RegCloseKey(hKey); sus++; }
    }
    g_iRegistrySus = sus;
    return sus;
}

void ScanDir(const char* dir, const char* pattern) {
    char searchPath[MAX_PATH]; sprintf(searchPath, "%s\\%s", dir, pattern);
    WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(searchPath, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char filepath[MAX_PATH], filename[MAX_PATH];
        sprintf(filepath, "%s\\%s", dir, fd.cFileName);
        strcpy(filename, fd.cFileName); ToLower(filename);
        DWORD modTime = fd.ftLastWriteTime.dwLowDateTime;
        auto it = g_FileCache.find(filename);
        if (it != g_FileCache.end() && it->second.modTime == modTime) continue;
        char shortH[16], fullH[64]; GetFileHash(filepath, shortH, fullH);
        if (shortH[0]) { CachedFile cf; cf.shortHash=shortH; cf.fullHash=fullH; cf.modTime=modTime; g_FileCache[filename]=cf; }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void ScanAllFiles() {
    char dir[MAX_PATH];
    ScanDir(g_szGameDir, "*.dll"); ScanDir(g_szGameDir, "*.exe");
    ScanDir(g_szValveDir, "*.dll");
    sprintf(dir, "%s\\cl_dlls", g_szValveDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\dlls", g_szValveDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\addons", g_szValveDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag", g_szGameDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag\\cl_dlls", g_szGameDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag\\dlls", g_szGameDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag\\addons", g_szGameDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\cstrike", g_szGameDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\cstrike\\cl_dlls", g_szGameDir); ScanDir(dir, "*.dll");
    Log("Scanned %d files", (int)g_FileCache.size());
}

int CheckSusFiles() {
    int sus = 0;
    for (auto& p : g_FileCache) {
        for (int i = 0; g_SusFile[i]; i++) {
            if (p.first.find(g_SusFile[i]) != std::string::npos) { Log("SUS FILE: %s", p.first.c_str()); sus++; break; }
        }
    }
    return sus;
}

// ============================================
// JSON BUILDER (Simple)
// ============================================
std::string EscapeJson(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    return out;
}

std::string BuildJson() {
    std::string json = "{";
    json += "\"hwid\":\"" + std::string(g_szHWID) + "\",";
    json += "\"version\":\"" + std::string(AGTR_VERSION) + "\",";
    json += "\"dll_hash\":\"" + std::string(g_szDLLHash) + "\",";
    json += "\"server_ip\":\"" + std::string(g_szServerIP) + "\",";
    json += "\"server_port\":" + std::to_string(g_iServerPort) + ",";
    json += "\"passed\":" + std::string(g_bPassed ? "true" : "false") + ",";
    json += "\"sus_count\":" + std::to_string(g_iSusCount) + ",";
    json += "\"reg_sus\":" + std::to_string(g_iRegistrySus) + ",";
    json += "\"timestamp\":" + std::to_string(GetTickCount()) + ",";
    
    // File hashes
    json += "\"hashes\":[";
    bool first = true;
    for (auto& h : g_FileCache) {
        if (!first) json += ",";
        json += "{\"file\":\"" + EscapeJson(h.first) + "\",\"hash\":\"" + h.second.shortHash + "\"}";
        first = false;
    }
    json += "]";
    
    json += "}";
    return json;
}

// ============================================
// SIGNATURE (HMAC-like)
// ============================================
std::string ComputeSignature(const std::string& data) {
    char key[32]; Deobf(OBF_KEY, OBF_KEY_LEN, key);
    MD5 md5;
    md5.Update((unsigned char*)key, strlen(key));
    md5.Update((unsigned char*)data.c_str(), data.length());
    return md5.GetHashString();
}

// ============================================
// HTTP POST (WinHTTP)
// ============================================
bool SendToAPI(const std::string& jsonData, const std::string& signature) {
    HINTERNET hSession = WinHttpOpen(L"AGTR/7.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) { Log("HTTP: Session failed"); return false; }
    
    HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
    if (!hConnect) { Log("HTTP: Connect failed"); WinHttpCloseHandle(hSession); return false; }
    
    DWORD flags = API_USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", API_PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { Log("HTTP: Request failed"); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    
    // Headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"X-AGTR-Signature: " + std::wstring(signature.begin(), signature.end()) + L"\r\n";
    headers += L"X-AGTR-HWID: " + std::wstring(g_szHWID, g_szHWID + strlen(g_szHWID)) + L"\r\n";
    
    BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)jsonData.c_str(), jsonData.length(), jsonData.length(), 0);
    if (!result) { Log("HTTP: Send failed (%d)", GetLastError()); }
    else {
        result = WinHttpReceiveResponse(hRequest, NULL);
        if (result) {
            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &statusSize, NULL);
            Log("HTTP: Response %d", statusCode);
            result = (statusCode == 200);
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result == TRUE;
}

// ============================================
// SERVER IP DETECTION
// ============================================
void DetectServerIP() {
    // userconfig.cfg veya config.cfg'den server IP'sini bul
    // Veya cmdline'dan
    char cmdline[1024];
    GetModuleFileNameA(NULL, cmdline, sizeof(cmdline));
    
    // Şimdilik boş bırak - server bağlantısında güncellenecek
    strcpy(g_szServerIP, "unknown");
    g_iServerPort = 27015;
    
    // TODO: cl.dll hook ile gerçek server IP'sini al
}

// ============================================
// CACHE SAVE/LOAD
// ============================================
void SaveCache() {
    char path[MAX_PATH]; sprintf(path, "%s\\agtr_cache.dat", g_szValveDir);
    FILE* f = fopen(path, "wb");
    if (f) { for (auto& p : g_FileCache) fprintf(f, "%s|%s|%s|%u\n", p.first.c_str(), p.second.shortHash.c_str(), p.second.fullHash.c_str(), p.second.modTime); fclose(f); }
}

void LoadCache() {
    char path[MAX_PATH]; sprintf(path, "%s\\agtr_cache.dat", g_szValveDir);
    FILE* f = fopen(path, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            char fn[256], sh[16], fh[64]; DWORD mod;
            if (sscanf(line, "%[^|]|%[^|]|%[^|]|%u", fn, sh, fh, &mod) == 4) {
                CachedFile cf; cf.shortHash=sh; cf.fullHash=fh; cf.modTime=mod; g_FileCache[fn]=cf;
            }
        }
        fclose(f);
        Log("Cache loaded: %d entries", (int)g_FileCache.size());
    }
}

// ============================================
// MAIN SCAN
// ============================================
void DoScan() {
    Log("=== SCAN START ===");
    
    ComputeDLLHash();
    DetectServerIP();
    
    g_iSusCount = 0;
    g_iSusCount += ScanProc();
    g_iSusCount += ScanWin();
    g_iSusCount += ScanRegistry();
    
    ScanAllFiles();
    g_iSusCount += CheckSusFiles();
    
    g_bPassed = (g_iSusCount == 0);
    
    // Build JSON and send
    std::string json = BuildJson();
    std::string sig = ComputeSignature(json);
    
    Log("Sending to API: %d bytes, sig: %s", (int)json.length(), sig.substr(0, 16).c_str());
    
    if (SendToAPI(json, sig)) {
        Log("API: Success");
    } else {
        Log("API: Failed (will retry)");
    }
    
    SaveCache();
    Log("Scan complete: %s | Sus:%d | Reg:%d", g_bPassed ? "CLEAN" : "SUSPICIOUS", g_iSusCount, g_iRegistrySus);
}

// ============================================
// MAIN THREAD
// ============================================
DWORD WINAPI ScanThread(LPVOID) {
    Sleep(AGTR_INITIAL_DELAY);
    
    Log("=== AGTR v%s Started (Network Mode) ===", AGTR_VERSION);
    
    GenHWID();
    LoadCache();
    
    // Initial scan
    DoScan();
    
    // Periodic rescan
    while (g_bRunning) {
        for (int i = 0; i < AGTR_SCAN_INTERVAL / 100 && g_bRunning; i++) {
            Sleep(100);
        }
        if (g_bRunning) DoScan();
    }
    
    return 0;
}

void StartScanThread() {
    if (g_bThreadStarted) return;
    g_bThreadStarted = true;
    g_bRunning = true;
    g_hThread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
}

void Init() {
    char path[MAX_PATH]; GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\'); if (slash) *slash = 0;
    strcpy(g_szGameDir, path);
    sprintf(g_szValveDir, "%s\\valve", path);
}

void Shutdown() {
    g_bRunning = false;
    if (g_hThread) { WaitForSingleObject(g_hThread, 2000); CloseHandle(g_hThread); }
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(hMod); LoadOriginal(); Init(); StartScanThread(); }
    else if (reason == DLL_PROCESS_DETACH) { Shutdown(); if (g_hOriginal) FreeLibrary(g_hOriginal); }
    return TRUE;
}
