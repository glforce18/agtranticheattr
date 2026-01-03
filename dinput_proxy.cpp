#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <set>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

#define AGTR_VERSION "6.0"
#define AGTR_SCAN_INTERVAL 60000
#define AGTR_INITIAL_DELAY 3000
#define AGTR_HASH_LENGTH 8

// #4 Obfuscated Master Key (XOR 0x5A)
#define OBF_XOR 0x5A
static const unsigned char OBF_MKEY[] = {0x1B,0x3D,0x2E,0x28,0x6F,0x6A,0x6F,0x75,0x1D,0x3F,0x2B,0x71}; // "AGTR2025KEY!"
#define OBF_MKEY_LEN 12
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

void StartScanThread();

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
// ENCRYPTION
// ============================================
std::string Encrypt(const std::string& data) {
    const char* key = AGTR_ENCRYPTION_KEY;
    size_t keyLen = strlen(key);
    std::string result;
    for (size_t i = 0; i < data.length(); i++) {
        unsigned char c = data[i] ^ key[i % keyLen];
        char hex[3]; sprintf(hex, "%02x", c);
        result += hex;
    }
    return result;
}

// ============================================
// SUSPICIOUS LISTS
// ============================================
const char* g_SusProc[] = { 
    "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe", 
    "artmoney.exe", "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", 
    "processhacker.exe", "extreme injector.exe", "wemod.exe", 
    "ida.exe", "ida64.exe", NULL 
};

const char* g_SusWin[] = { 
    "cheat engine", "artmoney", "process hacker", 
    "extreme injector", "[aimbot]", "[wallhack]", "[esp]", NULL 
};

const char* g_SusKey[] = { 
    "aimbot", "wallhack", "speedhack", "norecoil", "triggerbot", 
    "ssw", "plwh", "ogc", NULL 
};

// #15 Registry keys for cheat detection
const char* g_SusReg[] = {
    "SOFTWARE\\Cheat Engine", "SOFTWARE\\CheatEngine", "SOFTWARE\\ArtMoney",
    "SOFTWARE\\Process Hacker", "SOFTWARE\\x64dbg", "SOFTWARE\\OllyDbg", NULL
};

// ============================================
// GLOBALS
// ============================================
HANDLE g_hThread = NULL;
HANDLE g_hWatchThread = NULL;  // Challenge watcher
bool g_bRunning = false;
bool g_bThreadStarted = false;
bool g_bActivated = false;     // Server handshake completed
char g_szGameDir[MAX_PATH] = {0};
char g_szValveDir[MAX_PATH] = {0};
char g_szChallenge[64] = {0};  // #2 Server challenge token
char g_szSessionKey[33] = {0}; // #2 Dynamic session key
char g_szDLLHash[33] = {0};    // #3 Anti-tamper DLL hash
int g_iSusCount = 0;
int g_iRegistrySus = 0;        // #15 Registry suspicious count
bool g_bPassed = true;
char g_szHWID[64] = {0};

// #6 #7 File cache with timestamps
struct CachedFile { std::string shortHash, fullHash; DWORD modTime; };
std::map<std::string, CachedFile> g_FileCache;

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

// ============================================
// UTILITIES
// ============================================
void ToLower(char* str) {
    for (int i = 0; str[i]; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') str[i] += 32;
    }
}

void GetFileHash(const char* filepath, char* shortHash, char* fullHash) {
    shortHash[0] = 0;
    fullHash[0] = 0;
    
    // #8 Async-like performance with larger buffer and sequential scan flag
    HANDLE h = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    
    MD5 md5;
    unsigned char buf[32768];  // #8 Larger buffer for better I/O
    DWORD rd;
    while (ReadFile(h, buf, sizeof(buf), &rd, NULL) && rd > 0) {
        md5.Update(buf, rd);
    }
    CloseHandle(h);
    
    std::string hash = md5.GetHashString();
    strncpy(fullHash, hash.c_str(), 32);
    fullHash[32] = 0;
    strncpy(shortHash, hash.c_str(), AGTR_HASH_LENGTH);
    shortHash[AGTR_HASH_LENGTH] = 0;
}

void GenHWID() {
    int cpu[4] = {0};
    __cpuid(cpu, 0);
    DWORD vol = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &vol, NULL, NULL, NULL, 0);
    char pc[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD sz = sizeof(pc);
    GetComputerNameA(pc, &sz);
    sprintf(g_szHWID, "%08X%08X%08X", cpu[0] ^ cpu[1], vol, (pc[0] << 24) | (pc[1] << 16) | (pc[2] << 8) | pc[3]);
    Log("HWID: %s", g_szHWID);
}

// #2 Generate dynamic session key: MD5(MasterKey + HWID + Challenge)
void GenerateSessionKey() {
    char masterKey[32]; Deobf(OBF_MKEY, OBF_MKEY_LEN, masterKey);
    MD5 md5;
    md5.Update((unsigned char*)masterKey, strlen(masterKey));
    md5.Update((unsigned char*)g_szHWID, strlen(g_szHWID));
    md5.Update((unsigned char*)g_szChallenge, strlen(g_szChallenge));
    std::string key = md5.GetHashString();
    strncpy(g_szSessionKey, key.c_str(), 32); g_szSessionKey[32] = 0;
    Log("Session key generated");
}

// #5 HMAC for integrity verification
std::string ComputeHMAC(const std::string& data) {
    MD5 inner, outer;
    inner.Update((unsigned char*)g_szSessionKey, 32);
    inner.Update((unsigned char*)data.c_str(), data.length());
    std::string h1 = inner.GetHashString();
    outer.Update((unsigned char*)g_szSessionKey, 32);
    outer.Update((unsigned char*)h1.c_str(), h1.length());
    return outer.GetHashString().substr(0, 16);
}

// #3 Anti-tamper: compute own DLL hash
void ComputeDLLHash() {
    char path[MAX_PATH];
    sprintf(path, "%s\\dinput.dll", g_szGameDir);
    char shortH[16];
    GetFileHash(path, shortH, g_szDLLHash);
    Log("DLL Hash: %s", g_szDLLHash);
}

// #15 Registry scan for cheat tools
int ScanRegistry() {
    int sus = 0;
    for (int i = 0; g_SusReg[i]; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            Log("SUS REG: HKCU\\%s", g_SusReg[i]); RegCloseKey(hKey); sus++;
        }
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            Log("SUS REG: HKLM\\%s", g_SusReg[i]); RegCloseKey(hKey); sus++;
        }
    }
    g_iRegistrySus = sus;
    return sus;
}

// ============================================
// SCANNING
// ============================================
int ScanProc() {
    int sus = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            char name[MAX_PATH];
            strcpy(name, pe.szExeFile);
            ToLower(name);
            for (int i = 0; g_SusProc[i]; i++) {
                if (strcmp(name, g_SusProc[i]) == 0) {
                    Log("SUS PROC: %s", pe.szExeFile);
                    sus++;
                    break;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return sus;
}

static int g_WinSus = 0;
BOOL CALLBACK EnumWinProc(HWND hwnd, LPARAM) {
    char title[256] = {0};
    GetWindowTextA(hwnd, title, 256);
    if (strlen(title) > 0) {
        ToLower(title);
        for (int i = 0; g_SusWin[i]; i++) {
            if (strstr(title, g_SusWin[i])) {
                g_WinSus++;
                break;
            }
        }
    }
    return TRUE;
}

int ScanWin() {
    g_WinSus = 0;
    EnumWindows(EnumWinProc, 0);
    return g_WinSus;
}

// #6 #7 Incremental scan with cache
void ScanDir(const char* dir, const char* pattern) {
    char searchPath[MAX_PATH];
    sprintf(searchPath, "%s\\%s", dir, pattern);
    
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(searchPath, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char filepath[MAX_PATH], filename[MAX_PATH];
            sprintf(filepath, "%s\\%s", dir, fd.cFileName);
            strcpy(filename, fd.cFileName);
            ToLower(filename);
            
            DWORD modTime = fd.ftLastWriteTime.dwLowDateTime;
            
            // #7 Check cache - skip if unchanged
            auto it = g_FileCache.find(filename);
            if (it != g_FileCache.end() && it->second.modTime == modTime) continue;
            
            // #6 Compute hash for new/modified files
            char shortHash[16], fullHash[64];
            GetFileHash(filepath, shortHash, fullHash);
            
            if (shortHash[0]) {
                CachedFile cf;
                cf.shortHash = shortHash;
                cf.fullHash = fullHash;
                cf.modTime = modTime;
                g_FileCache[filename] = cf;
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void ScanAllFiles() {
    // #6 Incremental - don't clear cache
    
    char dir[MAX_PATH];
    
    // Half-Life root
    ScanDir(g_szGameDir, "*.dll");
    ScanDir(g_szGameDir, "*.exe");
    
    // valve
    ScanDir(g_szValveDir, "*.dll");
    sprintf(dir, "%s\\cl_dlls", g_szValveDir);
    ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\dlls", g_szValveDir);
    ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\addons", g_szValveDir);
    ScanDir(dir, "*.dll");
    
    // valve_hd
    sprintf(dir, "%s\\valve_hd", g_szGameDir);
    ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\valve_hd\\cl_dlls", g_szGameDir);
    ScanDir(dir, "*.dll");
    
    // ag
    sprintf(dir, "%s\\ag", g_szGameDir);
    ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag\\cl_dlls", g_szGameDir);
    ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag\\dlls", g_szGameDir);
    ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag\\addons", g_szGameDir);
    ScanDir(dir, "*.dll");
    
    // cstrike
    sprintf(dir, "%s\\cstrike", g_szGameDir);
    ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\cstrike\\cl_dlls", g_szGameDir);
    ScanDir(dir, "*.dll");
    
    Log("Total hashed: %d files", (int)g_FileCache.size());
}

int ScanFiles() {
    int sus = 0;
    for (auto& p : g_FileCache) {
        for (int i = 0; g_SusKey[i]; i++) {
            if (p.first.find(g_SusKey[i]) != std::string::npos) {
                Log("SUS FILE: %s", p.first.c_str());
                sus++;
                break;
            }
        }
    }
    return sus;
}

// ============================================
// OUTPUT FILES
// ============================================
void WriteResult() {
    char path[MAX_PATH];
    sprintf(path, "%s\\agtr_result.txt", g_szValveDir);
    FILE* f = fopen(path, "w");
    if (f) {
        fprintf(f, "HWID=%s\n", g_szHWID);
        fprintf(f, "PASSED=%d\n", g_bPassed ? 1 : 0);
        fprintf(f, "SUSPICIOUS=%d\n", g_iSusCount);
        fprintf(f, "REGISTRY=%d\n", g_iRegistrySus);
        fprintf(f, "DLL_HASH=%s\n", g_szDLLHash);
        fprintf(f, "VERSION=%s\n", AGTR_VERSION);
        fprintf(f, "ACTIVATED=%d\n", g_bActivated ? 1 : 0);
        fclose(f);
    }
}

void WriteHashes() {
    char path[MAX_PATH];
    sprintf(path, "%s\\agtr_hashes.txt", g_szValveDir);
    FILE* f = fopen(path, "w");
    if (f) {
        fprintf(f, "# AGTR v%s | HWID: %s\n", AGTR_VERSION, g_szHWID);
        for (auto& h : g_FileCache) {
            fprintf(f, "%s,%s,%s\n", h.second.shortHash.c_str(), h.second.fullHash.c_str(), h.first.c_str());
        }
        fclose(f);
    }
}

// #7 Cache save/load
void SaveCache() {
    char path[MAX_PATH];
    sprintf(path, "%s\\agtr_cache.dat", g_szValveDir);
    FILE* f = fopen(path, "wb");
    if (f) {
        for (auto& p : g_FileCache)
            fprintf(f, "%s|%s|%s|%u\n", p.first.c_str(), p.second.shortHash.c_str(), p.second.fullHash.c_str(), p.second.modTime);
        fclose(f);
    }
}

void LoadCache() {
    char path[MAX_PATH];
    sprintf(path, "%s\\agtr_cache.dat", g_szValveDir);
    FILE* f = fopen(path, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            char fn[256], sh[16], fh[64]; DWORD mod;
            if (sscanf(line, "%[^|]|%[^|]|%[^|]|%u", fn, sh, fh, &mod) == 4) {
                CachedFile cf; cf.shortHash = sh; cf.fullHash = fh; cf.modTime = mod;
                g_FileCache[fn] = cf;
            }
        }
        fclose(f);
        Log("Cache loaded: %d entries", (int)g_FileCache.size());
    }
}

void SetupAutoExec() {
    // valve/userconfig.cfg
    char path[MAX_PATH];
    sprintf(path, "%s\\userconfig.cfg", g_szValveDir);
    
    FILE* f = fopen(path, "r");
    std::string content;
    if (f) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), f)) content += buf;
        fclose(f);
    }
    
    if (content.find("agtr_send.cfg") == std::string::npos) {
        f = fopen(path, "a");
        if (f) {
            fprintf(f, "\nexec agtr_send.cfg\n");
            fclose(f);
            Log("Auto-exec added to valve/userconfig.cfg");
        }
    }
    
    // ag/userconfig.cfg
    sprintf(path, "%s\\ag\\userconfig.cfg", g_szGameDir);
    f = fopen(path, "r");
    content.clear();
    if (f) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), f)) content += buf;
        fclose(f);
    }
    
    if (content.find("agtr_send.cfg") == std::string::npos) {
        f = fopen(path, "a");
        if (f) {
            fprintf(f, "\nexec agtr_send.cfg\n");
            fclose(f);
            Log("Auto-exec added to ag/userconfig.cfg");
        }
    }
}

void WriteSendCfg() {
    char path[MAX_PATH];
    sprintf(path, "%s\\agtr_send.cfg", g_szValveDir);
    FILE* f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "// AGTR v%s\n\n", AGTR_VERSION);
    
    // If not activated yet, just send hello
    if (!g_bActivated) {
        fprintf(f, "agtr_hello %s %s\n", g_szHWID, AGTR_VERSION);
    } else {
        // Full response with challenge, HMAC
        // Status: HWID|passed|suscount|regsus|dllhash|version
        char statusData[512];
        sprintf(statusData, "%s|%d|%d|%d|%s|%s", g_szHWID, g_bPassed?1:0, g_iSusCount, g_iRegistrySus, g_szDLLHash, AGTR_VERSION);
        
        std::string encStatus = Encrypt(statusData);
        std::string hmacStatus = ComputeHMAC(statusData);
        
        // agtr_response HWID CHALLENGE ENCRYPTED HMAC
        fprintf(f, "agtr_response %s %s %s %s\n", g_szHWID, g_szChallenge, encStatus.c_str(), hmacStatus.c_str());
        fprintf(f, "wait;wait;wait;wait;wait;wait;wait;wait;wait;wait\n");
        
        // Hashes with HMAC
        int count = 0;
        for (auto& h : g_FileCache) {
            std::string hashData = h.second.shortHash + "|" + h.first;
            std::string encHash = Encrypt(hashData);
            std::string hmacHash = ComputeHMAC(hashData);
            fprintf(f, "agtr_hash %s %s\n", encHash.c_str(), hmacHash.c_str());
            count++;
            if (count % 5 == 0) fprintf(f, "wait;wait;wait;wait;wait;wait;wait;wait;wait;wait\n");
        }
        
        fprintf(f, "wait;wait;wait;wait;wait;wait;wait;wait;wait;wait\n");
        fprintf(f, "agtr_done %d\n", (int)g_FileCache.size());
    }
    fclose(f);
    
    // Copy to ag/
    sprintf(path, "%s\\ag\\agtr_send.cfg", g_szGameDir);
    FILE* f2 = fopen(path, "w");
    if (f2) {
        sprintf(path, "%s\\agtr_send.cfg", g_szValveDir);
        FILE* src = fopen(path, "r");
        if (src) { char buf[1024]; while(fgets(buf,sizeof(buf),src)) fputs(buf,f2); fclose(src); }
        fclose(f2);
    }
    
    Log("CFG written: %d hashes", (int)g_FileCache.size());
}

// ============================================
// MAIN SCAN
// ============================================
void DoScan() {
    if (!g_bActivated) return;  // Only scan when server activated
    
    Log("=== SCAN START (Challenge: %s) ===", g_szChallenge);
    
    GenerateSessionKey();
    ComputeDLLHash();
    
    g_iSusCount = 0;
    g_iSusCount += ScanProc();
    g_iSusCount += ScanWin();
    g_iSusCount += ScanRegistry();  // #15
    g_iSusCount += ScanFiles();
    
    g_bPassed = (g_iSusCount == 0);
    Log("Result: %s | Sus: %d | Reg: %d", g_bPassed ? "CLEAN" : "SUSPICIOUS", g_iSusCount, g_iRegistrySus);
    
    WriteResult();
    WriteHashes();
    WriteSendCfg();
    SaveCache();
}

// Challenge watcher - server'dan challenge bekle
DWORD WINAPI WatchThread(LPVOID) {
    char challengePath[MAX_PATH];
    sprintf(challengePath, "%s\\agtr_challenge.txt", g_szValveDir);
    
    Log("Watching for challenge...");
    
    while (g_bRunning) {
        FILE* f = fopen(challengePath, "r");
        if (f) {
            char token[64] = {0};
            if (fgets(token, sizeof(token), f)) {
                char* nl = strchr(token, '\n'); if (nl) *nl = 0;
                char* cr = strchr(token, '\r'); if (cr) *cr = 0;
                
                if (strlen(token) > 0 && strcmp(token, g_szChallenge) != 0) {
                    strncpy(g_szChallenge, token, 63); g_szChallenge[63] = 0;
                    g_bActivated = true;
                    Log("Challenge received: %s", g_szChallenge);
                    DoScan();
                }
            }
            fclose(f);
            DeleteFileA(challengePath);
        }
        Sleep(500);
    }
    return 0;
}

DWORD WINAPI ScanThread(LPVOID) {
    Sleep(AGTR_INITIAL_DELAY);
    
    Log("=== AGTR v%s Started ===", AGTR_VERSION);
    
    GenHWID();
    LoadCache();
    SetupAutoExec();
    ScanAllFiles();
    WriteHashes();
    WriteSendCfg();  // Initial hello
    SaveCache();
    
    Log("Hello sent, waiting for server challenge...");
    
    // Periodic rescan if activated
    while (g_bRunning) {
        if (g_bActivated) {
            DoScan();
        }
        for (int i = 0; i < AGTR_SCAN_INTERVAL / 100 && g_bRunning; i++) {
            Sleep(100);
        }
    }
    
    return 0;
}

void StartScanThread() {
    if (g_bThreadStarted) return;
    g_bThreadStarted = true;
    g_bRunning = true;
    g_hThread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
    g_hWatchThread = CreateThread(NULL, 0, WatchThread, NULL, 0, NULL);
}

void Init() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) *slash = 0;
    
    strcpy(g_szGameDir, path);
    sprintf(g_szValveDir, "%s\\valve", path);
}

void Shutdown() {
    g_bRunning = false;
    if (g_hThread) { WaitForSingleObject(g_hThread, 2000); CloseHandle(g_hThread); }
    if (g_hWatchThread) { WaitForSingleObject(g_hWatchThread, 2000); CloseHandle(g_hWatchThread); }
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        LoadOriginal();
        Init();
        StartScanThread();  // Hemen baslat
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Shutdown();
        if (g_hOriginal) {
            FreeLibrary(g_hOriginal);
            g_hOriginal = NULL;
        }
    }
    return TRUE;
}
