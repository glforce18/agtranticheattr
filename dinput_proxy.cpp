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

#define AGTR_VERSION "10.1"
#define AGTR_HASH_LENGTH 8
#define AGTR_SCAN_INTERVAL 120000   // 2 dakika
#define AGTR_INITIAL_DELAY 10000    // 10 saniye

// ============================================
// API CONFIGURATION
// ============================================
#define API_HOST L"185.171.25.137"
#define API_PORT 5000
#define API_PATH L"/api/v1/scan"
#define API_USE_HTTPS false

// ============================================
// OBFUSCATED KEY
// ============================================
#define OBF_XOR 0x5A
static const unsigned char OBF_KEY[] = {0x1B,0x3D,0x2E,0x28,0x6F,0x6A,0x6F,0x75,0x29,0x3F,0x39,0x28,0x3F,0x2E};
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
        for(int i=0;i<16;i++) sprintf(h+i*2,"%02x",d[i]); 
        return std::string(h); 
    }
private:
    unsigned int state[4], count[2]; unsigned char buffer[64];
    void Transform(unsigned int state[4], const unsigned char block[64]) {
        unsigned int a=state[0],b=state[1],c=state[2],d=state[3],x[16];
        Decode(x,block,64);
        #define S(x,n) (((x)<<(n))|((x)>>(32-(n))))
        #define F(x,y,z) (((x)&(y))|((~x)&(z)))
        #define G(x,y,z) (((x)&(z))|((y)&(~z)))
        #define H(x,y,z) ((x)^(y)^(z))
        #define I(x,y,z) ((y)^((x)|(~z)))
        #define FF(a,b,c,d,x,s,ac) {(a)+=F((b),(c),(d))+(x)+(ac);(a)=S((a),(s));(a)+=(b);}
        #define GG(a,b,c,d,x,s,ac) {(a)+=G((b),(c),(d))+(x)+(ac);(a)=S((a),(s));(a)+=(b);}
        #define HH(a,b,c,d,x,s,ac) {(a)+=H((b),(c),(d))+(x)+(ac);(a)=S((a),(s));(a)+=(b);}
        #define II(a,b,c,d,x,s,ac) {(a)+=I((b),(c),(d))+(x)+(ac);(a)=S((a),(s));(a)+=(b);}
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
        state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    }
    void Encode(unsigned char* out, const unsigned int* in, unsigned int len) { for(unsigned int i=0,j=0;j<len;i++,j+=4){out[j]=in[i]&0xff;out[j+1]=(in[i]>>8)&0xff;out[j+2]=(in[i]>>16)&0xff;out[j+3]=(in[i]>>24)&0xff;} }
    void Decode(unsigned int* out, const unsigned char* in, unsigned int len) { for(unsigned int i=0,j=0;j<len;i++,j+=4) out[i]=in[j]|(in[j+1]<<8)|(in[j+2]<<16)|(in[j+3]<<24); }
};

// ============================================
// GLOBALS
// ============================================
static HANDLE g_hThread = NULL;
static bool g_bRunning = true;
static bool g_bThreadStarted = false;

static char g_szHWID[64] = {0};
static char g_szDLLHash[64] = {0};
static char g_szGameDir[MAX_PATH] = {0};
static char g_szValveDir[MAX_PATH] = {0};
static char g_szServerIP[64] = "unknown";
static int g_iServerPort = 0;

static bool g_bPassed = true;
static int g_iSusCount = 0;
static int g_iRegistrySus = 0;

// Detaylı veri yapıları
struct ProcessInfo {
    std::string name;
    std::string path;
    DWORD pid;
    bool suspicious;
};
static std::vector<ProcessInfo> g_Processes;

struct ModuleInfo {
    std::string name;
    std::string path;
    std::string hash;
    DWORD size;
};
static std::vector<ModuleInfo> g_Modules;

struct WindowInfo {
    std::string title;
    std::string className;
    DWORD pid;
    bool suspicious;
};
static std::vector<WindowInfo> g_Windows;

struct FileHashInfo {
    std::string filename;
    std::string path;
    std::string shortHash;
    std::string fullHash;
    DWORD size;
    DWORD modTime;
};
static std::map<std::string, FileHashInfo> g_FileCache;

// ============================================
// SUSPICIOUS LISTS
// ============================================
const char* g_SusProc[] = { 
    "cheatengine", "artmoney", "ollydbg", "x64dbg", "x32dbg", 
    "processhacker", "wireshark", "fiddler", "ida.exe", "ida64.exe",
    "ghidra", "reclass", "themida", "ce.exe", "speedhack", 
    "gamehack", "trainer", "injector", "aimbot", "wallhack",
    NULL 
};

// Sistem process'leri - WHITELIST (bunlar şüpheli DEĞİL)
const char* g_WhitelistProc[] = {
    "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "explorer.exe", "dwm.exe", "taskhostw.exe",
    "searchindexer", "searchhost", "runtimebroker", "sihost.exe", "fontdrvhost",
    "ctfmon.exe", "conhost.exe", "dllhost.exe", "audiodg.exe", "spoolsv.exe",
    // Windows Defender & Security
    "msmpeng.exe", "mpcmdrun.exe", "mpdefendercoreservice", "securityhealthservice",
    "smartscreen.exe", "sgrmbroker.exe", "memfilesservice", "wscntfy.exe",
    // Common system services
    "lightingservice", "rogcoreservice", "rogliveservice", "mspcmanagerservice",
    "armsvc.exe", "igfxem.exe", "igfxhk.exe", "nvcontainer.exe", "nvdisplay",
    "amdrsserv", "radeonsoft", "gamingservices", "gamebar", "gamebarft",
    // Steam & Gaming platforms
    "steam.exe", "steamservice.exe", "steamwebhelper", "epicgameslauncher",
    "origin.exe", "eadesktop.exe", "discord.exe", "discordptb", "discordcanary",
    // Common apps
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    "spotify.exe", "teams.exe", "zoom.exe", "obs64.exe", "obs32.exe",
    NULL
};

const char* g_SusWin[] = { 
    "cheat engine", "artmoney", "speed hack", "game hack", 
    "[aimbot]", "[wallhack]", "[esp]", "trainer", "injector",
    "dll inject", "process hack", "memory edit",
    NULL 
};
const char* g_SusReg[] = { 
    "SOFTWARE\\Cheat Engine", 
    "SOFTWARE\\ArtMoney",
    "SOFTWARE\\Process Hacker",
    NULL 
};
const char* g_SusFile[] = { "aimbot", "wallhack", "cheat", "hack", "esp", "speedhack", "norecoil", NULL };

const char* g_SusDLLs[] = {
    "opengl32.dll",  // Custom opengl hook (system dışında)
    "d3d9.dll",      // DirectX hook
    "hook.dll", "inject.dll", "cheat.dll", "hack.dll",
    "aimbot.dll", "wallhack.dll", "esp.dll", "speedhack.dll",
    NULL
};

// ============================================
// LOGGING
// ============================================
static FILE* g_LogFile = NULL;
void Log(const char* fmt, ...) {
    if (!g_LogFile) {
        char path[MAX_PATH];
        sprintf(path, "%s\\agtr_client.log", g_szGameDir[0] ? g_szGameDir : ".");
        g_LogFile = fopen(path, "a");
    }
    if (g_LogFile) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(g_LogFile, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        va_list args; va_start(args, fmt);
        vfprintf(g_LogFile, fmt, args);
        va_end(args);
        fprintf(g_LogFile, "\n");
        fflush(g_LogFile);
    }
}

void ToLower(char* s) { for (; *s; s++) *s = tolower(*s); }

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

void GetFileHash(const char* filepath, char* shortHash, char* fullHash, DWORD* fileSize) {
    shortHash[0] = fullHash[0] = 0;
    *fileSize = 0;
    HANDLE h = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    
    *fileSize = GetFileSize(h, NULL);
    
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
    DWORD size;
    GetFileHash(path, shortH, g_szDLLHash, &size);
    Log("DLL Hash: %s", g_szDLLHash);
}

// ============================================
// PROCESS SCANNER - DETAYLI
// ============================================
bool IsWhitelistedProcess(const char* name) {
    char lower[MAX_PATH];
    strcpy(lower, name);
    ToLower(lower);
    for (int i = 0; g_WhitelistProc[i]; i++) {
        if (strstr(lower, g_WhitelistProc[i])) return true;
    }
    return false;
}

int ScanProcesses() {
    g_Processes.clear();
    int sus = 0;
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            ProcessInfo pi;
            pi.name = pe.szExeFile;
            pi.pid = pe.th32ProcessID;
            pi.suspicious = false;
            
            // Get full path
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                char path[MAX_PATH] = {0};
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameA(hProc, 0, path, &size)) {
                    pi.path = path;
                }
                CloseHandle(hProc);
            }
            
            // Whitelist kontrolü - sistem process'lerini atla
            if (!IsWhitelistedProcess(pe.szExeFile)) {
                // Check if suspicious
                char name[MAX_PATH]; strcpy(name, pe.szExeFile); ToLower(name);
                for (int i = 0; g_SusProc[i]; i++) {
                    if (strstr(name, g_SusProc[i])) {
                        pi.suspicious = true;
                        sus++;
                        Log("SUS PROC: %s (%s)", pe.szExeFile, pi.path.c_str());
                        break;
                    }
                }
            }
            
            g_Processes.push_back(pi);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return sus;
}

// ============================================
// MODULE SCANNER - HL.EXE'nin yüklenmiş DLL'leri
// ============================================
int ScanModules() {
    g_Modules.clear();
    int sus = 0;
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    ToLower(sysDir);
    
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            ModuleInfo mi;
            mi.name = me.szModule;
            mi.path = me.szExePath;
            mi.size = me.modBaseSize;
            
            // Hash hesapla
            char shortH[16], fullH[64];
            DWORD fsize;
            GetFileHash(me.szExePath, shortH, fullH, &fsize);
            mi.hash = shortH;
            
            // Suspicious check
            char modName[MAX_PATH]; strcpy(modName, me.szModule); ToLower(modName);
            char modPath[MAX_PATH]; strcpy(modPath, me.szExePath); ToLower(modPath);
            
            for (int i = 0; g_SusDLLs[i]; i++) {
                if (strstr(modName, g_SusDLLs[i])) {
                    // opengl32 ve d3d9 için system dizini kontrolü
                    if ((strcmp(g_SusDLLs[i], "opengl32.dll") == 0 || strcmp(g_SusDLLs[i], "d3d9.dll") == 0)) {
                        if (strstr(modPath, sysDir)) continue; // System DLL, OK
                    }
                    sus++;
                    Log("SUS MODULE: %s (%s)", me.szModule, me.szExePath);
                    break;
                }
            }
            
            g_Modules.push_back(mi);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    
    Log("Loaded modules: %d", (int)g_Modules.size());
    return sus;
}

// ============================================
// WINDOW SCANNER - DETAYLI
// ============================================
static int g_WinSus = 0;

BOOL CALLBACK EnumWinCB(HWND hwnd, LPARAM) {
    char title[256] = {0}; 
    char className[256] = {0};
    
    GetWindowTextA(hwnd, title, 256);
    GetClassNameA(hwnd, className, 256);
    
    if (title[0] || className[0]) {
        WindowInfo wi;
        wi.title = title;
        wi.className = className;
        
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        wi.pid = pid;
        wi.suspicious = false;
        
        if (title[0]) {
            char lowerTitle[256]; strcpy(lowerTitle, title); ToLower(lowerTitle);
            for (int i = 0; g_SusWin[i]; i++) {
                if (strstr(lowerTitle, g_SusWin[i])) {
                    wi.suspicious = true;
                    g_WinSus++;
                    Log("SUS WINDOW: %s (class: %s)", title, className);
                    break;
                }
            }
        }
        
        if (wi.title.length() > 0) {
            g_Windows.push_back(wi);
        }
    }
    return TRUE;
}

int ScanWindows() { 
    g_Windows.clear();
    g_WinSus = 0; 
    EnumWindows(EnumWinCB, 0); 
    Log("Windows found: %d", (int)g_Windows.size());
    return g_WinSus; 
}

// ============================================
// REGISTRY SCANNER
// ============================================
int ScanRegistry() {
    int sus = 0;
    for (int i = 0; g_SusReg[i]; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) { 
            Log("SUS REG: HKCU\\%s", g_SusReg[i]); 
            RegCloseKey(hKey); 
            sus++; 
        }
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, g_SusReg[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) { 
            Log("SUS REG: HKLM\\%s", g_SusReg[i]); 
            RegCloseKey(hKey); 
            sus++; 
        }
    }
    g_iRegistrySus = sus;
    return sus;
}

// ============================================
// FILE SCANNER - DETAYLI
// ============================================
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
        
        char shortH[16], fullH[64];
        DWORD fileSize;
        GetFileHash(filepath, shortH, fullH, &fileSize);
        
        if (shortH[0]) { 
            FileHashInfo fhi;
            fhi.filename = filename;
            fhi.path = filepath;
            fhi.shortHash = shortH;
            fhi.fullHash = fullH;
            fhi.size = fileSize;
            fhi.modTime = modTime;
            g_FileCache[filename] = fhi;
        }
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
    Log("Scanned %d files", (int)g_FileCache.size());
}

int CheckSusFiles() {
    int sus = 0;
    for (auto& p : g_FileCache) {
        for (int i = 0; g_SusFile[i]; i++) {
            if (p.first.find(g_SusFile[i]) != std::string::npos) { 
                Log("SUS FILE: %s", p.first.c_str()); 
                sus++; 
                break; 
            }
        }
    }
    return sus;
}

// ============================================
// JSON BUILDER - DETAYLI
// ============================================
std::string EscapeJson(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
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
    
    // Özet istatistikler
    json += "\"total_processes\":" + std::to_string(g_Processes.size()) + ",";
    json += "\"total_modules\":" + std::to_string(g_Modules.size()) + ",";
    json += "\"total_windows\":" + std::to_string(g_Windows.size()) + ",";
    
    // File hashes - DETAYLI (her zaman gönder - blacklist kontrolü için)
    json += "\"hashes\":[";
    bool first = true;
    for (auto& h : g_FileCache) {
        if (!first) json += ",";
        json += "{\"file\":\"" + EscapeJson(h.second.filename) + "\",";
        json += "\"path\":\"" + EscapeJson(h.second.path) + "\",";
        json += "\"hash\":\"" + h.second.shortHash + "\",";
        json += "\"size\":" + std::to_string(h.second.size) + "}";
        first = false;
    }
    json += "],";
    
    // Processes - SADECE ŞÜPHELİ OLANLAR + İLK 20 (özet için)
    json += "\"processes\":[";
    first = true;
    int procCount = 0;
    for (auto& p : g_Processes) {
        if (p.suspicious || procCount < 20) {
            if (!first) json += ",";
            json += "{\"name\":\"" + EscapeJson(p.name) + "\",";
            json += "\"path\":\"" + EscapeJson(p.path) + "\",";
            json += "\"pid\":" + std::to_string(p.pid) + ",";
            json += "\"suspicious\":" + std::string(p.suspicious ? "true" : "false") + "}";
            first = false;
            procCount++;
        }
    }
    json += "],";
    
    // Modules - SADECE OYUN KLASÖRÜNDEN OLANLAR (sistem DLL'leri hariç)
    json += "\"modules\":[";
    first = true;
    char gamePathLower[MAX_PATH];
    strcpy(gamePathLower, g_szGameDir);
    ToLower(gamePathLower);
    
    for (auto& m : g_Modules) {
        char modPathLower[MAX_PATH];
        strcpy(modPathLower, m.path.c_str());
        ToLower(modPathLower);
        
        // Sadece oyun klasöründeki DLL'leri gönder
        if (strstr(modPathLower, "half-life") || strstr(modPathLower, "steam") || 
            strstr(modPathLower, gamePathLower) || strstr(modPathLower, "\\valve\\") ||
            strstr(modPathLower, "\\ag\\") || strstr(modPathLower, "\\cstrike\\")) {
            if (!first) json += ",";
            json += "{\"name\":\"" + EscapeJson(m.name) + "\",";
            json += "\"path\":\"" + EscapeJson(m.path) + "\",";
            json += "\"hash\":\"" + m.hash + "\",";
            json += "\"size\":" + std::to_string(m.size) + "}";
            first = false;
        }
    }
    json += "],";
    
    // Windows - SADECE ŞÜPHELİ OLANLAR + HL/AG ile ilgili olanlar
    json += "\"windows\":[";
    first = true;
    int winCount = 0;
    for (auto& w : g_Windows) {
        if (w.title.empty()) continue;
        
        char titleLower[256];
        strncpy(titleLower, w.title.c_str(), 255);
        ToLower(titleLower);
        
        // Şüpheli veya oyunla ilgili pencereleri gönder
        bool isRelevant = w.suspicious || 
                          strstr(titleLower, "half-life") || strstr(titleLower, "counter") ||
                          strstr(titleLower, "agtr") || strstr(titleLower, " ag ") ||
                          strstr(titleLower, "steam");
        
        if (isRelevant || winCount < 10) {
            if (!first) json += ",";
            json += "{\"title\":\"" + EscapeJson(w.title) + "\",";
            json += "\"class\":\"" + EscapeJson(w.className) + "\",";
            json += "\"pid\":" + std::to_string(w.pid) + ",";
            json += "\"suspicious\":" + std::string(w.suspicious ? "true" : "false") + "}";
            first = false;
            winCount++;
        }
    }
    json += "]";
    
    json += "}";
    return json;
}

// ============================================
// SIGNATURE
// ============================================
std::string ComputeSignature(const std::string& data) {
    char key[32]; Deobf(OBF_KEY, OBF_KEY_LEN, key);
    MD5 md5;
    md5.Update((unsigned char*)key, strlen(key));
    md5.Update((unsigned char*)data.c_str(), data.length());
    return md5.GetHashString();
}

// ============================================
// HTTP POST
// ============================================
bool SendToAPI(const std::string& jsonData, const std::string& signature) {
    HINTERNET hSession = WinHttpOpen(L"AGTR/10.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) { Log("HTTP: Session failed"); return false; }
    
    HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
    if (!hConnect) { Log("HTTP: Connect failed"); WinHttpCloseHandle(hSession); return false; }
    
    DWORD flags = API_USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", API_PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { Log("HTTP: Request failed"); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    
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
// MAIN SCAN
// ============================================
void DoScan() {
    Log("=== Starting Scan ===");
    
    g_iSusCount = 0;
    g_iSusCount += ScanProcesses();
    g_iSusCount += ScanModules();
    g_iSusCount += ScanWindows();
    g_iSusCount += ScanRegistry();
    g_iSusCount += CheckSusFiles();
    
    g_bPassed = (g_iSusCount == 0);
    
    std::string json = BuildJson();
    std::string sig = ComputeSignature(json);
    
    Log("Scan: %s | Sus:%d | Proc:%d | Mod:%d | Win:%d | Files:%d | Size:%dKB", 
        g_bPassed ? "CLEAN" : "SUSPICIOUS", g_iSusCount,
        (int)g_Processes.size(), (int)g_Modules.size(), 
        (int)g_Windows.size(), (int)g_FileCache.size(),
        (int)(json.length() / 1024));
    
    SendToAPI(json, sig);
}

DWORD WINAPI ScanThread(LPVOID) {
    Sleep(AGTR_INITIAL_DELAY);
    
    Log("=== AGTR v%s Started ===", AGTR_VERSION);
    
    GenHWID();
    ComputeDLLHash();
    ScanAllFiles();
    DoScan();
    
    while (g_bRunning) {
        for (int i = 0; i < AGTR_SCAN_INTERVAL / 100 && g_bRunning; i++) {
            Sleep(100);
        }
        if (g_bRunning) {
            ScanAllFiles(); // Refresh file cache
            DoScan();
        }
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
    if (g_LogFile) { fclose(g_LogFile); g_LogFile = NULL; }
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        LoadOriginal();
        Init();
        StartScanThread();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Shutdown();
    }
    return TRUE;
}
