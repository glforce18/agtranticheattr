#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winhttp.h>
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
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winhttp.lib")

#define AGTR_VERSION "4.0"
#define AGTR_SCAN_INTERVAL 60000
#define AGTR_INITIAL_DELAY 5000
#define AGTR_DLL_CHECK_INTERVAL 5000
#define AGTR_ENCRYPTION_KEY "AGTR2025SecretKey!"
#define AGTR_HASH_LENGTH 8

// Discord Webhook URL
#define DISCORD_WEBHOOK_HOST L"discord.com"
#define DISCORD_WEBHOOK_PATH L"/api/webhooks/1456818284543348919/eRkNm3naWMqRZT1TmyyKQtA0IWp74NuVYuYNv4K1VEmiL8j6x10tnniYHid8ETIWaOUl"

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
// ENCRYPTION
// ============================================
std::string Encrypt(const std::string& data) {
    const char* key = AGTR_ENCRYPTION_KEY;
    int keyLen = strlen(key);
    std::string result;
    for (size_t i = 0; i < data.length(); i++) {
        unsigned char c = data[i] ^ key[i % keyLen];
        char hex[3]; sprintf(hex, "%02x", c);
        result += hex;
    }
    return result;
}

// ============================================
// DISCORD WEBHOOK
// ============================================
bool SendDiscordWebhook(const char* title, const char* description, int color, const char* fields = NULL) {
    HINTERNET hSession = WinHttpOpen(L"AGTR/4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, DISCORD_WEBHOOK_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", DISCORD_WEBHOOK_PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    
    // JSON body
    char json[4096];
    if (fields) {
        sprintf(json, "{\"embeds\":[{\"title\":\"%s\",\"description\":\"%s\",\"color\":%d,\"fields\":[%s],\"footer\":{\"text\":\"AGTR Anti-Cheat v%s\"}}]}", 
            title, description, color, fields, AGTR_VERSION);
    } else {
        sprintf(json, "{\"embeds\":[{\"title\":\"%s\",\"description\":\"%s\",\"color\":%d,\"footer\":{\"text\":\"AGTR Anti-Cheat v%s\"}}]}", 
            title, description, color, AGTR_VERSION);
    }
    
    BOOL result = WinHttpSendRequest(hRequest, L"Content-Type: application/json\r\n", -1, json, strlen(json), strlen(json), 0);
    if (result) WinHttpReceiveResponse(hRequest, NULL);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result == TRUE;
}

// Escape JSON special characters
std::string JsonEscape(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

// ============================================
// MEMORY SIGNATURES
// ============================================
struct MemSig { const char* name; const unsigned char* pattern; int length; const char* mask; };
unsigned char SIG_AIMBOT1[] = { 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x00, 0x8B, 0x01 };
unsigned char SIG_WALLHACK1[] = { 0xD9, 0x05, 0x00, 0x00, 0x00, 0x00, 0xD8, 0x1D, 0x00, 0x00, 0x00, 0x00, 0xDF, 0xE0 };
unsigned char SIG_SPEEDHACK1[] = { 0xF3, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x59, 0xC1 };
MemSig g_MemSigs[] = {
    { "Aimbot", SIG_AIMBOT1, 12, "xx????xx?xx" },
    { "Wallhack", SIG_WALLHACK1, 14, "xx????xx????xx" },
    { "Speedhack", SIG_SPEEDHACK1, 12, "xxxx????xxxx" },
    { NULL, NULL, 0, NULL }
};

// ============================================
// SUSPICIOUS LISTS
// ============================================
const char* g_SusProc[] = { "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe", "artmoney.exe", "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "processhacker.exe", "extreme injector.exe", "wemod.exe", "ida.exe", "ida64.exe", NULL };
const char* g_SusWin[] = { "cheat engine", "artmoney", "process hacker", "extreme injector", "[aimbot]", "[wallhack]", "[esp]", NULL };
const char* g_SusKey[] = { "aimbot", "wallhack", "speedhack", "norecoil", "triggerbot", "ssw", "plwh", "ogc", "opengl32.dll", NULL };

// ============================================
// GLOBALS
// ============================================
HANDLE g_hThread = NULL, g_hDllWatchThread = NULL, g_hCommandThread = NULL;
bool g_bRunning = false;
std::string g_szGameDir, g_szValveDir;
std::string g_szPlayerName = "Unknown";
std::string g_szServerIP = "Unknown";
int g_iSusCount = 0;
bool g_bPassed = true, g_bDebugger = false;
char g_szHWID[64] = {0};
struct HashInfo { std::string shortHash, fullHash; };
std::map<std::string, HashInfo> g_Hashes;
std::set<std::string> g_LoadedDLLs;
int g_iMemorySus = 0, g_iInjectionCount = 0;
bool g_bScreenshotRequested = false;

void Log(const char* fmt, ...) {
    char path[MAX_PATH]; strcpy(path, g_szGameDir.c_str()); strcat(path, "\\agtr_anticheat.log");
    FILE* f = fopen(path, "a");
    if (f) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        va_list args; va_start(args, fmt); vfprintf(f, fmt, args); va_end(args);
        fprintf(f, "\n"); fclose(f);
    }
}

std::string ToLower(const std::string& s) { std::string r = s; std::transform(r.begin(), r.end(), r.begin(), ::tolower); return r; }
std::string ToUpper(const std::string& s) { std::string r = s; std::transform(r.begin(), r.end(), r.begin(), ::toupper); return r; }

bool GetFileHashes(const std::string& path, std::string& shortHash, std::string& fullHash) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    MD5 md5; unsigned char buf[8192]; DWORD rd;
    while (ReadFile(h, buf, sizeof(buf), &rd, NULL) && rd > 0) md5.Update(buf, rd);
    CloseHandle(h);
    fullHash = md5.GetHashString();
    shortHash = fullHash.substr(0, AGTR_HASH_LENGTH);
    return true;
}

void GenHWID() {
    int cpu[4] = {0}; __cpuid(cpu, 0);
    DWORD vol = 0; GetVolumeInformationA("C:\\", NULL, 0, &vol, NULL, NULL, NULL, 0);
    char pc[MAX_COMPUTERNAME_LENGTH + 1] = {0}; DWORD sz = sizeof(pc); GetComputerNameA(pc, &sz);
    sprintf(g_szHWID, "%08X%08X%08X", cpu[0] ^ cpu[1], vol, (pc[0] << 24) | (pc[1] << 16) | (pc[2] << 8) | pc[3]);
    Log("HWID: %s", g_szHWID);
}

bool CheckDebug() { if (IsDebuggerPresent()) return true; BOOL d = FALSE; CheckRemoteDebuggerPresent(GetCurrentProcess(), &d); return d == TRUE; }

// ============================================
// SCREENSHOT & DISCORD UPLOAD
// ============================================
std::string TakeScreenshotAndGetPath() {
    HWND hwnd = FindWindowA("Valve001", NULL);  // Half-Life window
    if (!hwnd) hwnd = GetForegroundWindow();
    if (!hwnd) hwnd = GetDesktopWindow();
    
    HDC hdcScreen = GetDC(hwnd);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    RECT rc; GetClientRect(hwnd, &rc);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    if (width <= 0 || height <= 0) {
        width = GetSystemMetrics(SM_CXSCREEN);
        height = GetSystemMetrics(SM_CYSCREEN);
        ReleaseDC(hwnd, hdcScreen);
        hdcScreen = GetDC(NULL);
    }
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    HBITMAP hOld = (HBITMAP)SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);
    SelectObject(hdcMem, hOld);
    
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(BITMAPINFOHEADER); bi.biWidth = width; bi.biHeight = height;
    bi.biPlanes = 1; bi.biBitCount = 24; bi.biCompression = BI_RGB;
    
    int rowSize = ((width * 3 + 3) & ~3);
    int dataSize = rowSize * height;
    unsigned char* pixels = new unsigned char[dataSize];
    GetDIBits(hdcMem, hBitmap, 0, height, pixels, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    SYSTEMTIME st; GetLocalTime(&st);
    char filename[MAX_PATH];
    sprintf(filename, "%s\\agtr_ss_%04d%02d%02d_%02d%02d%02d.bmp", 
        g_szGameDir.c_str(), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    FILE* f = fopen(filename, "wb");
    if (f) {
        BITMAPFILEHEADER bf = {0};
        bf.bfType = 0x4D42; bf.bfSize = sizeof(bf) + sizeof(bi) + dataSize;
        bf.bfOffBits = sizeof(bf) + sizeof(bi);
        fwrite(&bf, sizeof(bf), 1, f);
        fwrite(&bi, sizeof(bi), 1, f);
        fwrite(pixels, dataSize, 1, f);
        fclose(f);
    }
    
    delete[] pixels;
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(hwnd, hdcScreen);
    
    return std::string(filename);
}

// Upload screenshot to Discord via multipart form
bool UploadScreenshotToDiscord(const std::string& filepath, const char* reason) {
    FILE* f = fopen(filepath.c_str(), "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    // Max 8MB for Discord
    if (fileSize > 8 * 1024 * 1024) {
        fclose(f);
        return false;
    }
    
    unsigned char* fileData = new unsigned char[fileSize];
    fread(fileData, 1, fileSize, f);
    fclose(f);
    
    // Multipart form data
    std::string boundary = "----AGTRBoundary" + std::to_string(GetTickCount());
    std::string body;
    
    // JSON payload
    char jsonPart[1024];
    sprintf(jsonPart, "--%s\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n"
        "{\"embeds\":[{\"title\":\"Screenshot Request\",\"description\":\"%s\",\"color\":3447003,"
        "\"fields\":[{\"name\":\"Player\",\"value\":\"%s\",\"inline\":true},{\"name\":\"HWID\",\"value\":\"%s\",\"inline\":true}],"
        "\"image\":{\"url\":\"attachment://screenshot.bmp\"},\"footer\":{\"text\":\"AGTR Anti-Cheat v%s\"}}]}\r\n",
        boundary.c_str(), reason, JsonEscape(g_szPlayerName).c_str(), g_szHWID, AGTR_VERSION);
    body += jsonPart;
    
    // File part
    char filePart[256];
    sprintf(filePart, "--%s\r\nContent-Disposition: form-data; name=\"files[0]\"; filename=\"screenshot.bmp\"\r\nContent-Type: image/bmp\r\n\r\n", boundary.c_str());
    body += filePart;
    body.append((char*)fileData, fileSize);
    body += "\r\n--" + boundary + "--\r\n";
    
    delete[] fileData;
    
    // Send
    HINTERNET hSession = WinHttpOpen(L"AGTR/4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, DISCORD_WEBHOOK_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", DISCORD_WEBHOOK_PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    
    wchar_t headers[256];
    swprintf(headers, 256, L"Content-Type: multipart/form-data; boundary=%hs\r\n", boundary.c_str());
    
    BOOL result = WinHttpSendRequest(hRequest, headers, -1, (LPVOID)body.c_str(), body.size(), body.size(), 0);
    if (result) WinHttpReceiveResponse(hRequest, NULL);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    Log("Screenshot uploaded to Discord: %s", result ? "OK" : "FAIL");
    return result == TRUE;
}

// ============================================
// MEMORY SCANNING
// ============================================
bool PatternMatch(const unsigned char* data, const unsigned char* pattern, const char* mask, int len) {
    for (int i = 0; i < len; i++) if (mask[i] == 'x' && data[i] != pattern[i]) return false;
    return true;
}

int ScanMemory() {
    int found = 0;
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[256]; DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        int modCount = cbNeeded / sizeof(HMODULE);
        for (int i = 0; i < modCount && i < 256; i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                unsigned char* base = (unsigned char*)modInfo.lpBaseOfDll;
                DWORD size = modInfo.SizeOfImage;
                for (int s = 0; g_MemSigs[s].name != NULL; s++) {
                    for (DWORD offset = 0; offset < size - g_MemSigs[s].length; offset++) {
                        __try {
                            if (PatternMatch(base + offset, g_MemSigs[s].pattern, g_MemSigs[s].mask, g_MemSigs[s].length)) {
                                Log("!!! MEMORY: %s", g_MemSigs[s].name);
                                found++;
                            }
                        } __except(EXCEPTION_EXECUTE_HANDLER) {}
                    }
                }
            }
        }
    }
    g_iMemorySus = found;
    return found;
}

// ============================================
// DLL INJECTION DETECTION
// ============================================
std::set<std::string> GetCurrentModules() {
    std::set<std::string> modules;
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[512]; DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        int count = cbNeeded / sizeof(HMODULE);
        for (int i = 0; i < count && i < 512; i++) {
            char modName[MAX_PATH];
            if (GetModuleFileNameA(hMods[i], modName, MAX_PATH)) modules.insert(ToLower(modName));
        }
    }
    return modules;
}

int CheckNewDLLs() {
    int newCount = 0;
    std::set<std::string> current = GetCurrentModules();
    for (const auto& mod : current) {
        if (g_LoadedDLLs.find(mod) == g_LoadedDLLs.end()) {
            std::string fn = mod;
            size_t pos = fn.rfind('\\');
            if (pos != std::string::npos) fn = fn.substr(pos + 1);
            if (mod.find("windows") != std::string::npos || mod.find("system32") != std::string::npos) {
                g_LoadedDLLs.insert(mod);
                continue;
            }
            Log("!!! INJECTION: %s", mod.c_str());
            
            // Discord bildirim
            char fields[512];
            sprintf(fields, "{\"name\":\"DLL\",\"value\":\"%s\",\"inline\":false},{\"name\":\"HWID\",\"value\":\"%s\",\"inline\":true}", 
                JsonEscape(fn).c_str(), g_szHWID);
            SendDiscordWebhook("DLL Injection Detected", JsonEscape(g_szPlayerName).c_str(), 15158332, fields);
            
            g_LoadedDLLs.insert(mod);
            newCount++;
            g_iInjectionCount++;
        }
    }
    return newCount;
}

DWORD WINAPI DllWatchThread(LPVOID) {
    g_LoadedDLLs = GetCurrentModules();
    while (g_bRunning) { Sleep(AGTR_DLL_CHECK_INTERVAL); CheckNewDLLs(); }
    return 0;
}

// ============================================
// COMMAND LISTENER (for screenshot request)
// ============================================
DWORD WINAPI CommandThread(LPVOID) {
    while (g_bRunning) {
        // Check for screenshot request file
        std::string cmdFile = g_szGameDir + "\\agtr_command.txt";
        FILE* f = fopen(cmdFile.c_str(), "r");
        if (f) {
            char cmd[256] = {0};
            fgets(cmd, sizeof(cmd), f);
            fclose(f);
            DeleteFileA(cmdFile.c_str());
            
            if (strstr(cmd, "screenshot")) {
                Log("Screenshot requested by admin");
                std::string ssPath = TakeScreenshotAndGetPath();
                if (!ssPath.empty()) {
                    UploadScreenshotToDiscord(ssPath, "Admin Request");
                }
            }
        }
        Sleep(1000);
    }
    return 0;
}

// ============================================
// NORMAL SCANNING
// ============================================
int ScanProc() {
    int sus = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            std::string n = ToLower(pe.szExeFile);
            for (int i = 0; g_SusProc[i]; i++) {
                if (n == g_SusProc[i]) { Log("SUS PROC: %s", pe.szExeFile); sus++; break; }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return sus;
}

static int g_WinSus = 0;
BOOL CALLBACK EnumWinProc(HWND hwnd, LPARAM) {
    char t[256] = {0}; GetWindowTextA(hwnd, t, 256);
    if (strlen(t) > 0) {
        std::string tl = ToLower(t);
        for (int i = 0; g_SusWin[i]; i++) {
            if (tl.find(g_SusWin[i]) != std::string::npos) { Log("SUS WIN: %s", t); g_WinSus++; break; }
        }
    }
    return TRUE;
}
int ScanWin() { g_WinSus = 0; EnumWindows(EnumWinProc, 0); return g_WinSus; }

void ScanDir(const std::string& dir, const std::string& pat) {
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((dir + "\\" + pat).c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string fp = dir + "\\" + fd.cFileName;
            std::string shortHash, fullHash;
            if (GetFileHashes(fp, shortHash, fullHash)) {
                g_Hashes[ToLower(fd.cFileName)] = {shortHash, fullHash};
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void ScanAllFiles() {
    g_Hashes.clear();
    ScanDir(g_szGameDir, "*.dll"); ScanDir(g_szGameDir, "*.exe");
    ScanDir(g_szValveDir, "*.dll"); ScanDir(g_szValveDir + "\\cl_dlls", "*.dll");
    ScanDir(g_szValveDir + "\\dlls", "*.dll"); ScanDir(g_szValveDir + "\\addons", "*.dll");
    ScanDir(g_szGameDir + "\\valve_hd", "*.dll"); ScanDir(g_szGameDir + "\\valve_hd\\cl_dlls", "*.dll");
    ScanDir(g_szGameDir + "\\ag", "*.dll"); ScanDir(g_szGameDir + "\\ag\\cl_dlls", "*.dll");
    ScanDir(g_szGameDir + "\\ag\\dlls", "*.dll"); ScanDir(g_szGameDir + "\\ag\\addons", "*.dll");
    ScanDir(g_szGameDir + "\\cstrike", "*.dll"); ScanDir(g_szGameDir + "\\cstrike\\cl_dlls", "*.dll");
    Log("Total hashed: %d files", (int)g_Hashes.size());
}

int ScanFiles() {
    int sus = 0;
    for (auto& p : g_Hashes) {
        for (int i = 0; g_SusKey[i]; i++) {
            if (p.first.find(g_SusKey[i]) != std::string::npos) { Log("SUS FILE: %s", p.first.c_str()); sus++; break; }
        }
    }
    return sus;
}

void WriteResult() {
    char p[MAX_PATH]; strcpy(p, g_szGameDir.c_str()); strcat(p, "\\agtr_result.txt");
    FILE* f = fopen(p, "w");
    if (f) {
        fprintf(f, "HWID=%s\nPASSED=%d\nSUSPICIOUS=%d\nMEMORY=%d\nINJECTIONS=%d\nVERSION=%s\n",
            g_szHWID, g_bPassed ? 1 : 0, g_iSusCount, g_iMemorySus, g_iInjectionCount, AGTR_VERSION);
        fclose(f);
    }
}

void WriteHashes() {
    char p[MAX_PATH]; strcpy(p, g_szGameDir.c_str()); strcat(p, "\\agtr_hashes.txt");
    FILE* f = fopen(p, "w");
    if (f) {
        fprintf(f, "# AGTR v%s | HWID: %s\n", AGTR_VERSION, g_szHWID);
        for (auto& h : g_Hashes) fprintf(f, "%s,%s,%s\n", h.second.shortHash.c_str(), h.second.fullHash.c_str(), h.first.c_str());
        fclose(f);
    }
}

void SetupAutoExec() {
    std::string ucPath = g_szValveDir + "\\userconfig.cfg";
    FILE* f = fopen(ucPath.c_str(), "r");
    std::string content;
    if (f) { char buf[1024]; while (fgets(buf, sizeof(buf), f)) content += buf; fclose(f); }
    if (content.find("agtr_send.cfg") != std::string::npos) return;
    f = fopen(ucPath.c_str(), "a");
    if (f) { fprintf(f, "\nexec agtr_send.cfg\n"); fclose(f); Log("Auto-exec configured"); }
    
    std::string agPath = g_szGameDir + "\\ag\\userconfig.cfg";
    f = fopen(agPath.c_str(), "r"); content.clear();
    if (f) { char buf[1024]; while (fgets(buf, sizeof(buf), f)) content += buf; fclose(f); }
    if (content.find("agtr_send.cfg") == std::string::npos) {
        f = fopen(agPath.c_str(), "a");
        if (f) { fprintf(f, "\nexec agtr_send.cfg\n"); fclose(f); }
    }
}

// ============================================
// OPTIMIZED SEND CFG - Overflow Prevention
// ============================================
void WriteSendCfg() {
    char p[MAX_PATH]; strcpy(p, g_szGameDir.c_str()); strcat(p, "\\agtr_send.cfg");
    FILE* f = fopen(p, "w");
    if (!f) return;
    
    fprintf(f, "// AGTR v%s\n\n", AGTR_VERSION);
    
    // Status (encrypted)
    char statusData[256];
    sprintf(statusData, "%s|%d|%d|%d|%d|%s", g_szHWID, g_bPassed ? 1 : 0, g_iSusCount, g_iMemorySus, g_iInjectionCount, AGTR_VERSION);
    fprintf(f, "agtr_enc_status %s\n", Encrypt(statusData).c_str());
    fprintf(f, "wait;wait;wait;wait;wait;wait;wait;wait;wait;wait\n");  // 10 wait
    
    // Hash'leri grupla - her 5 hash'te bir wait
    int count = 0;
    for (auto& h : g_Hashes) {
        std::string hashData = h.second.shortHash + "|" + h.first;
        fprintf(f, "agtr_enc_hash %s\n", Encrypt(hashData).c_str());
        count++;
        if (count % 5 == 0) {
            fprintf(f, "wait;wait;wait;wait;wait;wait;wait;wait;wait;wait\n");
        }
    }
    
    fprintf(f, "wait;wait;wait;wait;wait;wait;wait;wait;wait;wait\n");
    fprintf(f, "agtr_enc_done %s\n", Encrypt(std::to_string(g_Hashes.size())).c_str());
    
    fclose(f);
    Log("CFG written: %d hashes", (int)g_Hashes.size());
}

void DoScan() {
    Log("=== SCAN ===");
    g_iSusCount = 0;
    g_bDebugger = CheckDebug();
    if (g_bDebugger) { g_iSusCount += 10; Log("!!! DEBUGGER"); }
    g_iSusCount += ScanProc();
    g_iSusCount += ScanWin();
    g_iSusCount += ScanFiles();
    
    static int memCounter = 0;
    if (memCounter++ % 5 == 0) {
        int hits = ScanMemory();
        if (hits > 0) g_iSusCount += hits * 5;
    }
    if (g_iInjectionCount > 0) g_iSusCount += g_iInjectionCount * 3;
    
    g_bPassed = (g_iSusCount == 0);
    Log("Result: %s | Sus: %d", g_bPassed ? "CLEAN" : "SUS", g_iSusCount);
    WriteResult();
    WriteSendCfg();
}

DWORD WINAPI ScanThread(LPVOID) {
    Sleep(AGTR_INITIAL_DELAY);
    Log("AGTR v%s Started", AGTR_VERSION);
    
    // Startup notification
    char fields[256];
    sprintf(fields, "{\"name\":\"HWID\",\"value\":\"%s\",\"inline\":true},{\"name\":\"Version\",\"value\":\"%s\",\"inline\":true}", g_szHWID, AGTR_VERSION);
    SendDiscordWebhook("Client Started", "AGTR Anti-Cheat initialized", 3066993, fields);
    
    GenHWID();
    SetupAutoExec();
    ScanAllFiles();
    WriteHashes();
    WriteSendCfg();
    
    while (g_bRunning) {
        DoScan();
        for (int i = 0; i < AGTR_SCAN_INTERVAL / 100 && g_bRunning; i++) Sleep(100);
    }
    return 0;
}

void Init() {
    char p[MAX_PATH]; GetModuleFileNameA(NULL, p, MAX_PATH);
    char* s = strrchr(p, '\\'); if (s) *s = 0;
    g_szGameDir = p; g_szValveDir = g_szGameDir + "\\valve";
    Log("=== AGTR v%s Init ===", AGTR_VERSION);
    g_bRunning = true;
    g_hThread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
    g_hDllWatchThread = CreateThread(NULL, 0, DllWatchThread, NULL, 0, NULL);
    g_hCommandThread = CreateThread(NULL, 0, CommandThread, NULL, 0, NULL);
}

void Shutdown() {
    g_bRunning = false;
    if (g_hThread) { WaitForSingleObject(g_hThread, 3000); CloseHandle(g_hThread); }
    if (g_hDllWatchThread) { WaitForSingleObject(g_hDllWatchThread, 3000); CloseHandle(g_hDllWatchThread); }
    if (g_hCommandThread) { WaitForSingleObject(g_hCommandThread, 3000); CloseHandle(g_hCommandThread); }
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(hMod); LoadOriginal(); Init(); }
    else if (reason == DLL_PROCESS_DETACH) { Shutdown(); if (g_hOriginal) FreeLibrary(g_hOriginal); }
    return TRUE;
}
