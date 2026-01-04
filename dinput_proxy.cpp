/*
 * AGTR Anti-Cheat v11.5 - winmm.dll Proxy
 * ========================================
 * Based on dinput.dll scanning system
 * 
 * Features:
 * - Process scanner (cheat engine, artmoney, etc.)
 * - Module/DLL scanner (injected DLLs)
 * - Window scanner (suspicious titles)
 * - File hash scanner (blacklist check)
 * - Registry scanner (cheat software)
 * 
 * BUILD: cl /O2 /MT /LD agtr_winmm.cpp /link /DEF:winmm.def /OUT:winmm.dll
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <mmsystem.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <map>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define AGTR_VERSION "11.5"
#define AGTR_HASH_LENGTH 8
#define AGTR_HEARTBEAT_INTERVAL 30000

// ============================================
// API CONFIGURATION
// ============================================
#define API_HOST L"185.171.25.137"
#define API_PORT 5000
#define API_PATH_SCAN L"/api/v1/scan"
#define API_PATH_REGISTER L"/api/v1/client/register"
#define API_PATH_HEARTBEAT L"/api/v1/client/heartbeat"
#define API_USE_HTTPS false

// ============================================
// DYNAMIC SETTINGS (API'den gelir)
// ============================================
struct ClientSettings {
    bool scan_enabled = true;
    int scan_interval = 120000;
    bool scan_only_in_server = true;
    bool scan_processes = true;
    bool scan_modules = true;
    bool scan_windows = true;
    bool scan_files = true;
    bool scan_registry = true;
    bool kick_on_detect = true;
    char message_on_kick[256] = "AGTR Anti-Cheat: Banned";
};
static ClientSettings g_Settings;

// ============================================
// GAME STATE
// ============================================
static bool g_bInServer = false;
static char g_szConnectedIP[64] = {0};
static int g_iConnectedPort = 0;
static DWORD g_dwLastHeartbeat = 0;
static DWORD g_dwLastScan = 0;
static bool g_bSettingsLoaded = false;

// ============================================
// OBFUSCATED KEY
// ============================================
#define OBF_XOR 0x5A
static const unsigned char OBF_KEY[] = {0x1B,0x3D,0x2E,0x28,0x6F,0x6A,0x6F,0x75,0x29,0x3F,0x39,0x28,0x3F,0x2E};
#define OBF_KEY_LEN 14
static void Deobf(const unsigned char* s, int len, char* d) { for(int i=0;i<len;i++) d[i]=s[i]^OBF_XOR; d[len]=0; }

// ============================================
// WINMM FORWARDING
// ============================================
static HMODULE g_hOriginal = NULL;

// Function pointer types
typedef DWORD (WINAPI *pfnTimeGetTime)(void);
typedef MMRESULT (WINAPI *pfnTimeBeginPeriod)(UINT);
typedef MMRESULT (WINAPI *pfnTimeEndPeriod)(UINT);
typedef MMRESULT (WINAPI *pfnTimeGetDevCaps)(LPTIMECAPS, UINT);
typedef MMRESULT (WINAPI *pfnTimeGetSystemTime)(LPMMTIME, UINT);
typedef MMRESULT (WINAPI *pfnTimeSetEvent)(UINT, UINT, LPTIMECALLBACK, DWORD_PTR, UINT);
typedef MMRESULT (WINAPI *pfnTimeKillEvent)(UINT);
typedef MMRESULT (WINAPI *pfnWaveOutOpen)(LPHWAVEOUT, UINT, LPCWAVEFORMATEX, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *pfnWaveOutClose)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveOutWrite)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutPrepareHeader)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutUnprepareHeader)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutReset)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveOutPause)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveOutRestart)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveOutGetPosition)(HWAVEOUT, LPMMTIME, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutGetDevCapsA)(UINT, LPWAVEOUTCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutGetDevCapsW)(UINT, LPWAVEOUTCAPSW, UINT);
typedef UINT (WINAPI *pfnWaveOutGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnWaveOutGetVolume)(HWAVEOUT, LPDWORD);
typedef MMRESULT (WINAPI *pfnWaveOutSetVolume)(HWAVEOUT, DWORD);
typedef MMRESULT (WINAPI *pfnWaveOutGetErrorTextA)(MMRESULT, LPSTR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutGetErrorTextW)(MMRESULT, LPWSTR, UINT);
typedef MMRESULT (WINAPI *pfnWaveOutGetID)(HWAVEOUT, LPUINT);
typedef MMRESULT (WINAPI *pfnWaveOutMessage)(HWAVEOUT, UINT, DWORD_PTR, DWORD_PTR);
typedef MMRESULT (WINAPI *pfnWaveOutBreakLoop)(HWAVEOUT);
typedef MMRESULT (WINAPI *pfnWaveInOpen)(LPHWAVEIN, UINT, LPCWAVEFORMATEX, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *pfnWaveInClose)(HWAVEIN);
typedef UINT (WINAPI *pfnWaveInGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnWaveInGetDevCapsA)(UINT, LPWAVEINCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnWaveInGetDevCapsW)(UINT, LPWAVEINCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnWaveInStart)(HWAVEIN);
typedef MMRESULT (WINAPI *pfnWaveInStop)(HWAVEIN);
typedef MMRESULT (WINAPI *pfnWaveInReset)(HWAVEIN);
typedef MMRESULT (WINAPI *pfnWaveInPrepareHeader)(HWAVEIN, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInUnprepareHeader)(HWAVEIN, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInAddBuffer)(HWAVEIN, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInGetPosition)(HWAVEIN, LPMMTIME, UINT);
typedef MMRESULT (WINAPI *pfnWaveInGetID)(HWAVEIN, LPUINT);
typedef MMRESULT (WINAPI *pfnWaveInGetErrorTextA)(MMRESULT, LPSTR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInGetErrorTextW)(MMRESULT, LPWSTR, UINT);
typedef MMRESULT (WINAPI *pfnWaveInMessage)(HWAVEIN, UINT, DWORD_PTR, DWORD_PTR);
typedef BOOL (WINAPI *pfnPlaySoundA)(LPCSTR, HMODULE, DWORD);
typedef BOOL (WINAPI *pfnPlaySoundW)(LPCWSTR, HMODULE, DWORD);
typedef BOOL (WINAPI *pfnSndPlaySoundA)(LPCSTR, UINT);
typedef BOOL (WINAPI *pfnSndPlaySoundW)(LPCWSTR, UINT);
typedef UINT (WINAPI *pfnMidiOutGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnMidiOutGetDevCapsA)(UINT, LPMIDIOUTCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnMidiOutGetDevCapsW)(UINT, LPMIDIOUTCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnMidiOutOpen)(LPHMIDIOUT, UINT, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *pfnMidiOutClose)(HMIDIOUT);
typedef MMRESULT (WINAPI *pfnMidiOutShortMsg)(HMIDIOUT, DWORD);
typedef MMRESULT (WINAPI *pfnMidiOutLongMsg)(HMIDIOUT, LPMIDIHDR, UINT);
typedef MMRESULT (WINAPI *pfnMidiOutReset)(HMIDIOUT);
typedef MMRESULT (WINAPI *pfnMidiOutPrepareHeader)(HMIDIOUT, LPMIDIHDR, UINT);
typedef MMRESULT (WINAPI *pfnMidiOutUnprepareHeader)(HMIDIOUT, LPMIDIHDR, UINT);
typedef UINT (WINAPI *pfnJoyGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnJoyGetDevCapsA)(UINT, LPJOYCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnJoyGetDevCapsW)(UINT, LPJOYCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnJoyGetPos)(UINT, LPJOYINFO);
typedef MMRESULT (WINAPI *pfnJoyGetPosEx)(UINT, LPJOYINFOEX);
typedef MMRESULT (WINAPI *pfnJoyGetThreshold)(UINT, LPUINT);
typedef MMRESULT (WINAPI *pfnJoySetThreshold)(UINT, UINT);
typedef MMRESULT (WINAPI *pfnJoySetCapture)(HWND, UINT, UINT, BOOL);
typedef MMRESULT (WINAPI *pfnJoyReleaseCapture)(UINT);
typedef UINT (WINAPI *pfnAuxGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnAuxGetDevCapsA)(UINT, LPAUXCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnAuxGetDevCapsW)(UINT, LPAUXCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnAuxGetVolume)(UINT, LPDWORD);
typedef MMRESULT (WINAPI *pfnAuxSetVolume)(UINT, DWORD);
typedef MMRESULT (WINAPI *pfnAuxOutMessage)(UINT, UINT, DWORD_PTR, DWORD_PTR);
typedef UINT (WINAPI *pfnMixerGetNumDevs)(void);
typedef MMRESULT (WINAPI *pfnMixerOpen)(LPHMIXER, UINT, DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *pfnMixerClose)(HMIXER);
typedef MMRESULT (WINAPI *pfnMixerGetDevCapsA)(UINT, LPMIXERCAPSA, UINT);
typedef MMRESULT (WINAPI *pfnMixerGetDevCapsW)(UINT, LPMIXERCAPSW, UINT);
typedef MMRESULT (WINAPI *pfnMixerGetLineInfoA)(HMIXEROBJ, LPMIXERLINEA, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetLineInfoW)(HMIXEROBJ, LPMIXERLINEW, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetLineControlsA)(HMIXEROBJ, LPMIXERLINECONTROLSA, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetLineControlsW)(HMIXEROBJ, LPMIXERLINECONTROLSW, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetControlDetailsA)(HMIXEROBJ, LPMIXERCONTROLDETAILS, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetControlDetailsW)(HMIXEROBJ, LPMIXERCONTROLDETAILS, DWORD);
typedef MMRESULT (WINAPI *pfnMixerSetControlDetails)(HMIXEROBJ, LPMIXERCONTROLDETAILS, DWORD);
typedef MMRESULT (WINAPI *pfnMixerGetID)(HMIXEROBJ, PUINT, DWORD);
typedef DWORD (WINAPI *pfnMixerMessage)(HMIXER, UINT, DWORD_PTR, DWORD_PTR);
typedef MCIERROR (WINAPI *pfnMciSendCommandA)(MCIDEVICEID, UINT, DWORD_PTR, DWORD_PTR);
typedef MCIERROR (WINAPI *pfnMciSendCommandW)(MCIDEVICEID, UINT, DWORD_PTR, DWORD_PTR);
typedef MCIERROR (WINAPI *pfnMciSendStringA)(LPCSTR, LPSTR, UINT, HWND);
typedef MCIERROR (WINAPI *pfnMciSendStringW)(LPCWSTR, LPWSTR, UINT, HWND);
typedef BOOL (WINAPI *pfnMciGetErrorStringA)(MCIERROR, LPSTR, UINT);
typedef BOOL (WINAPI *pfnMciGetErrorStringW)(MCIERROR, LPWSTR, UINT);
typedef MCIDEVICEID (WINAPI *pfnMciGetDeviceIDA)(LPCSTR);
typedef MCIDEVICEID (WINAPI *pfnMciGetDeviceIDW)(LPCWSTR);
typedef MCIDEVICEID (WINAPI *pfnMciGetDeviceIDFromElementIDA)(DWORD, LPCSTR);
typedef MCIDEVICEID (WINAPI *pfnMciGetDeviceIDFromElementIDW)(DWORD, LPCWSTR);
typedef BOOL (WINAPI *pfnMciSetYieldProc)(MCIDEVICEID, YIELDPROC, DWORD);
typedef YIELDPROC (WINAPI *pfnMciGetYieldProc)(MCIDEVICEID, LPDWORD);
typedef HTASK (WINAPI *pfnMciGetCreatorTask)(MCIDEVICEID);
typedef BOOL (WINAPI *pfnMciExecute)(LPCSTR);
typedef HMMIO (WINAPI *pfnMmioOpenA)(LPSTR, LPMMIOINFO, DWORD);
typedef HMMIO (WINAPI *pfnMmioOpenW)(LPWSTR, LPMMIOINFO, DWORD);
typedef MMRESULT (WINAPI *pfnMmioClose)(HMMIO, UINT);
typedef LONG (WINAPI *pfnMmioRead)(HMMIO, HPSTR, LONG);
typedef LONG (WINAPI *pfnMmioWrite)(HMMIO, const char*, LONG);
typedef LONG (WINAPI *pfnMmioSeek)(HMMIO, LONG, int);
typedef MMRESULT (WINAPI *pfnMmioGetInfo)(HMMIO, LPMMIOINFO, UINT);
typedef MMRESULT (WINAPI *pfnMmioSetInfo)(HMMIO, LPCMMIOINFO, UINT);
typedef MMRESULT (WINAPI *pfnMmioSetBuffer)(HMMIO, LPSTR, LONG, UINT);
typedef MMRESULT (WINAPI *pfnMmioFlush)(HMMIO, UINT);
typedef MMRESULT (WINAPI *pfnMmioAdvance)(HMMIO, LPMMIOINFO, UINT);
typedef LPMMIOPROC (WINAPI *pfnMmioInstallIOProcA)(FOURCC, LPMMIOPROC, DWORD);
typedef LPMMIOPROC (WINAPI *pfnMmioInstallIOProcW)(FOURCC, LPMMIOPROC, DWORD);
typedef FOURCC (WINAPI *pfnMmioStringToFOURCCA)(LPCSTR, UINT);
typedef FOURCC (WINAPI *pfnMmioStringToFOURCCW)(LPCWSTR, UINT);
typedef MMRESULT (WINAPI *pfnMmioDescend)(HMMIO, LPMMCKINFO, const MMCKINFO*, UINT);
typedef MMRESULT (WINAPI *pfnMmioAscend)(HMMIO, LPMMCKINFO, UINT);
typedef MMRESULT (WINAPI *pfnMmioCreateChunk)(HMMIO, LPMMCKINFO, UINT);
typedef MMRESULT (WINAPI *pfnMmioRename)(LPCSTR, LPCSTR, LPCMMIOINFO, DWORD);
typedef LRESULT (WINAPI *pfnMmioSendMessage)(HMMIO, UINT, LPARAM, LPARAM);

// Function pointers
static pfnTimeGetTime o_TimeGetTime = NULL;
static pfnTimeBeginPeriod o_TimeBeginPeriod = NULL;
static pfnTimeEndPeriod o_TimeEndPeriod = NULL;
static pfnTimeGetDevCaps o_TimeGetDevCaps = NULL;
static pfnTimeGetSystemTime o_TimeGetSystemTime = NULL;
static pfnTimeSetEvent o_TimeSetEvent = NULL;
static pfnTimeKillEvent o_TimeKillEvent = NULL;
static pfnWaveOutOpen o_WaveOutOpen = NULL;
static pfnWaveOutClose o_WaveOutClose = NULL;
static pfnWaveOutWrite o_WaveOutWrite = NULL;
static pfnWaveOutPrepareHeader o_WaveOutPrepareHeader = NULL;
static pfnWaveOutUnprepareHeader o_WaveOutUnprepareHeader = NULL;
static pfnWaveOutReset o_WaveOutReset = NULL;
static pfnWaveOutPause o_WaveOutPause = NULL;
static pfnWaveOutRestart o_WaveOutRestart = NULL;
static pfnWaveOutGetPosition o_WaveOutGetPosition = NULL;
static pfnWaveOutGetDevCapsA o_WaveOutGetDevCapsA = NULL;
static pfnWaveOutGetDevCapsW o_WaveOutGetDevCapsW = NULL;
static pfnWaveOutGetNumDevs o_WaveOutGetNumDevs = NULL;
static pfnWaveOutGetVolume o_WaveOutGetVolume = NULL;
static pfnWaveOutSetVolume o_WaveOutSetVolume = NULL;
static pfnWaveOutGetErrorTextA o_WaveOutGetErrorTextA = NULL;
static pfnWaveOutGetErrorTextW o_WaveOutGetErrorTextW = NULL;
static pfnWaveOutGetID o_WaveOutGetID = NULL;
static pfnWaveOutMessage o_WaveOutMessage = NULL;
static pfnWaveOutBreakLoop o_WaveOutBreakLoop = NULL;
static pfnWaveInOpen o_WaveInOpen = NULL;
static pfnWaveInClose o_WaveInClose = NULL;
static pfnWaveInGetNumDevs o_WaveInGetNumDevs = NULL;
static pfnWaveInGetDevCapsA o_WaveInGetDevCapsA = NULL;
static pfnWaveInGetDevCapsW o_WaveInGetDevCapsW = NULL;
static pfnWaveInStart o_WaveInStart = NULL;
static pfnWaveInStop o_WaveInStop = NULL;
static pfnWaveInReset o_WaveInReset = NULL;
static pfnWaveInPrepareHeader o_WaveInPrepareHeader = NULL;
static pfnWaveInUnprepareHeader o_WaveInUnprepareHeader = NULL;
static pfnWaveInAddBuffer o_WaveInAddBuffer = NULL;
static pfnWaveInGetPosition o_WaveInGetPosition = NULL;
static pfnWaveInGetID o_WaveInGetID = NULL;
static pfnWaveInGetErrorTextA o_WaveInGetErrorTextA = NULL;
static pfnWaveInGetErrorTextW o_WaveInGetErrorTextW = NULL;
static pfnWaveInMessage o_WaveInMessage = NULL;
static pfnPlaySoundA o_PlaySoundA = NULL;
static pfnPlaySoundW o_PlaySoundW = NULL;
static pfnSndPlaySoundA o_SndPlaySoundA = NULL;
static pfnSndPlaySoundW o_SndPlaySoundW = NULL;
static pfnMidiOutGetNumDevs o_MidiOutGetNumDevs = NULL;
static pfnMidiOutGetDevCapsA o_MidiOutGetDevCapsA = NULL;
static pfnMidiOutGetDevCapsW o_MidiOutGetDevCapsW = NULL;
static pfnMidiOutOpen o_MidiOutOpen = NULL;
static pfnMidiOutClose o_MidiOutClose = NULL;
static pfnMidiOutShortMsg o_MidiOutShortMsg = NULL;
static pfnMidiOutLongMsg o_MidiOutLongMsg = NULL;
static pfnMidiOutReset o_MidiOutReset = NULL;
static pfnMidiOutPrepareHeader o_MidiOutPrepareHeader = NULL;
static pfnMidiOutUnprepareHeader o_MidiOutUnprepareHeader = NULL;
static pfnJoyGetNumDevs o_JoyGetNumDevs = NULL;
static pfnJoyGetDevCapsA o_JoyGetDevCapsA = NULL;
static pfnJoyGetDevCapsW o_JoyGetDevCapsW = NULL;
static pfnJoyGetPos o_JoyGetPos = NULL;
static pfnJoyGetPosEx o_JoyGetPosEx = NULL;
static pfnJoyGetThreshold o_JoyGetThreshold = NULL;
static pfnJoySetThreshold o_JoySetThreshold = NULL;
static pfnJoySetCapture o_JoySetCapture = NULL;
static pfnJoyReleaseCapture o_JoyReleaseCapture = NULL;
static pfnAuxGetNumDevs o_AuxGetNumDevs = NULL;
static pfnAuxGetDevCapsA o_AuxGetDevCapsA = NULL;
static pfnAuxGetDevCapsW o_AuxGetDevCapsW = NULL;
static pfnAuxGetVolume o_AuxGetVolume = NULL;
static pfnAuxSetVolume o_AuxSetVolume = NULL;
static pfnAuxOutMessage o_AuxOutMessage = NULL;
static pfnMixerGetNumDevs o_MixerGetNumDevs = NULL;
static pfnMixerOpen o_MixerOpen = NULL;
static pfnMixerClose o_MixerClose = NULL;
static pfnMixerGetDevCapsA o_MixerGetDevCapsA = NULL;
static pfnMixerGetDevCapsW o_MixerGetDevCapsW = NULL;
static pfnMixerGetLineInfoA o_MixerGetLineInfoA = NULL;
static pfnMixerGetLineInfoW o_MixerGetLineInfoW = NULL;
static pfnMixerGetLineControlsA o_MixerGetLineControlsA = NULL;
static pfnMixerGetLineControlsW o_MixerGetLineControlsW = NULL;
static pfnMixerGetControlDetailsA o_MixerGetControlDetailsA = NULL;
static pfnMixerGetControlDetailsW o_MixerGetControlDetailsW = NULL;
static pfnMixerSetControlDetails o_MixerSetControlDetails = NULL;
static pfnMixerGetID o_MixerGetID = NULL;
static pfnMixerMessage o_MixerMessage = NULL;
static pfnMciSendCommandA o_MciSendCommandA = NULL;
static pfnMciSendCommandW o_MciSendCommandW = NULL;
static pfnMciSendStringA o_MciSendStringA = NULL;
static pfnMciSendStringW o_MciSendStringW = NULL;
static pfnMciGetErrorStringA o_MciGetErrorStringA = NULL;
static pfnMciGetErrorStringW o_MciGetErrorStringW = NULL;
static pfnMciGetDeviceIDA o_MciGetDeviceIDA = NULL;
static pfnMciGetDeviceIDW o_MciGetDeviceIDW = NULL;
static pfnMciGetDeviceIDFromElementIDA o_MciGetDeviceIDFromElementIDA = NULL;
static pfnMciGetDeviceIDFromElementIDW o_MciGetDeviceIDFromElementIDW = NULL;
static pfnMciSetYieldProc o_MciSetYieldProc = NULL;
static pfnMciGetYieldProc o_MciGetYieldProc = NULL;
static pfnMciGetCreatorTask o_MciGetCreatorTask = NULL;
static pfnMciExecute o_MciExecute = NULL;
static pfnMmioOpenA o_MmioOpenA = NULL;
static pfnMmioOpenW o_MmioOpenW = NULL;
static pfnMmioClose o_MmioClose = NULL;
static pfnMmioRead o_MmioRead = NULL;
static pfnMmioWrite o_MmioWrite = NULL;
static pfnMmioSeek o_MmioSeek = NULL;
static pfnMmioGetInfo o_MmioGetInfo = NULL;
static pfnMmioSetInfo o_MmioSetInfo = NULL;
static pfnMmioSetBuffer o_MmioSetBuffer = NULL;
static pfnMmioFlush o_MmioFlush = NULL;
static pfnMmioAdvance o_MmioAdvance = NULL;
static pfnMmioInstallIOProcA o_MmioInstallIOProcA = NULL;
static pfnMmioInstallIOProcW o_MmioInstallIOProcW = NULL;
static pfnMmioStringToFOURCCA o_MmioStringToFOURCCA = NULL;
static pfnMmioStringToFOURCCW o_MmioStringToFOURCCW = NULL;
static pfnMmioDescend o_MmioDescend = NULL;
static pfnMmioAscend o_MmioAscend = NULL;
static pfnMmioCreateChunk o_MmioCreateChunk = NULL;
static pfnMmioRename o_MmioRename = NULL;
static pfnMmioSendMessage o_MmioSendMessage = NULL;

bool LoadOriginal() {
    if (g_hOriginal) return true;
    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat(sysPath, "\\winmm.dll");
    g_hOriginal = LoadLibraryA(sysPath);
    if (!g_hOriginal) return false;
    
    o_TimeGetTime = (pfnTimeGetTime)GetProcAddress(g_hOriginal, "timeGetTime");
    o_TimeBeginPeriod = (pfnTimeBeginPeriod)GetProcAddress(g_hOriginal, "timeBeginPeriod");
    o_TimeEndPeriod = (pfnTimeEndPeriod)GetProcAddress(g_hOriginal, "timeEndPeriod");
    o_TimeGetDevCaps = (pfnTimeGetDevCaps)GetProcAddress(g_hOriginal, "timeGetDevCaps");
    o_TimeGetSystemTime = (pfnTimeGetSystemTime)GetProcAddress(g_hOriginal, "timeGetSystemTime");
    o_TimeSetEvent = (pfnTimeSetEvent)GetProcAddress(g_hOriginal, "timeSetEvent");
    o_TimeKillEvent = (pfnTimeKillEvent)GetProcAddress(g_hOriginal, "timeKillEvent");
    o_WaveOutOpen = (pfnWaveOutOpen)GetProcAddress(g_hOriginal, "waveOutOpen");
    o_WaveOutClose = (pfnWaveOutClose)GetProcAddress(g_hOriginal, "waveOutClose");
    o_WaveOutWrite = (pfnWaveOutWrite)GetProcAddress(g_hOriginal, "waveOutWrite");
    o_WaveOutPrepareHeader = (pfnWaveOutPrepareHeader)GetProcAddress(g_hOriginal, "waveOutPrepareHeader");
    o_WaveOutUnprepareHeader = (pfnWaveOutUnprepareHeader)GetProcAddress(g_hOriginal, "waveOutUnprepareHeader");
    o_WaveOutReset = (pfnWaveOutReset)GetProcAddress(g_hOriginal, "waveOutReset");
    o_WaveOutPause = (pfnWaveOutPause)GetProcAddress(g_hOriginal, "waveOutPause");
    o_WaveOutRestart = (pfnWaveOutRestart)GetProcAddress(g_hOriginal, "waveOutRestart");
    o_WaveOutGetPosition = (pfnWaveOutGetPosition)GetProcAddress(g_hOriginal, "waveOutGetPosition");
    o_WaveOutGetDevCapsA = (pfnWaveOutGetDevCapsA)GetProcAddress(g_hOriginal, "waveOutGetDevCapsA");
    o_WaveOutGetDevCapsW = (pfnWaveOutGetDevCapsW)GetProcAddress(g_hOriginal, "waveOutGetDevCapsW");
    o_WaveOutGetNumDevs = (pfnWaveOutGetNumDevs)GetProcAddress(g_hOriginal, "waveOutGetNumDevs");
    o_WaveOutGetVolume = (pfnWaveOutGetVolume)GetProcAddress(g_hOriginal, "waveOutGetVolume");
    o_WaveOutSetVolume = (pfnWaveOutSetVolume)GetProcAddress(g_hOriginal, "waveOutSetVolume");
    o_WaveOutGetErrorTextA = (pfnWaveOutGetErrorTextA)GetProcAddress(g_hOriginal, "waveOutGetErrorTextA");
    o_WaveOutGetErrorTextW = (pfnWaveOutGetErrorTextW)GetProcAddress(g_hOriginal, "waveOutGetErrorTextW");
    o_WaveOutGetID = (pfnWaveOutGetID)GetProcAddress(g_hOriginal, "waveOutGetID");
    o_WaveOutMessage = (pfnWaveOutMessage)GetProcAddress(g_hOriginal, "waveOutMessage");
    o_WaveOutBreakLoop = (pfnWaveOutBreakLoop)GetProcAddress(g_hOriginal, "waveOutBreakLoop");
    o_WaveInOpen = (pfnWaveInOpen)GetProcAddress(g_hOriginal, "waveInOpen");
    o_WaveInClose = (pfnWaveInClose)GetProcAddress(g_hOriginal, "waveInClose");
    o_WaveInGetNumDevs = (pfnWaveInGetNumDevs)GetProcAddress(g_hOriginal, "waveInGetNumDevs");
    o_WaveInGetDevCapsA = (pfnWaveInGetDevCapsA)GetProcAddress(g_hOriginal, "waveInGetDevCapsA");
    o_WaveInGetDevCapsW = (pfnWaveInGetDevCapsW)GetProcAddress(g_hOriginal, "waveInGetDevCapsW");
    o_WaveInStart = (pfnWaveInStart)GetProcAddress(g_hOriginal, "waveInStart");
    o_WaveInStop = (pfnWaveInStop)GetProcAddress(g_hOriginal, "waveInStop");
    o_WaveInReset = (pfnWaveInReset)GetProcAddress(g_hOriginal, "waveInReset");
    o_WaveInPrepareHeader = (pfnWaveInPrepareHeader)GetProcAddress(g_hOriginal, "waveInPrepareHeader");
    o_WaveInUnprepareHeader = (pfnWaveInUnprepareHeader)GetProcAddress(g_hOriginal, "waveInUnprepareHeader");
    o_WaveInAddBuffer = (pfnWaveInAddBuffer)GetProcAddress(g_hOriginal, "waveInAddBuffer");
    o_WaveInGetPosition = (pfnWaveInGetPosition)GetProcAddress(g_hOriginal, "waveInGetPosition");
    o_WaveInGetID = (pfnWaveInGetID)GetProcAddress(g_hOriginal, "waveInGetID");
    o_WaveInGetErrorTextA = (pfnWaveInGetErrorTextA)GetProcAddress(g_hOriginal, "waveInGetErrorTextA");
    o_WaveInGetErrorTextW = (pfnWaveInGetErrorTextW)GetProcAddress(g_hOriginal, "waveInGetErrorTextW");
    o_WaveInMessage = (pfnWaveInMessage)GetProcAddress(g_hOriginal, "waveInMessage");
    o_PlaySoundA = (pfnPlaySoundA)GetProcAddress(g_hOriginal, "PlaySoundA");
    o_PlaySoundW = (pfnPlaySoundW)GetProcAddress(g_hOriginal, "PlaySoundW");
    o_SndPlaySoundA = (pfnSndPlaySoundA)GetProcAddress(g_hOriginal, "sndPlaySoundA");
    o_SndPlaySoundW = (pfnSndPlaySoundW)GetProcAddress(g_hOriginal, "sndPlaySoundW");
    o_MidiOutGetNumDevs = (pfnMidiOutGetNumDevs)GetProcAddress(g_hOriginal, "midiOutGetNumDevs");
    o_MidiOutGetDevCapsA = (pfnMidiOutGetDevCapsA)GetProcAddress(g_hOriginal, "midiOutGetDevCapsA");
    o_MidiOutGetDevCapsW = (pfnMidiOutGetDevCapsW)GetProcAddress(g_hOriginal, "midiOutGetDevCapsW");
    o_MidiOutOpen = (pfnMidiOutOpen)GetProcAddress(g_hOriginal, "midiOutOpen");
    o_MidiOutClose = (pfnMidiOutClose)GetProcAddress(g_hOriginal, "midiOutClose");
    o_MidiOutShortMsg = (pfnMidiOutShortMsg)GetProcAddress(g_hOriginal, "midiOutShortMsg");
    o_MidiOutLongMsg = (pfnMidiOutLongMsg)GetProcAddress(g_hOriginal, "midiOutLongMsg");
    o_MidiOutReset = (pfnMidiOutReset)GetProcAddress(g_hOriginal, "midiOutReset");
    o_MidiOutPrepareHeader = (pfnMidiOutPrepareHeader)GetProcAddress(g_hOriginal, "midiOutPrepareHeader");
    o_MidiOutUnprepareHeader = (pfnMidiOutUnprepareHeader)GetProcAddress(g_hOriginal, "midiOutUnprepareHeader");
    o_JoyGetNumDevs = (pfnJoyGetNumDevs)GetProcAddress(g_hOriginal, "joyGetNumDevs");
    o_JoyGetDevCapsA = (pfnJoyGetDevCapsA)GetProcAddress(g_hOriginal, "joyGetDevCapsA");
    o_JoyGetDevCapsW = (pfnJoyGetDevCapsW)GetProcAddress(g_hOriginal, "joyGetDevCapsW");
    o_JoyGetPos = (pfnJoyGetPos)GetProcAddress(g_hOriginal, "joyGetPos");
    o_JoyGetPosEx = (pfnJoyGetPosEx)GetProcAddress(g_hOriginal, "joyGetPosEx");
    o_JoyGetThreshold = (pfnJoyGetThreshold)GetProcAddress(g_hOriginal, "joyGetThreshold");
    o_JoySetThreshold = (pfnJoySetThreshold)GetProcAddress(g_hOriginal, "joySetThreshold");
    o_JoySetCapture = (pfnJoySetCapture)GetProcAddress(g_hOriginal, "joySetCapture");
    o_JoyReleaseCapture = (pfnJoyReleaseCapture)GetProcAddress(g_hOriginal, "joyReleaseCapture");
    o_AuxGetNumDevs = (pfnAuxGetNumDevs)GetProcAddress(g_hOriginal, "auxGetNumDevs");
    o_AuxGetDevCapsA = (pfnAuxGetDevCapsA)GetProcAddress(g_hOriginal, "auxGetDevCapsA");
    o_AuxGetDevCapsW = (pfnAuxGetDevCapsW)GetProcAddress(g_hOriginal, "auxGetDevCapsW");
    o_AuxGetVolume = (pfnAuxGetVolume)GetProcAddress(g_hOriginal, "auxGetVolume");
    o_AuxSetVolume = (pfnAuxSetVolume)GetProcAddress(g_hOriginal, "auxSetVolume");
    o_AuxOutMessage = (pfnAuxOutMessage)GetProcAddress(g_hOriginal, "auxOutMessage");
    o_MixerGetNumDevs = (pfnMixerGetNumDevs)GetProcAddress(g_hOriginal, "mixerGetNumDevs");
    o_MixerOpen = (pfnMixerOpen)GetProcAddress(g_hOriginal, "mixerOpen");
    o_MixerClose = (pfnMixerClose)GetProcAddress(g_hOriginal, "mixerClose");
    o_MixerGetDevCapsA = (pfnMixerGetDevCapsA)GetProcAddress(g_hOriginal, "mixerGetDevCapsA");
    o_MixerGetDevCapsW = (pfnMixerGetDevCapsW)GetProcAddress(g_hOriginal, "mixerGetDevCapsW");
    o_MixerGetLineInfoA = (pfnMixerGetLineInfoA)GetProcAddress(g_hOriginal, "mixerGetLineInfoA");
    o_MixerGetLineInfoW = (pfnMixerGetLineInfoW)GetProcAddress(g_hOriginal, "mixerGetLineInfoW");
    o_MixerGetLineControlsA = (pfnMixerGetLineControlsA)GetProcAddress(g_hOriginal, "mixerGetLineControlsA");
    o_MixerGetLineControlsW = (pfnMixerGetLineControlsW)GetProcAddress(g_hOriginal, "mixerGetLineControlsW");
    o_MixerGetControlDetailsA = (pfnMixerGetControlDetailsA)GetProcAddress(g_hOriginal, "mixerGetControlDetailsA");
    o_MixerGetControlDetailsW = (pfnMixerGetControlDetailsW)GetProcAddress(g_hOriginal, "mixerGetControlDetailsW");
    o_MixerSetControlDetails = (pfnMixerSetControlDetails)GetProcAddress(g_hOriginal, "mixerSetControlDetails");
    o_MixerGetID = (pfnMixerGetID)GetProcAddress(g_hOriginal, "mixerGetID");
    o_MixerMessage = (pfnMixerMessage)GetProcAddress(g_hOriginal, "mixerMessage");
    o_MciSendCommandA = (pfnMciSendCommandA)GetProcAddress(g_hOriginal, "mciSendCommandA");
    o_MciSendCommandW = (pfnMciSendCommandW)GetProcAddress(g_hOriginal, "mciSendCommandW");
    o_MciSendStringA = (pfnMciSendStringA)GetProcAddress(g_hOriginal, "mciSendStringA");
    o_MciSendStringW = (pfnMciSendStringW)GetProcAddress(g_hOriginal, "mciSendStringW");
    o_MciGetErrorStringA = (pfnMciGetErrorStringA)GetProcAddress(g_hOriginal, "mciGetErrorStringA");
    o_MciGetErrorStringW = (pfnMciGetErrorStringW)GetProcAddress(g_hOriginal, "mciGetErrorStringW");
    o_MciGetDeviceIDA = (pfnMciGetDeviceIDA)GetProcAddress(g_hOriginal, "mciGetDeviceIDA");
    o_MciGetDeviceIDW = (pfnMciGetDeviceIDW)GetProcAddress(g_hOriginal, "mciGetDeviceIDW");
    o_MciGetDeviceIDFromElementIDA = (pfnMciGetDeviceIDFromElementIDA)GetProcAddress(g_hOriginal, "mciGetDeviceIDFromElementIDA");
    o_MciGetDeviceIDFromElementIDW = (pfnMciGetDeviceIDFromElementIDW)GetProcAddress(g_hOriginal, "mciGetDeviceIDFromElementIDW");
    o_MciSetYieldProc = (pfnMciSetYieldProc)GetProcAddress(g_hOriginal, "mciSetYieldProc");
    o_MciGetYieldProc = (pfnMciGetYieldProc)GetProcAddress(g_hOriginal, "mciGetYieldProc");
    o_MciGetCreatorTask = (pfnMciGetCreatorTask)GetProcAddress(g_hOriginal, "mciGetCreatorTask");
    o_MciExecute = (pfnMciExecute)GetProcAddress(g_hOriginal, "mciExecute");
    o_MmioOpenA = (pfnMmioOpenA)GetProcAddress(g_hOriginal, "mmioOpenA");
    o_MmioOpenW = (pfnMmioOpenW)GetProcAddress(g_hOriginal, "mmioOpenW");
    o_MmioClose = (pfnMmioClose)GetProcAddress(g_hOriginal, "mmioClose");
    o_MmioRead = (pfnMmioRead)GetProcAddress(g_hOriginal, "mmioRead");
    o_MmioWrite = (pfnMmioWrite)GetProcAddress(g_hOriginal, "mmioWrite");
    o_MmioSeek = (pfnMmioSeek)GetProcAddress(g_hOriginal, "mmioSeek");
    o_MmioGetInfo = (pfnMmioGetInfo)GetProcAddress(g_hOriginal, "mmioGetInfo");
    o_MmioSetInfo = (pfnMmioSetInfo)GetProcAddress(g_hOriginal, "mmioSetInfo");
    o_MmioSetBuffer = (pfnMmioSetBuffer)GetProcAddress(g_hOriginal, "mmioSetBuffer");
    o_MmioFlush = (pfnMmioFlush)GetProcAddress(g_hOriginal, "mmioFlush");
    o_MmioAdvance = (pfnMmioAdvance)GetProcAddress(g_hOriginal, "mmioAdvance");
    o_MmioInstallIOProcA = (pfnMmioInstallIOProcA)GetProcAddress(g_hOriginal, "mmioInstallIOProcA");
    o_MmioInstallIOProcW = (pfnMmioInstallIOProcW)GetProcAddress(g_hOriginal, "mmioInstallIOProcW");
    o_MmioStringToFOURCCA = (pfnMmioStringToFOURCCA)GetProcAddress(g_hOriginal, "mmioStringToFOURCCA");
    o_MmioStringToFOURCCW = (pfnMmioStringToFOURCCW)GetProcAddress(g_hOriginal, "mmioStringToFOURCCW");
    o_MmioDescend = (pfnMmioDescend)GetProcAddress(g_hOriginal, "mmioDescend");
    o_MmioAscend = (pfnMmioAscend)GetProcAddress(g_hOriginal, "mmioAscend");
    o_MmioCreateChunk = (pfnMmioCreateChunk)GetProcAddress(g_hOriginal, "mmioCreateChunk");
    o_MmioRename = (pfnMmioRename)GetProcAddress(g_hOriginal, "mmioRenameA");
    o_MmioSendMessage = (pfnMmioSendMessage)GetProcAddress(g_hOriginal, "mmioSendMessage");
    
    return true;
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

struct ProcessInfo { std::string name; std::string path; DWORD pid; bool suspicious; };
static std::vector<ProcessInfo> g_Processes;

struct ModuleInfo { std::string name; std::string path; std::string hash; DWORD size; };
static std::vector<ModuleInfo> g_Modules;

struct WindowInfo { std::string title; std::string className; DWORD pid; bool suspicious; };
static std::vector<WindowInfo> g_Windows;

struct FileHashInfo { std::string filename; std::string path; std::string shortHash; std::string fullHash; DWORD size; DWORD modTime; };
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

const char* g_WhitelistProc[] = {
    "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "explorer.exe", "dwm.exe", "taskhostw.exe",
    "searchindexer", "searchhost", "runtimebroker", "sihost.exe", "fontdrvhost",
    "ctfmon.exe", "conhost.exe", "dllhost.exe", "audiodg.exe", "spoolsv.exe",
    "msmpeng.exe", "mpcmdrun.exe", "mpdefendercoreservice", "securityhealthservice",
    "smartscreen.exe", "sgrmbroker.exe",
    "steam.exe", "steamservice.exe", "steamwebhelper", "epicgameslauncher",
    "discord.exe", "discordptb", "discordcanary",
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
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
    "opengl32.dll", "d3d9.dll",
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
// SERVER DETECTION
// ============================================
bool DetectConnectedServer() {
    g_bInServer = false;
    g_szConnectedIP[0] = 0;
    g_iConnectedPort = 0;
    
    DWORD hlPid = GetCurrentProcessId();
    MIB_TCPTABLE_OWNER_PID* pTcpTable = NULL;
    DWORD dwSize = 0;
    
    if (GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
        if (pTcpTable && GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];
                if (row.dwOwningPid == hlPid && row.dwState == MIB_TCP_STATE_ESTAB) {
                    IN_ADDR remoteAddr;
                    remoteAddr.S_un.S_addr = row.dwRemoteAddr;
                    int remotePort = ntohs((u_short)row.dwRemotePort);
                    if (remotePort >= 27000 && remotePort <= 27100) {
                        strcpy(g_szConnectedIP, inet_ntoa(remoteAddr));
                        g_iConnectedPort = remotePort;
                        g_bInServer = true;
                        break;
                    }
                }
            }
        }
        if (pTcpTable) free(pTcpTable);
    }
    
    if (!g_bInServer) {
        MIB_UDPTABLE_OWNER_PID* pUdpTable = NULL;
        dwSize = 0;
        if (GetExtendedUdpTable(NULL, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
            pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(dwSize);
            if (pUdpTable && GetExtendedUdpTable(pUdpTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                    MIB_UDPROW_OWNER_PID& row = pUdpTable->table[i];
                    if (row.dwOwningPid == hlPid) {
                        int localPort = ntohs((u_short)row.dwLocalPort);
                        if (localPort >= 27000 && localPort <= 27100) {
                            g_bInServer = true;
                            break;
                        }
                    }
                }
            }
            if (pUdpTable) free(pUdpTable);
        }
    }
    
    return g_bInServer;
}

// ============================================
// HTTP Helper
// ============================================
std::string HttpRequest(const wchar_t* path, const std::string& body, const std::string& method = "POST") {
    std::string response;
    HINTERNET hSession = WinHttpOpen(L"AGTR/11.5", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return response;
    
    HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return response; }
    
    DWORD flags = API_USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    std::wstring wmethod(method.begin(), method.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wmethod.c_str(), path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return response; }
    
    std::wstring headers = L"Content-Type: application/json\r\n";
    BOOL result = body.empty() ? 
        WinHttpSendRequest(hRequest, headers.c_str(), -1, NULL, 0, 0, 0) :
        WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)body.c_str(), body.length(), body.length(), 0);
    
    if (result && WinHttpReceiveResponse(hRequest, NULL)) {
        char buffer[4096] = {0};
        DWORD bytesRead = 0;
        WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead);
        if (bytesRead > 0) response = std::string(buffer, bytesRead);
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

// ============================================
// SETTINGS & HEARTBEAT
// ============================================
bool FetchSettings() {
    std::string json = "{\"hwid\":\"" + std::string(g_szHWID) + "\",\"version\":\"" + AGTR_VERSION + "\",\"trigger\":\"winmm\"}";
    std::string resp = HttpRequest(API_PATH_REGISTER, json);
    
    if (resp.empty()) { Log("Settings fetch failed"); return false; }
    Log("Settings: %.200s", resp.c_str());
    
    if (strstr(resp.c_str(), "\"scan_enabled\":false")) g_Settings.scan_enabled = false;
    if (strstr(resp.c_str(), "\"scan_only_in_server\":false")) g_Settings.scan_only_in_server = false;
    
    const char* intPos = strstr(resp.c_str(), "\"scan_interval\":");
    if (intPos) {
        int interval = atoi(intPos + 16);
        if (interval >= 30 && interval <= 600) g_Settings.scan_interval = interval * 1000;
    }
    
    if (strstr(resp.c_str(), "\"status\":\"banned\"") || strstr(resp.c_str(), "\"action\":\"kick\"")) {
        Log("!!! BANNED !!!");
        MessageBoxA(NULL, g_Settings.message_on_kick, "AGTR Anti-Cheat", MB_OK | MB_ICONERROR);
        ExitProcess(0);
        return false;
    }
    
    g_bSettingsLoaded = true;
    return true;
}

void SendHeartbeat() {
    DetectConnectedServer();
    char json[512];
    sprintf(json, "{\"hwid\":\"%s\",\"server_ip\":\"%s\",\"server_port\":%d,\"in_game\":%s,\"trigger\":\"winmm\"}",
        g_szHWID, g_szConnectedIP, g_iConnectedPort, g_bInServer ? "true" : "false");
    std::string resp = HttpRequest(API_PATH_HEARTBEAT, json);
    if (!resp.empty() && strstr(resp.c_str(), "\"should_scan\":false")) g_Settings.scan_enabled = false;
    g_dwLastHeartbeat = GetTickCount();
}

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
    shortHash[0] = fullHash[0] = 0; *fileSize = 0;
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
    sprintf(path, "%s\\winmm.dll", g_szGameDir);
    char shortH[16]; DWORD size;
    GetFileHash(path, shortH, g_szDLLHash, &size);
    Log("DLL Hash: %s", g_szDLLHash);
}

// ============================================
// SCANNERS
// ============================================
bool IsWhitelistedProcess(const char* name) {
    char lower[MAX_PATH]; strcpy(lower, name); ToLower(lower);
    for (int i = 0; g_WhitelistProc[i]; i++) if (strstr(lower, g_WhitelistProc[i])) return true;
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
            ProcessInfo pi; pi.name = pe.szExeFile; pi.pid = pe.th32ProcessID; pi.suspicious = false;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                char path[MAX_PATH] = {0}; DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameA(hProc, 0, path, &size)) pi.path = path;
                CloseHandle(hProc);
            }
            if (!IsWhitelistedProcess(pe.szExeFile)) {
                char name[MAX_PATH]; strcpy(name, pe.szExeFile); ToLower(name);
                for (int i = 0; g_SusProc[i]; i++) {
                    if (strstr(name, g_SusProc[i])) { pi.suspicious = true; sus++; Log("SUS PROC: %s", pe.szExeFile); break; }
                }
            }
            g_Processes.push_back(pi);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return sus;
}

int ScanModules() {
    g_Modules.clear();
    int sus = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    char sysDir[MAX_PATH]; GetSystemDirectoryA(sysDir, MAX_PATH); ToLower(sysDir);
    
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            ModuleInfo mi; mi.name = me.szModule; mi.path = me.szExePath; mi.size = me.modBaseSize;
            char shortH[16], fullH[64]; DWORD fsize;
            GetFileHash(me.szExePath, shortH, fullH, &fsize);
            mi.hash = shortH;
            
            char modName[MAX_PATH]; strcpy(modName, me.szModule); ToLower(modName);
            char modPath[MAX_PATH]; strcpy(modPath, me.szExePath); ToLower(modPath);
            
            for (int i = 0; g_SusDLLs[i]; i++) {
                if (strstr(modName, g_SusDLLs[i])) {
                    if ((strcmp(g_SusDLLs[i], "opengl32.dll") == 0 || strcmp(g_SusDLLs[i], "d3d9.dll") == 0)) {
                        if (strstr(modPath, sysDir)) continue;
                    }
                    sus++; Log("SUS MODULE: %s", me.szModule); break;
                }
            }
            g_Modules.push_back(mi);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return sus;
}

static int g_WinSus = 0;
BOOL CALLBACK EnumWinCB(HWND hwnd, LPARAM) {
    char title[256] = {0}, className[256] = {0};
    GetWindowTextA(hwnd, title, 256);
    GetClassNameA(hwnd, className, 256);
    if (title[0]) {
        WindowInfo wi; wi.title = title; wi.className = className;
        DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
        wi.pid = pid; wi.suspicious = false;
        char lowerTitle[256]; strcpy(lowerTitle, title); ToLower(lowerTitle);
        for (int i = 0; g_SusWin[i]; i++) {
            if (strstr(lowerTitle, g_SusWin[i])) { wi.suspicious = true; g_WinSus++; Log("SUS WIN: %s", title); break; }
        }
        g_Windows.push_back(wi);
    }
    return TRUE;
}

int ScanWindows() { g_Windows.clear(); g_WinSus = 0; EnumWindows(EnumWinCB, 0); return g_WinSus; }

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
        char shortH[16], fullH[64]; DWORD fileSize;
        GetFileHash(filepath, shortH, fullH, &fileSize);
        if (shortH[0]) {
            FileHashInfo fhi; fhi.filename = filename; fhi.path = filepath;
            fhi.shortHash = shortH; fhi.fullHash = fullH; fhi.size = fileSize; fhi.modTime = modTime;
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
    sprintf(dir, "%s\\ag", g_szGameDir); ScanDir(dir, "*.dll");
    sprintf(dir, "%s\\ag\\cl_dlls", g_szGameDir); ScanDir(dir, "*.dll");
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
// JSON BUILDER
// ============================================
std::string EscapeJson(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.length(); i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: if (c < 0x20) { char buf[8]; sprintf(buf, "\\u%04x", c); out += buf; } else out += c; break;
        }
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
    json += "\"total_processes\":" + std::to_string(g_Processes.size()) + ",";
    json += "\"total_modules\":" + std::to_string(g_Modules.size()) + ",";
    json += "\"total_windows\":" + std::to_string(g_Windows.size()) + ",";
    
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
    
    json += "\"processes\":[";
    first = true; int procCount = 0;
    for (auto& p : g_Processes) {
        if (p.suspicious || procCount < 20) {
            if (!first) json += ",";
            json += "{\"name\":\"" + EscapeJson(p.name) + "\",";
            json += "\"path\":\"" + EscapeJson(p.path) + "\",";
            json += "\"pid\":" + std::to_string(p.pid) + ",";
            json += "\"suspicious\":" + std::string(p.suspicious ? "true" : "false") + "}";
            first = false; procCount++;
        }
    }
    json += "],";
    
    json += "\"modules\":[";
    first = true;
    char gamePathLower[MAX_PATH]; strcpy(gamePathLower, g_szGameDir); ToLower(gamePathLower);
    for (auto& m : g_Modules) {
        char modPathLower[MAX_PATH]; strcpy(modPathLower, m.path.c_str()); ToLower(modPathLower);
        if (strstr(modPathLower, "half-life") || strstr(modPathLower, gamePathLower)) {
            if (!first) json += ",";
            json += "{\"name\":\"" + EscapeJson(m.name) + "\",";
            json += "\"path\":\"" + EscapeJson(m.path) + "\",";
            json += "\"hash\":\"" + m.hash + "\",";
            json += "\"size\":" + std::to_string(m.size) + "}";
            first = false;
        }
    }
    json += "],";
    
    json += "\"windows\":[";
    first = true;
    for (auto& w : g_Windows) {
        if (w.suspicious) {
            if (!first) json += ",";
            json += "{\"title\":\"" + EscapeJson(w.title) + "\",";
            json += "\"class\":\"" + EscapeJson(w.className) + "\",";
            json += "\"suspicious\":true}";
            first = false;
        }
    }
    json += "]";
    
    json += "}";
    return json;
}

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
    HINTERNET hSession = WinHttpOpen(L"AGTR/11.5", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
    
    DWORD flags = API_USE_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", API_PATH_SCAN, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"X-AGTR-Signature: " + std::wstring(signature.begin(), signature.end()) + L"\r\n";
    headers += L"X-AGTR-HWID: " + std::wstring(g_szHWID, g_szHWID + strlen(g_szHWID)) + L"\r\n";
    
    BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)jsonData.c_str(), jsonData.length(), jsonData.length(), 0);
    if (result && WinHttpReceiveResponse(hRequest, NULL)) {
        char responseBody[4096] = {0};
        DWORD bytesRead = 0;
        WinHttpReadData(hRequest, responseBody, sizeof(responseBody) - 1, &bytesRead);
        
        if (bytesRead > 0 && strstr(responseBody, "\"action\":\"kick\"")) {
            Log("!!! KICK !!!");
            char* reasonStart = strstr(responseBody, "\"reason\":\"");
            if (reasonStart) {
                reasonStart += 10;
                char* reasonEnd = strchr(reasonStart, '"');
                if (reasonEnd) {
                    char reason[256] = {0};
                    strncpy(reason, reasonStart, min((int)(reasonEnd - reasonStart), 255));
                    char msg[512];
                    sprintf(msg, "AGTR Anti-Cheat\n\n%s", reason);
                    MessageBoxA(NULL, msg, "AGTR Anti-Cheat", MB_OK | MB_ICONERROR);
                    ExitProcess(0);
                }
            }
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
        g_bPassed ? "CLEAN" : "SUS", g_iSusCount,
        (int)g_Processes.size(), (int)g_Modules.size(), 
        (int)g_Windows.size(), (int)g_FileCache.size(), (int)(json.length() / 1024));
    
    SendToAPI(json, sig);
}

DWORD WINAPI ScanThread(LPVOID) {
    Sleep(10000);
    Log("=== AGTR v%s (winmm) Started ===", AGTR_VERSION);
    
    GenHWID();
    ComputeDLLHash();
    
    if (!FetchSettings()) Log("Using default settings");
    SendHeartbeat();
    
    if (g_Settings.scan_enabled) {
        ScanAllFiles();
        DoScan();
        g_dwLastScan = GetTickCount();
    }
    
    while (g_bRunning) {
        Sleep(1000);
        DWORD now = GetTickCount();
        
        if (now - g_dwLastHeartbeat >= AGTR_HEARTBEAT_INTERVAL) SendHeartbeat();
        
        if (now - g_dwLastScan >= (DWORD)g_Settings.scan_interval) {
            if (!g_Settings.scan_enabled) continue;
            if (g_Settings.scan_only_in_server) {
                DetectConnectedServer();
                if (!g_bInServer) { g_dwLastScan = now; continue; }
            }
            ScanAllFiles();
            DoScan();
            g_dwLastScan = now;
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

// ============================================
// EXPORTED WINMM FUNCTIONS
// ============================================
extern "C" {

__declspec(dllexport) DWORD WINAPI timeGetTime(void) { if (!LoadOriginal() || !o_TimeGetTime) return GetTickCount(); return o_TimeGetTime(); }
__declspec(dllexport) MMRESULT WINAPI timeBeginPeriod(UINT p) { if (!LoadOriginal() || !o_TimeBeginPeriod) return MMSYSERR_ERROR; return o_TimeBeginPeriod(p); }
__declspec(dllexport) MMRESULT WINAPI timeEndPeriod(UINT p) { if (!LoadOriginal() || !o_TimeEndPeriod) return MMSYSERR_ERROR; return o_TimeEndPeriod(p); }
__declspec(dllexport) MMRESULT WINAPI timeGetDevCaps(LPTIMECAPS p, UINT s) { if (!LoadOriginal() || !o_TimeGetDevCaps) return MMSYSERR_ERROR; return o_TimeGetDevCaps(p, s); }
__declspec(dllexport) MMRESULT WINAPI timeGetSystemTime(LPMMTIME p, UINT s) { if (!LoadOriginal() || !o_TimeGetSystemTime) return MMSYSERR_ERROR; return o_TimeGetSystemTime(p, s); }
__declspec(dllexport) MMRESULT WINAPI timeSetEvent(UINT d, UINT r, LPTIMECALLBACK c, DWORD_PTR u, UINT e) { if (!LoadOriginal() || !o_TimeSetEvent) return 0; return o_TimeSetEvent(d, r, c, u, e); }
__declspec(dllexport) MMRESULT WINAPI timeKillEvent(UINT id) { if (!LoadOriginal() || !o_TimeKillEvent) return MMSYSERR_ERROR; return o_TimeKillEvent(id); }

__declspec(dllexport) MMRESULT WINAPI waveOutOpen(LPHWAVEOUT p, UINT d, LPCWAVEFORMATEX f, DWORD_PTR c, DWORD_PTR i, DWORD o) { if (!LoadOriginal() || !o_WaveOutOpen) return MMSYSERR_ERROR; return o_WaveOutOpen(p, d, f, c, i, o); }
__declspec(dllexport) MMRESULT WINAPI waveOutClose(HWAVEOUT h) { if (!o_WaveOutClose) return MMSYSERR_ERROR; return o_WaveOutClose(h); }
__declspec(dllexport) MMRESULT WINAPI waveOutWrite(HWAVEOUT h, LPWAVEHDR p, UINT s) { if (!o_WaveOutWrite) return MMSYSERR_ERROR; return o_WaveOutWrite(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveOutPrepareHeader(HWAVEOUT h, LPWAVEHDR p, UINT s) { if (!o_WaveOutPrepareHeader) return MMSYSERR_ERROR; return o_WaveOutPrepareHeader(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveOutUnprepareHeader(HWAVEOUT h, LPWAVEHDR p, UINT s) { if (!o_WaveOutUnprepareHeader) return MMSYSERR_ERROR; return o_WaveOutUnprepareHeader(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveOutReset(HWAVEOUT h) { if (!o_WaveOutReset) return MMSYSERR_ERROR; return o_WaveOutReset(h); }
__declspec(dllexport) MMRESULT WINAPI waveOutPause(HWAVEOUT h) { if (!o_WaveOutPause) return MMSYSERR_ERROR; return o_WaveOutPause(h); }
__declspec(dllexport) MMRESULT WINAPI waveOutRestart(HWAVEOUT h) { if (!o_WaveOutRestart) return MMSYSERR_ERROR; return o_WaveOutRestart(h); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetPosition(HWAVEOUT h, LPMMTIME p, UINT s) { if (!o_WaveOutGetPosition) return MMSYSERR_ERROR; return o_WaveOutGetPosition(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetDevCapsA(UINT d, LPWAVEOUTCAPSA p, UINT s) { if (!LoadOriginal() || !o_WaveOutGetDevCapsA) return MMSYSERR_ERROR; return o_WaveOutGetDevCapsA(d, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetDevCapsW(UINT d, LPWAVEOUTCAPSW p, UINT s) { if (!LoadOriginal() || !o_WaveOutGetDevCapsW) return MMSYSERR_ERROR; return o_WaveOutGetDevCapsW(d, p, s); }
__declspec(dllexport) UINT WINAPI waveOutGetNumDevs(void) { if (!LoadOriginal() || !o_WaveOutGetNumDevs) return 0; return o_WaveOutGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetVolume(HWAVEOUT h, LPDWORD p) { if (!o_WaveOutGetVolume) return MMSYSERR_ERROR; return o_WaveOutGetVolume(h, p); }
__declspec(dllexport) MMRESULT WINAPI waveOutSetVolume(HWAVEOUT h, DWORD v) { if (!o_WaveOutSetVolume) return MMSYSERR_ERROR; return o_WaveOutSetVolume(h, v); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetErrorTextA(MMRESULT e, LPSTR p, UINT s) { if (!LoadOriginal() || !o_WaveOutGetErrorTextA) return MMSYSERR_ERROR; return o_WaveOutGetErrorTextA(e, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetErrorTextW(MMRESULT e, LPWSTR p, UINT s) { if (!LoadOriginal() || !o_WaveOutGetErrorTextW) return MMSYSERR_ERROR; return o_WaveOutGetErrorTextW(e, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveOutGetID(HWAVEOUT h, LPUINT p) { if (!o_WaveOutGetID) return MMSYSERR_ERROR; return o_WaveOutGetID(h, p); }
__declspec(dllexport) MMRESULT WINAPI waveOutMessage(HWAVEOUT h, UINT m, DWORD_PTR p1, DWORD_PTR p2) { if (!o_WaveOutMessage) return MMSYSERR_ERROR; return o_WaveOutMessage(h, m, p1, p2); }
__declspec(dllexport) MMRESULT WINAPI waveOutBreakLoop(HWAVEOUT h) { if (!o_WaveOutBreakLoop) return MMSYSERR_ERROR; return o_WaveOutBreakLoop(h); }

__declspec(dllexport) MMRESULT WINAPI waveInOpen(LPHWAVEIN p, UINT d, LPCWAVEFORMATEX f, DWORD_PTR c, DWORD_PTR i, DWORD o) { if (!LoadOriginal() || !o_WaveInOpen) return MMSYSERR_ERROR; return o_WaveInOpen(p, d, f, c, i, o); }
__declspec(dllexport) MMRESULT WINAPI waveInClose(HWAVEIN h) { if (!o_WaveInClose) return MMSYSERR_ERROR; return o_WaveInClose(h); }
__declspec(dllexport) UINT WINAPI waveInGetNumDevs(void) { if (!LoadOriginal() || !o_WaveInGetNumDevs) return 0; return o_WaveInGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI waveInGetDevCapsA(UINT d, LPWAVEINCAPSA p, UINT s) { if (!LoadOriginal() || !o_WaveInGetDevCapsA) return MMSYSERR_ERROR; return o_WaveInGetDevCapsA(d, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveInGetDevCapsW(UINT d, LPWAVEINCAPSW p, UINT s) { if (!LoadOriginal() || !o_WaveInGetDevCapsW) return MMSYSERR_ERROR; return o_WaveInGetDevCapsW(d, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveInStart(HWAVEIN h) { if (!o_WaveInStart) return MMSYSERR_ERROR; return o_WaveInStart(h); }
__declspec(dllexport) MMRESULT WINAPI waveInStop(HWAVEIN h) { if (!o_WaveInStop) return MMSYSERR_ERROR; return o_WaveInStop(h); }
__declspec(dllexport) MMRESULT WINAPI waveInReset(HWAVEIN h) { if (!o_WaveInReset) return MMSYSERR_ERROR; return o_WaveInReset(h); }
__declspec(dllexport) MMRESULT WINAPI waveInPrepareHeader(HWAVEIN h, LPWAVEHDR p, UINT s) { if (!o_WaveInPrepareHeader) return MMSYSERR_ERROR; return o_WaveInPrepareHeader(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveInUnprepareHeader(HWAVEIN h, LPWAVEHDR p, UINT s) { if (!o_WaveInUnprepareHeader) return MMSYSERR_ERROR; return o_WaveInUnprepareHeader(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveInAddBuffer(HWAVEIN h, LPWAVEHDR p, UINT s) { if (!o_WaveInAddBuffer) return MMSYSERR_ERROR; return o_WaveInAddBuffer(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveInGetPosition(HWAVEIN h, LPMMTIME p, UINT s) { if (!o_WaveInGetPosition) return MMSYSERR_ERROR; return o_WaveInGetPosition(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveInGetID(HWAVEIN h, LPUINT p) { if (!o_WaveInGetID) return MMSYSERR_ERROR; return o_WaveInGetID(h, p); }
__declspec(dllexport) MMRESULT WINAPI waveInGetErrorTextA(MMRESULT e, LPSTR p, UINT s) { if (!LoadOriginal() || !o_WaveInGetErrorTextA) return MMSYSERR_ERROR; return o_WaveInGetErrorTextA(e, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveInGetErrorTextW(MMRESULT e, LPWSTR p, UINT s) { if (!LoadOriginal() || !o_WaveInGetErrorTextW) return MMSYSERR_ERROR; return o_WaveInGetErrorTextW(e, p, s); }
__declspec(dllexport) MMRESULT WINAPI waveInMessage(HWAVEIN h, UINT m, DWORD_PTR p1, DWORD_PTR p2) { if (!o_WaveInMessage) return MMSYSERR_ERROR; return o_WaveInMessage(h, m, p1, p2); }

__declspec(dllexport) BOOL WINAPI PlaySoundA(LPCSTR p, HMODULE m, DWORD f) { if (!LoadOriginal() || !o_PlaySoundA) return FALSE; return o_PlaySoundA(p, m, f); }
__declspec(dllexport) BOOL WINAPI PlaySoundW(LPCWSTR p, HMODULE m, DWORD f) { if (!LoadOriginal() || !o_PlaySoundW) return FALSE; return o_PlaySoundW(p, m, f); }
__declspec(dllexport) BOOL WINAPI sndPlaySoundA(LPCSTR p, UINT f) { if (!LoadOriginal() || !o_SndPlaySoundA) return FALSE; return o_SndPlaySoundA(p, f); }
__declspec(dllexport) BOOL WINAPI sndPlaySoundW(LPCWSTR p, UINT f) { if (!LoadOriginal() || !o_SndPlaySoundW) return FALSE; return o_SndPlaySoundW(p, f); }

__declspec(dllexport) UINT WINAPI joyGetNumDevs(void) { if (!LoadOriginal() || !o_JoyGetNumDevs) return 0; return o_JoyGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI joyGetDevCapsA(UINT i, LPJOYCAPSA p, UINT s) { if (!LoadOriginal() || !o_JoyGetDevCapsA) return MMSYSERR_ERROR; return o_JoyGetDevCapsA(i, p, s); }
__declspec(dllexport) MMRESULT WINAPI joyGetDevCapsW(UINT i, LPJOYCAPSW p, UINT s) { if (!LoadOriginal() || !o_JoyGetDevCapsW) return MMSYSERR_ERROR; return o_JoyGetDevCapsW(i, p, s); }
__declspec(dllexport) MMRESULT WINAPI joyGetPos(UINT i, LPJOYINFO p) { if (!LoadOriginal() || !o_JoyGetPos) return MMSYSERR_ERROR; return o_JoyGetPos(i, p); }
__declspec(dllexport) MMRESULT WINAPI joyGetPosEx(UINT i, LPJOYINFOEX p) { if (!LoadOriginal() || !o_JoyGetPosEx) return MMSYSERR_ERROR; return o_JoyGetPosEx(i, p); }
__declspec(dllexport) MMRESULT WINAPI joyGetThreshold(UINT i, LPUINT p) { if (!LoadOriginal() || !o_JoyGetThreshold) return MMSYSERR_ERROR; return o_JoyGetThreshold(i, p); }
__declspec(dllexport) MMRESULT WINAPI joySetThreshold(UINT i, UINT t) { if (!LoadOriginal() || !o_JoySetThreshold) return MMSYSERR_ERROR; return o_JoySetThreshold(i, t); }
__declspec(dllexport) MMRESULT WINAPI joySetCapture(HWND h, UINT i, UINT p, BOOL c) { if (!LoadOriginal() || !o_JoySetCapture) return MMSYSERR_ERROR; return o_JoySetCapture(h, i, p, c); }
__declspec(dllexport) MMRESULT WINAPI joyReleaseCapture(UINT i) { if (!LoadOriginal() || !o_JoyReleaseCapture) return MMSYSERR_ERROR; return o_JoyReleaseCapture(i); }

__declspec(dllexport) UINT WINAPI midiOutGetNumDevs(void) { if (!LoadOriginal() || !o_MidiOutGetNumDevs) return 0; return o_MidiOutGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI midiOutGetDevCapsA(UINT i, LPMIDIOUTCAPSA p, UINT s) { if (!LoadOriginal() || !o_MidiOutGetDevCapsA) return MMSYSERR_ERROR; return o_MidiOutGetDevCapsA(i, p, s); }
__declspec(dllexport) MMRESULT WINAPI midiOutGetDevCapsW(UINT i, LPMIDIOUTCAPSW p, UINT s) { if (!LoadOriginal() || !o_MidiOutGetDevCapsW) return MMSYSERR_ERROR; return o_MidiOutGetDevCapsW(i, p, s); }
__declspec(dllexport) MMRESULT WINAPI midiOutOpen(LPHMIDIOUT p, UINT i, DWORD_PTR c, DWORD_PTR d, DWORD f) { if (!LoadOriginal() || !o_MidiOutOpen) return MMSYSERR_ERROR; return o_MidiOutOpen(p, i, c, d, f); }
__declspec(dllexport) MMRESULT WINAPI midiOutClose(HMIDIOUT h) { if (!o_MidiOutClose) return MMSYSERR_ERROR; return o_MidiOutClose(h); }
__declspec(dllexport) MMRESULT WINAPI midiOutShortMsg(HMIDIOUT h, DWORD m) { if (!o_MidiOutShortMsg) return MMSYSERR_ERROR; return o_MidiOutShortMsg(h, m); }
__declspec(dllexport) MMRESULT WINAPI midiOutLongMsg(HMIDIOUT h, LPMIDIHDR p, UINT s) { if (!o_MidiOutLongMsg) return MMSYSERR_ERROR; return o_MidiOutLongMsg(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI midiOutReset(HMIDIOUT h) { if (!o_MidiOutReset) return MMSYSERR_ERROR; return o_MidiOutReset(h); }
__declspec(dllexport) MMRESULT WINAPI midiOutPrepareHeader(HMIDIOUT h, LPMIDIHDR p, UINT s) { if (!o_MidiOutPrepareHeader) return MMSYSERR_ERROR; return o_MidiOutPrepareHeader(h, p, s); }
__declspec(dllexport) MMRESULT WINAPI midiOutUnprepareHeader(HMIDIOUT h, LPMIDIHDR p, UINT s) { if (!o_MidiOutUnprepareHeader) return MMSYSERR_ERROR; return o_MidiOutUnprepareHeader(h, p, s); }

__declspec(dllexport) UINT WINAPI auxGetNumDevs(void) { if (!LoadOriginal() || !o_AuxGetNumDevs) return 0; return o_AuxGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI auxGetDevCapsA(UINT i, LPAUXCAPSA p, UINT s) { if (!LoadOriginal() || !o_AuxGetDevCapsA) return MMSYSERR_ERROR; return o_AuxGetDevCapsA(i, p, s); }
__declspec(dllexport) MMRESULT WINAPI auxGetDevCapsW(UINT i, LPAUXCAPSW p, UINT s) { if (!LoadOriginal() || !o_AuxGetDevCapsW) return MMSYSERR_ERROR; return o_AuxGetDevCapsW(i, p, s); }
__declspec(dllexport) MMRESULT WINAPI auxGetVolume(UINT i, LPDWORD p) { if (!LoadOriginal() || !o_AuxGetVolume) return MMSYSERR_ERROR; return o_AuxGetVolume(i, p); }
__declspec(dllexport) MMRESULT WINAPI auxSetVolume(UINT i, DWORD v) { if (!LoadOriginal() || !o_AuxSetVolume) return MMSYSERR_ERROR; return o_AuxSetVolume(i, v); }
__declspec(dllexport) MMRESULT WINAPI auxOutMessage(UINT i, UINT m, DWORD_PTR p1, DWORD_PTR p2) { if (!LoadOriginal() || !o_AuxOutMessage) return MMSYSERR_ERROR; return o_AuxOutMessage(i, m, p1, p2); }

__declspec(dllexport) UINT WINAPI mixerGetNumDevs(void) { if (!LoadOriginal() || !o_MixerGetNumDevs) return 0; return o_MixerGetNumDevs(); }
__declspec(dllexport) MMRESULT WINAPI mixerOpen(LPHMIXER p, UINT i, DWORD_PTR c, DWORD_PTR d, DWORD f) { if (!LoadOriginal() || !o_MixerOpen) return MMSYSERR_ERROR; return o_MixerOpen(p, i, c, d, f); }
__declspec(dllexport) MMRESULT WINAPI mixerClose(HMIXER h) { if (!o_MixerClose) return MMSYSERR_ERROR; return o_MixerClose(h); }
__declspec(dllexport) MMRESULT WINAPI mixerGetDevCapsA(UINT i, LPMIXERCAPSA p, UINT s) { if (!LoadOriginal() || !o_MixerGetDevCapsA) return MMSYSERR_ERROR; return o_MixerGetDevCapsA(i, p, s); }
__declspec(dllexport) MMRESULT WINAPI mixerGetDevCapsW(UINT i, LPMIXERCAPSW p, UINT s) { if (!LoadOriginal() || !o_MixerGetDevCapsW) return MMSYSERR_ERROR; return o_MixerGetDevCapsW(i, p, s); }
__declspec(dllexport) MMRESULT WINAPI mixerGetLineInfoA(HMIXEROBJ h, LPMIXERLINEA p, DWORD f) { if (!LoadOriginal() || !o_MixerGetLineInfoA) return MMSYSERR_ERROR; return o_MixerGetLineInfoA(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mixerGetLineInfoW(HMIXEROBJ h, LPMIXERLINEW p, DWORD f) { if (!LoadOriginal() || !o_MixerGetLineInfoW) return MMSYSERR_ERROR; return o_MixerGetLineInfoW(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mixerGetLineControlsA(HMIXEROBJ h, LPMIXERLINECONTROLSA p, DWORD f) { if (!LoadOriginal() || !o_MixerGetLineControlsA) return MMSYSERR_ERROR; return o_MixerGetLineControlsA(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mixerGetLineControlsW(HMIXEROBJ h, LPMIXERLINECONTROLSW p, DWORD f) { if (!LoadOriginal() || !o_MixerGetLineControlsW) return MMSYSERR_ERROR; return o_MixerGetLineControlsW(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mixerGetControlDetailsA(HMIXEROBJ h, LPMIXERCONTROLDETAILS p, DWORD f) { if (!LoadOriginal() || !o_MixerGetControlDetailsA) return MMSYSERR_ERROR; return o_MixerGetControlDetailsA(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mixerGetControlDetailsW(HMIXEROBJ h, LPMIXERCONTROLDETAILS p, DWORD f) { if (!LoadOriginal() || !o_MixerGetControlDetailsW) return MMSYSERR_ERROR; return o_MixerGetControlDetailsW(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mixerSetControlDetails(HMIXEROBJ h, LPMIXERCONTROLDETAILS p, DWORD f) { if (!LoadOriginal() || !o_MixerSetControlDetails) return MMSYSERR_ERROR; return o_MixerSetControlDetails(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mixerGetID(HMIXEROBJ h, PUINT p, DWORD f) { if (!LoadOriginal() || !o_MixerGetID) return MMSYSERR_ERROR; return o_MixerGetID(h, p, f); }
__declspec(dllexport) DWORD WINAPI mixerMessage(HMIXER h, UINT m, DWORD_PTR p1, DWORD_PTR p2) { if (!LoadOriginal() || !o_MixerMessage) return MMSYSERR_ERROR; return o_MixerMessage(h, m, p1, p2); }

__declspec(dllexport) MCIERROR WINAPI mciSendCommandA(MCIDEVICEID i, UINT m, DWORD_PTR p1, DWORD_PTR p2) { if (!LoadOriginal() || !o_MciSendCommandA) return MCIERR_DEVICE_NOT_INSTALLED; return o_MciSendCommandA(i, m, p1, p2); }
__declspec(dllexport) MCIERROR WINAPI mciSendCommandW(MCIDEVICEID i, UINT m, DWORD_PTR p1, DWORD_PTR p2) { if (!LoadOriginal() || !o_MciSendCommandW) return MCIERR_DEVICE_NOT_INSTALLED; return o_MciSendCommandW(i, m, p1, p2); }
__declspec(dllexport) MCIERROR WINAPI mciSendStringA(LPCSTR c, LPSTR r, UINT l, HWND h) { if (!LoadOriginal() || !o_MciSendStringA) return MCIERR_DEVICE_NOT_INSTALLED; return o_MciSendStringA(c, r, l, h); }
__declspec(dllexport) MCIERROR WINAPI mciSendStringW(LPCWSTR c, LPWSTR r, UINT l, HWND h) { if (!LoadOriginal() || !o_MciSendStringW) return MCIERR_DEVICE_NOT_INSTALLED; return o_MciSendStringW(c, r, l, h); }
__declspec(dllexport) BOOL WINAPI mciGetErrorStringA(MCIERROR e, LPSTR p, UINT s) { if (!LoadOriginal() || !o_MciGetErrorStringA) return FALSE; return o_MciGetErrorStringA(e, p, s); }
__declspec(dllexport) BOOL WINAPI mciGetErrorStringW(MCIERROR e, LPWSTR p, UINT s) { if (!LoadOriginal() || !o_MciGetErrorStringW) return FALSE; return o_MciGetErrorStringW(e, p, s); }
__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDA(LPCSTR p) { if (!LoadOriginal() || !o_MciGetDeviceIDA) return 0; return o_MciGetDeviceIDA(p); }
__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDW(LPCWSTR p) { if (!LoadOriginal() || !o_MciGetDeviceIDW) return 0; return o_MciGetDeviceIDW(p); }
__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDFromElementIDA(DWORD e, LPCSTR t) { if (!LoadOriginal() || !o_MciGetDeviceIDFromElementIDA) return 0; return o_MciGetDeviceIDFromElementIDA(e, t); }
__declspec(dllexport) MCIDEVICEID WINAPI mciGetDeviceIDFromElementIDW(DWORD e, LPCWSTR t) { if (!LoadOriginal() || !o_MciGetDeviceIDFromElementIDW) return 0; return o_MciGetDeviceIDFromElementIDW(e, t); }
__declspec(dllexport) BOOL WINAPI mciSetYieldProc(MCIDEVICEID i, YIELDPROC p, DWORD d) { if (!LoadOriginal() || !o_MciSetYieldProc) return FALSE; return o_MciSetYieldProc(i, p, d); }
__declspec(dllexport) YIELDPROC WINAPI mciGetYieldProc(MCIDEVICEID i, LPDWORD p) { if (!LoadOriginal() || !o_MciGetYieldProc) return NULL; return o_MciGetYieldProc(i, p); }
__declspec(dllexport) HTASK WINAPI mciGetCreatorTask(MCIDEVICEID i) { if (!LoadOriginal() || !o_MciGetCreatorTask) return NULL; return o_MciGetCreatorTask(i); }
__declspec(dllexport) BOOL WINAPI mciExecute(LPCSTR c) { if (!LoadOriginal() || !o_MciExecute) return FALSE; return o_MciExecute(c); }

__declspec(dllexport) HMMIO WINAPI mmioOpenA(LPSTR f, LPMMIOINFO i, DWORD o) { if (!LoadOriginal() || !o_MmioOpenA) return NULL; return o_MmioOpenA(f, i, o); }
__declspec(dllexport) HMMIO WINAPI mmioOpenW(LPWSTR f, LPMMIOINFO i, DWORD o) { if (!LoadOriginal() || !o_MmioOpenW) return NULL; return o_MmioOpenW(f, i, o); }
__declspec(dllexport) MMRESULT WINAPI mmioClose(HMMIO h, UINT f) { if (!o_MmioClose) return MMSYSERR_ERROR; return o_MmioClose(h, f); }
__declspec(dllexport) LONG WINAPI mmioRead(HMMIO h, HPSTR p, LONG c) { if (!o_MmioRead) return -1; return o_MmioRead(h, p, c); }
__declspec(dllexport) LONG WINAPI mmioWrite(HMMIO h, const char* p, LONG c) { if (!o_MmioWrite) return -1; return o_MmioWrite(h, p, c); }
__declspec(dllexport) LONG WINAPI mmioSeek(HMMIO h, LONG o, int i) { if (!o_MmioSeek) return -1; return o_MmioSeek(h, o, i); }
__declspec(dllexport) MMRESULT WINAPI mmioGetInfo(HMMIO h, LPMMIOINFO p, UINT f) { if (!o_MmioGetInfo) return MMSYSERR_ERROR; return o_MmioGetInfo(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mmioSetInfo(HMMIO h, LPCMMIOINFO p, UINT f) { if (!o_MmioSetInfo) return MMSYSERR_ERROR; return o_MmioSetInfo(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mmioSetBuffer(HMMIO h, LPSTR p, LONG s, UINT f) { if (!o_MmioSetBuffer) return MMSYSERR_ERROR; return o_MmioSetBuffer(h, p, s, f); }
__declspec(dllexport) MMRESULT WINAPI mmioFlush(HMMIO h, UINT f) { if (!o_MmioFlush) return MMSYSERR_ERROR; return o_MmioFlush(h, f); }
__declspec(dllexport) MMRESULT WINAPI mmioAdvance(HMMIO h, LPMMIOINFO p, UINT f) { if (!o_MmioAdvance) return MMSYSERR_ERROR; return o_MmioAdvance(h, p, f); }
__declspec(dllexport) LPMMIOPROC WINAPI mmioInstallIOProcA(FOURCC c, LPMMIOPROC p, DWORD f) { if (!LoadOriginal() || !o_MmioInstallIOProcA) return NULL; return o_MmioInstallIOProcA(c, p, f); }
__declspec(dllexport) LPMMIOPROC WINAPI mmioInstallIOProcW(FOURCC c, LPMMIOPROC p, DWORD f) { if (!LoadOriginal() || !o_MmioInstallIOProcW) return NULL; return o_MmioInstallIOProcW(c, p, f); }
__declspec(dllexport) FOURCC WINAPI mmioStringToFOURCCA(LPCSTR s, UINT f) { if (!LoadOriginal() || !o_MmioStringToFOURCCA) return 0; return o_MmioStringToFOURCCA(s, f); }
__declspec(dllexport) FOURCC WINAPI mmioStringToFOURCCW(LPCWSTR s, UINT f) { if (!LoadOriginal() || !o_MmioStringToFOURCCW) return 0; return o_MmioStringToFOURCCW(s, f); }
__declspec(dllexport) MMRESULT WINAPI mmioDescend(HMMIO h, LPMMCKINFO p, const MMCKINFO* c, UINT f) { if (!o_MmioDescend) return MMSYSERR_ERROR; return o_MmioDescend(h, p, c, f); }
__declspec(dllexport) MMRESULT WINAPI mmioAscend(HMMIO h, LPMMCKINFO p, UINT f) { if (!o_MmioAscend) return MMSYSERR_ERROR; return o_MmioAscend(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mmioCreateChunk(HMMIO h, LPMMCKINFO p, UINT f) { if (!o_MmioCreateChunk) return MMSYSERR_ERROR; return o_MmioCreateChunk(h, p, f); }
__declspec(dllexport) MMRESULT WINAPI mmioRenameA(LPCSTR o, LPCSTR n, LPCMMIOINFO i, DWORD f) { if (!LoadOriginal() || !o_MmioRename) return MMSYSERR_ERROR; return o_MmioRename(o, n, i, f); }
__declspec(dllexport) LRESULT WINAPI mmioSendMessage(HMMIO h, UINT m, LPARAM p1, LPARAM p2) { if (!o_MmioSendMessage) return 0; return o_MmioSendMessage(h, m, p1, p2); }

} // extern "C"

// ============================================
// DLL ENTRY
// ============================================
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
