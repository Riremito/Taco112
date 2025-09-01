#include"Taco112.h"
#include"NMCO.h"
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)

// GMS126 Addresses.
// 004F4B20 | TSingleton<CSecurityClient>::IsInstantiated
// 00E1F990 | CSecurityClient::InitModule
// 00E1F350 | CSecurityClient::StartModule
// 006E6B30 | RemoveMSCRC_Main (IWzGr2D::RenderFrame)
// 00D9074D | RemoveMSCRC_Main (CWvsApp::Run LeaveVM)
// 00D8989A | Check_Mutex
// 0042E9A0 | ShowADBalloon
// 008D0920 | ShowStartUpWnd

// MSCRC skip
ULONG_PTR gRenderFrame = 0;
ULONG_PTR gRun_Leave_VM = 0;
void(__thiscall *_RenderFrame)(void *ecx);
void __fastcall RenderFrame_Hook(void *ecx, void *edx) {
	// call IWzGr2D::RenderFrame
	if ((((BYTE *)_ReturnAddress())[-0x05] == 0xE8)) {
		ULONG_PTR call_function = (ULONG_PTR)&((BYTE *)_ReturnAddress())[-0x05] + *(signed long *)&((BYTE *)_ReturnAddress())[-0x04] + 0x05;

		if (call_function == gRenderFrame) {
			return _RenderFrame(ecx);
		}
	}
	// CWvsApp::Run MSCRC
	*(ULONG_PTR *)_AddressOfReturnAddress() = gRun_Leave_VM;
	return _RenderFrame(ecx);
}

// EHSvc.dll check
decltype(GetModuleHandleA) *_GetModuleHandleA = NULL;
HMODULE WINAPI GetModuleHandleA_Hook(LPCSTR lpModuleName) {
	if (SimpleHook::IsCallerEXE(_ReturnAddress())) {
		if (lpModuleName && strcmp(lpModuleName, "ehsvc.dll") == 0) {
			return GetModuleHandleW(NULL); // fake
		}
	}
	return _GetModuleHandleA(lpModuleName);
}

ULONG_PTR uCSecurityClient__ms_pInstance = 0;
bool HSPtrScanner(ULONG_PTR addr) {
	if (*(DWORD *)(addr + 0x04) == uCSecurityClient__ms_pInstance) {
		return true;
	}
	return false;
}

std::vector<ULONG_PTR> crash_code_list;
bool CrashCodeScanner(ULONG_PTR addr) {
	crash_code_list.push_back(addr);
	return false;
}

bool TacoHook_Main(Rosemary &r) {
	bool isGMS112_mode = false;
	// CClientSocket::ProcessPacket inside.
	ULONG_PTR uHS_PtrRef = r.Scan(L"8B 0D ?? ?? ?? ?? 85 C9 74 ?? 8B 44 24 ?? 50 E8 ?? ?? ?? ?? EB");
	if (!uHS_PtrRef) {
		// GMS95
		uHS_PtrRef = r.Scan(L"8B 0D ?? ?? ?? ?? 85 C9 74 ?? 56 E8 ?? ?? ?? ?? EB ?? 56 8B CB E8");
	}
	ULONG_PTR uCSecurityClient__IsInstantiated = 0;
	if (uHS_PtrRef) {
		// TSingleton<CSecurityClient>::ms_pInstance
		uCSecurityClient__ms_pInstance = *(DWORD *)(uHS_PtrRef + 0x02);
		// TSingleton<CSecurityClient>::IsInstantiated
		// GMS126, 004F4B20
		uCSecurityClient__IsInstantiated = r.Scan(L"33 C0 39 05 ?? ?? ?? ?? 0F 95 C0 C3", HSPtrScanner);
	}
	// CSecurityClient::InitModule
	ULONG_PTR uCSecurityClient_InitModule = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 33 DB 53 8B E9");
	// 83 EC 08 56 8B F1 EB 10 - GMS95 DEVM
	// 83 EC 08 56 8B F1 E9 - GMS95
	if (!uCSecurityClient_InitModule) {
		// GMS112 - themida
		uCSecurityClient_InitModule = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8B E9 E9");
		isGMS112_mode = true;
	}

	// CSecurityClient::StartModule
	ULONG_PTR uCSecurityClient_StartModule = r.Scan(L"83 EC ?? A1 ?? ?? ?? ?? 33 C4 89 44 24 ?? 56 6A 00 8B F1 E9");
	// 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 56 8B F1 EB 10 - GMS95 DEVM
	// 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 56 8B F1 E9 - GMS95
	if (!uCSecurityClient_StartModule) {
		// GMS112 - themida
		uCSecurityClient_StartModule = r.Scan(L"83 EC 30 A1 ?? ?? ?? ?? 33 C4 89 44 24 2C 56 8B F1 E9");
		if (!uCSecurityClient_StartModule) {
			uCSecurityClient_StartModule = r.Scan(L"83 EC 08 56 6A 00 8B F1 E9");
		}
	}
	SCANRES(uHS_PtrRef);
	SCANRES(uCSecurityClient__ms_pInstance);
	SCANRES(uCSecurityClient__IsInstantiated);
	SCANRES(uCSecurityClient_InitModule);
	SCANRES(uCSecurityClient_StartModule);
	if (!uCSecurityClient__IsInstantiated || !uCSecurityClient_InitModule || !uCSecurityClient_StartModule){
		return false;
	}
	// get pushad crash code addresses.
	r.Scan(L"60 03 C3 03 C1 03 C2 74 02 75 25 EB 18 BE 04 74 76 F7 36 51 2C B3 96 DD BF 57 C0 10 75 43 54 4F 92 8B 09 30 F3 D4 25 10 25 15 52 05 05 58 6F CA 61", CrashCodeScanner);
	// MSCRC
	// IWzGr2D::RenderFrame
	gRenderFrame = r.Scan(L"56 57 8B F9 8B 07 8B 48 1C 57 FF D1 8B F0 85 F6 7D 0E 68 ?? ?? ?? ?? 57 56 E8 ?? ?? ?? ?? 8B C6 5F 5E C3");
	// CWvsApp::Run inside.
	gRun_Leave_VM = r.Scan(L"6A 01 FF 15 ?? ?? ?? ?? 8B ?? 08 83 ?? 00 75");
	SCANRES(gRenderFrame);
	SCANRES(gRun_Leave_VM);

	if (!gRenderFrame || !gRun_Leave_VM) {
		return false;
	}

	// HS Removal.
	r.Patch(uCSecurityClient__IsInstantiated, L"31 C0 C3");
	r.Patch(uCSecurityClient_InitModule, L"31 C0 C3");
	r.Patch(uCSecurityClient_StartModule, L"31 C0 C3");
	// CWvsApp::SetUp inside.
	// ehsvc.dll checks Removal.
	SHook(GetModuleHandleA);
	// pushad crash code fix.
	for (ULONG_PTR uCrashCodeAddr : crash_code_list) {
		r.Patch(uCrashCodeAddr, L"EB 2F");
		SCANRES(uCrashCodeAddr);
	}
	// MSCRC Removal.
	SHookFunction(RenderFrame, gRenderFrame);

	if (isGMS112_mode) {
		ULONG_PTR uHideDll = r.Scan(L"55 8B EC 83 EC 08 E9");
		SCANRES(uHideDll);
		if (uHideDll) {
			r.Patch(uHideDll, L"31 C0 C3");
		}
	}
	return true;
}


bool TacoHook_Sub(Rosemary &r) {
	// ShowADBalloon
	r.Patch(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 64 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 78 64 A3 00 00 00 00 33 ?? 5? FF 15", L"B8 01 00 00 00 C3");
	// ShowStartUpWnd
	r.Patch(L"83 EC ?? 55 56 33 ED 55 FF 15 ?? ?? ?? ?? 8B 74 24 ?? 89 35 ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 8D 4C 24 ?? 51 C7", L"B8 01 00 00 00 C3");
	return true;
}

void TacoHook2_Failed(std::wstring error_msg) {
	MessageBoxW(NULL, error_msg.c_str(), L"TacoHook2 is failed.", MB_OK);
	ExitProcess(0);
}

// delay executed.
bool TacoHook2() {
	Rosemary r;
	if (!TacoHook_Main(r)) {
		TacoHook2_Failed(L"TacoHook_Main");
		return false;
	}
	if (!NMCO_Hook(r)) {
		TacoHook2_Failed(L"NMCO_Hook");
		return false;
	}
	TacoHook_Sub(r);
	return true;
}

// Multi Client
#define MUTEX_MAPLE L"WvsClientMtx"
bool IsMapleMutex(LPCWSTR lpName) {
	if (!lpName) {
		return false;
	}

	if (wcsstr(lpName, MUTEX_MAPLE)) {
		return true;
	}

	return false;
}

bool CloseMutex(HANDLE hMutex) {
	HANDLE hDuplicatedMutex = NULL;
	if (DuplicateHandle(GetCurrentProcess(), hMutex, 0, &hDuplicatedMutex, 0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
		CloseHandle(hDuplicatedMutex);
		DEBUG(L"MuliClient: Enabled");
		return true;
	}
	return false;
}

bool bAlreadyLoaded = false;
decltype(CreateMutexExW) *_CreateMutexExW = NULL;
HANDLE WINAPI CreateMutexExW_Hook(LPSECURITY_ATTRIBUTES lpMutexAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess) {
	HANDLE hRet = _CreateMutexExW(lpMutexAttributes, lpName, dwFlags, dwDesiredAccess);

	if (IsMapleMutex(lpName)) {
		CloseMutex(hRet);
		if (!bAlreadyLoaded) {
			bAlreadyLoaded = true;
			DEBUG(L"DelayLoad CreateMutexExW");
			TacoHook2();
		}
	}

	return hRet;
}

decltype(RegCreateKeyExA) *_RegCreateKeyExA = NULL;
LSTATUS APIENTRY RegCreateKeyExA_Hook(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
	if (!bAlreadyLoaded) {
		if (lpSubKey && strstr(lpSubKey, "SOFTWARE\\Wizet\\Maple")) {
			bAlreadyLoaded = true;
			DEBUG(L"DelayLoad RegCreateKeyExA");
			TacoHook2();
		}
	}
	return _RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

// GameLaunching
std::string gFakeCommandLine;
decltype(GetCommandLineA) *_GetCommandLineA = NULL;
LPSTR WINAPI GetCommandLineA_Hook() {
	return (LPSTR)gFakeCommandLine.c_str();
}

bool SetFakeCommandLine() {
	gFakeCommandLine = _GetCommandLineA();
	if (strstr(gFakeCommandLine.c_str(), " GameLaunching")) {
		return false;
	}
	gFakeCommandLine += " GameLaunching";
	return true;
}

bool TacoHook1() {
	SHook(GetCommandLineA);
	// GMS126
	SHook(CreateMutexExW);
	// GMS112
	SHook(RegCreateKeyExA);
	return true;
}

bool Taco112_Install() {
	TacoHook1();
	SetFakeCommandLine();
	return true;
}