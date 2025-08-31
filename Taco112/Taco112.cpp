#include"Taco112.h"
#include<intrin.h>
#pragma intrinsic(_ReturnAddress)

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

decltype(GetModuleHandleA) *_GetModuleHandleA;
HMODULE WINAPI GetModuleHandleA_Hook(LPCSTR lpModuleName) {
	if (SimpleHook::IsCallerEXE(_ReturnAddress())) {
		if (lpModuleName && strcmp(lpModuleName, "ehsvc.dll") == 0) {
			return GetModuleHandleW(NULL); // fake
		}
	}
	return _GetModuleHandleA(lpModuleName);
}

// GMS126 Addresses.
// 004F4B20 | HS ptr check
// 00E1F990 | CSecurityClient::InitModule
// 00E1F350 | CSecurityClient::StartModule
// 006E6B30 | RemoveMSCRC_Main (IWzGr2D::RenderFrame)
// 00D9074D | RemoveMSCRC_Main (CWvsApp::Run LeaveVM)
// 00D8989A | Check_Mutex
// 0042E9A0 | ?ShowADBalloon@@YAHABUADBalloonParam@@@Z
// 008D0920 | ?ShowStartUpWnd@@YAHABUStartUpWndParam@@@Z


ULONG_PTR uHS_PtrAddr = 0;
bool HSPtrScanner(ULONG_PTR addr) {
	if (*(DWORD *)(addr + 0x04) == uHS_PtrAddr) {
		return true;
	}
	return false;
}

std::vector<ULONG_PTR> crash_code_list;
bool CrashCodeScanner(ULONG_PTR addr) {
	crash_code_list.push_back(addr);
	return false;
}

bool Taco112_Install() {
	Rosemary r;
	// ProcessPacket inside.
	ULONG_PTR uHS_PtrRef = r.Scan(L"8B 0D ?? ?? ?? ?? 85 C9 74 ?? 8B 44 24 ?? 50 E8 ?? ?? ?? ?? EB");
	ULONG_PTR uHS_PtrCheck = 0;
	if (uHS_PtrRef) {
		uHS_PtrAddr = *(DWORD *)(uHS_PtrRef + 0x02);
		// GMS126, 004F4B20
		uHS_PtrCheck = r.Scan(L"33 C0 39 05 ?? ?? ?? ?? 0F 95 C0 C3", HSPtrScanner);
	}
	SCANRES(uHS_PtrRef);
	SCANRES(uHS_PtrAddr);
	SCANRES(uHS_PtrCheck);

	ULONG_PTR uCSecurityClient_InitModule = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 33 DB 53 8B E9");
	ULONG_PTR uCSecurityClient_StartModule = r.Scan(L"83 EC ?? A1 ?? ?? ?? ?? 33 C4 89 44 24 ?? 56 6A 00 8B F1 E9");

	SCANRES(uCSecurityClient_InitModule);
	SCANRES(uCSecurityClient_StartModule);
	if (!uHS_PtrCheck || !uCSecurityClient_InitModule || !uCSecurityClient_StartModule){
		DEBUG(L"failed to get address.");
		return false;
	}
	r.Patch(uHS_PtrCheck, L"31 C0 C3");
	r.Patch(uCSecurityClient_InitModule, L"31 C0 C3");
	r.Patch(uCSecurityClient_StartModule, L"31 C0 C3");

	// crash fix.
	r.Scan(L"60 03 C3 03 C1 03 C2 74 02 75 25 EB 18 BE 04 74 76 F7 36 51 2C B3 96 DD BF 57 C0 10 75 43 54 4F 92 8B 09 30 F3 D4 25 10 25 15 52 05 05 58 6F CA 61", CrashCodeScanner);
	for (ULONG_PTR uCrashCodeAddr : crash_code_list) {
		r.Patch(uCrashCodeAddr, L"EB 2F");
		SCANRES(uCrashCodeAddr);
	}
	// ehsvc.dll checks
	SHook(GetModuleHandleA);
	// MSCRC
	gRenderFrame = r.Scan(L"56 57 8B F9 8B 07 8B 48 1C 57 FF D1 8B F0 85 F6 7D 0E 68 ?? ?? ?? ?? 57 56 E8 ?? ?? ?? ?? 8B C6 5F 5E C3");
	gRun_Leave_VM = r.Scan(L"6A 01 FF 15 ?? ?? ?? ?? 8B ?? 08 83 ?? 00 75");
	SHookFunction(RenderFrame, gRenderFrame);
	DEBUG(L"RemoveCRC_Run: " + DWORDtoString(gRenderFrame) + L" -> " + DWORDtoString(gRun_Leave_VM));

	// ShowADBalloon
	r.Patch(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 83 EC 64 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 44 24 78 64 A3 00 00 00 00 33 ?? 5? FF 15", L"B8 01 00 00 00 C3");
	// ShowStartUpWnd
	r.Patch(L"83 EC ?? 55 56 33 ED 55 FF 15 ?? ?? ?? ?? 8B 74 24 ?? 89 35 ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 8D 4C 24 ?? 51 C7", L"B8 01 00 00 00 C3");
	return true;
}


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
			Taco112_Install();
		}
	}

	return hRet;
}

decltype(GetCommandLineA) *_GetCommandLineA = NULL;
std::string fake_cmd_line;
LPSTR WINAPI GetCommandLineA_Hook() {
	return (LPSTR)fake_cmd_line.c_str();
}

bool Taco112_Start() {
	SHook(GetCommandLineA);
	fake_cmd_line = _GetCommandLineA();
	fake_cmd_line += " GameLaunching";
	SHook(CreateMutexExW);
	return true;
}