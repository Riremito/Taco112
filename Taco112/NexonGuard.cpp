#include"Taco112.h"
#include"Redirector.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		Redirector_Start(hinstDLL); // auth hook
		Taco112_Install();
	}
	return TRUE;
}

// NexonGuard.aes exports
DWORD __stdcall FakeExport1() {
	return 0;
}

DWORD __stdcall FakeExport2(DWORD v1, DWORD v2, DWORD v3) {
	return 0;
}