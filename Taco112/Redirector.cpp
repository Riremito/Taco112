#include<ws2spi.h> // do not move this include
#include"Redirector.h"
#pragma comment(lib, "ws2_32.lib")

bool useAuthHook = true;
WSPPROC_TABLE g_ProcTable = { 0 }; // AuthHook
DWORD PrivateServerIP = 0x0100007F; // 127.0.0.1
DWORD OfficialServerIP = 0;


void Redirect(sockaddr_in *name) {
	// port
	WORD wPort = ntohs(name->sin_port);
	// original ip
	OfficialServerIP = name->sin_addr.S_un.S_addr;
	std::wstring server = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);
	// redirect
	*(DWORD *)&name->sin_addr.S_un = PrivateServerIP;
	// private server ip
	std::wstring pserver = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);

	DEBUG(L"[Redirect][" + server + L" -> " + pserver + L"]");
}

void PeerNameBypass(sockaddr_in *name) {
	// port
	WORD wPort = ntohs(name->sin_port);
	// original ip
	std::wstring server = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);
	// fake ip
	*(DWORD *)&name->sin_addr.S_un = OfficialServerIP;
	// official server ip
	std::wstring oserver = std::to_wstring(name->sin_addr.S_un.S_un_b.s_b1) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b2) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b3) + L"." + std::to_wstring(name->sin_addr.S_un.S_un_b.s_b4) + L":" + std::to_wstring(wPort);

	DEBUG(L"[PeerNameBypass][" + server + L" -> " + oserver + L"]");
}

// nexon is watching private server players
bool IsWebPort(sockaddr_in *name) {
	WORD wPort = ntohs(name->sin_port);

	if (wPort == 80 || wPort == 443) {
		return true;
	}

	return false;
}

int WINAPI WSPGetPeerName_Hook(SOCKET s, sockaddr_in *name, LPINT namelen, LPINT lpErrno) {
	int ret = g_ProcTable.lpWSPGetPeerName(s, (sockaddr *)name, namelen, lpErrno);

	if (ret == SOCKET_ERROR) {
		return ret;
	}

	if (IsWebPort(name)) {
		return SOCKET_ERROR;
	}

	PeerNameBypass(name);

	return  ret;
}

int WINAPI WSPConnect_Hook(SOCKET s, sockaddr_in *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno) {

	if (IsWebPort(name)) {
		return SOCKET_ERROR;
	}

	Redirect(name);
	return g_ProcTable.lpWSPConnect(s, (sockaddr *)name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
}

decltype(WSPStartup) *_WSPStartup = NULL;
int WINAPI WSPStartup_Hook(WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFOW lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable) {
	int ret = _WSPStartup(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProcTable);

	g_ProcTable = *lpProcTable;

	lpProcTable->lpWSPConnect = (decltype(lpProcTable->lpWSPConnect))WSPConnect_Hook;
	lpProcTable->lpWSPGetPeerName = (decltype(lpProcTable->lpWSPGetPeerName))WSPGetPeerName_Hook;
	return ret;
}

bool Redirector_Hook() {
	HMODULE hDll = GetModuleHandleW(L"mswsock.dll");
	if (!hDll) {
		hDll = LoadLibraryW(L"mswsock.dll");
	}

	if (!hDll) {
		DEBUG(L"failed to load mswsock.dll");
		return false;
	}

	SHookNT(mswsock.dll, WSPStartup);
	return true;
}

bool Redirector_Conf(HMODULE hDll) {
	Config conf(INI_FILE_NAME, hDll);
	std::wstring wServerIP, wAuthHook, wFixedPortNumber;

	bool check = true;
	check &= conf.Read(DLL_NAME, L"ServerIP", wServerIP);

	if (!check) {
		DEBUG(L"use default IP");
		return false;
	}

	DWORD dwIP[4] = { 0 };
	swscanf_s(wServerIP.c_str(), L"%d.%d.%d.%d", &dwIP[0], &dwIP[1], &dwIP[2], &dwIP[3]);

	BYTE *ip_bytes = (BYTE *)&PrivateServerIP;
	for (int i = 0; i < 4; i++) {
		ip_bytes[i] = (BYTE)dwIP[i];
	}

	DEBUG(L"ServerIP = " + wServerIP);
	return true;
}

bool Redirector_Start(HMODULE hDll) {
	Redirector_Conf(hDll);
	Redirector_Hook();
	return true;
}