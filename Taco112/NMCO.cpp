#include"NMCO.h"
/*
	before :
	EncodeStr("password"); // from arguments
	EncodeStr("passport"); // from CNMCOClientObject::GetNexonPassport

	after :
	EncodeStr("maple_id"); // arguments swap.
	EncodeStr("password"); // from CNMCOClientObject::GetNexonPassport Hook
*/
char gPassword[256] = {};
int (__thiscall *_CLogin__SendCheckPasswordPacket)(void *ecx, char *maple_id, char *password) = NULL;
int __fastcall CLogin__SendCheckPasswordPacket_Hook(void *ecx, void *edx, char *maple_id, char *password) {
	// save password to use this as passport.
	int password_length = strlen(password);
	memset(gPassword, sizeof(gPassword), 0);
	memcpy_s(gPassword, password_length + 1, password, password_length + 1);
	// swap maple_id and password to change EncodeStr order.
	int ret = _CLogin__SendCheckPasswordPacket(ecx, password, maple_id);
	// clear password.
	memset(gPassword, sizeof(gPassword), 0);
	return ret;
}

int (__thiscall *_CNMCOClientObject__LoginAuth)(void *ecx, void *v1, void *v2,  void *v3,  void *v4) = NULL;
int __fastcall CNMCOClientObject__LoginAuth_Hook(void *ecx, void *edx, void *v1, void *v2, void *v3, void *v4) {
	// set error code to 0.
	return 0;
}

char* (__thiscall *_CNMCOClientObject__GetNexonPassport)(void *ecx, char *passport) = NULL;
char* __fastcall CNMCOClientObject__GetNexonPassport_Hook(void *ecx, void *edx, char *passport) {
	// use passport as password buffer.
	int password_length = strlen(gPassword);
	memcpy_s(passport, password_length + 1, gPassword, password_length + 1);
	return passport;
}

// 006F3630
int (__thiscall *_CLogin__SendCheckPasswordPacket126)(void *ecx, void *v1, char *maple_id, char *password) = NULL;
int __fastcall CLogin__SendCheckPasswordPacket126_Hook(void *ecx, void *edx, void *v1, char *maple_id, char *password) {
	// save password to use this as passport.
	int password_length = strlen(password);
	memset(gPassword, sizeof(gPassword), 0);
	memcpy_s(gPassword, password_length + 1, password, password_length + 1);
	// swap maple_id and password to change EncodeStr order.
	int ret = _CLogin__SendCheckPasswordPacket126(ecx, v1, password, maple_id);
	// clear password.
	memset(gPassword, sizeof(gPassword), 0);
	return ret;
}

// 007C2F00
int (__thiscall *_CNMCOClientObject__LoginAuth126)(void *ecx, void *v1, void *v2, void *v3, void *v4, void *v5) = NULL;
int __fastcall CNMCOClientObject__LoginAuth126_Hook(void *ecx, void *edx, void *v1, void *v2, void *v3, void *v4, void *v5) {
	// set error code to 0.
	return 0;
}

bool NMCO_Hook() {
	Rosemary r;
	// GMS126.
	ULONG_PTR uSendCheckPasswordPacket = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8B F1 83 BE ?? ?? ?? ?? 00 BD 01 00 00 00 89 AC 24 ?? ?? ?? ?? 74");
	ULONG_PTR uLoginAuth = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 56 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8B B4 24 ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 56 52 8B 94 24 ?? ?? ?? ?? 52 51 50 8D 4C 24 1C E8");
	// GMS95-126.
	ULONG_PTR uGetNexonPassport = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 56 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8B B4 24 ?? ?? ?? ?? 8D 4C 24 08 E8 ?? ?? ?? ?? 8D 44 24 08 50 C7 84 24 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 85 C0 74 ?? 68 00 04 00 00");

	SCANRES(uSendCheckPasswordPacket);
	SCANRES(uLoginAuth);
	SCANRES(uGetNexonPassport);
	if (!uSendCheckPasswordPacket || !uLoginAuth || !uGetNexonPassport) {
		return false;
	}

	SHookFunction(CLogin__SendCheckPasswordPacket126, uSendCheckPasswordPacket);
	SHookFunction(CNMCOClientObject__LoginAuth126, uLoginAuth);
	SHookFunction(CNMCOClientObject__GetNexonPassport, uGetNexonPassport);

	/*
	// CLogin::SendCheckPasswordPacket, GMS95 005DB9D0
	SHookFunction(CLogin__SendCheckPasswordPacket, 0x005DB9D0);
	// CNMCOClientObject::LoginAuth GMS95 0066D210
	SHookFunction(CNMCOClientObject__LoginAuth, 0x0066D210);
	// CNMCOClientObject::GetNexonPassport GMS95 0066D320
	SHookFunction(CNMCOClientObject__GetNexonPassport, 0x0066D320);
	*/
	return true;
}