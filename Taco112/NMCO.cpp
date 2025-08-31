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
// save password to use this as passport.
void SetPassword(char *password) {
	int password_length = strlen(password);
	memset(gPassword, sizeof(gPassword), 0);
	memcpy_s(gPassword, password_length + 1, password, password_length + 1);
}

// clear password.
void ClearPassword() {
	memset(gPassword, sizeof(gPassword), 0);
}

// set passport as password buffer.
char* GetPassport(char *passport) {
	int password_length = strlen(gPassword);
	memcpy_s(passport, password_length + 1, gPassword, password_length + 1);
	return passport;
}

// CLogin::SendCheckPasswordPacket
// GMS95, 005DB9D0
int (__thiscall *_CLogin__SendCheckPasswordPacket)(void *, char *, char *) = NULL;
int __fastcall CLogin__SendCheckPasswordPacket_Hook(void *ecx, void *edx, char *maple_id, char *password) {
	SetPassword(password);
	// swap maple_id and password to change EncodeStr order.
	int ret = _CLogin__SendCheckPasswordPacket(ecx, password, maple_id);
	ClearPassword();
	return ret;
}

// CNMCOClientObject::LoginAuth
// GMS95, 0066D210
int (__thiscall *_CNMCOClientObject__LoginAuth)(void *, void *, void *, void *, void *) = NULL;
int __fastcall CNMCOClientObject__LoginAuth_Hook(void *ecx, void *edx, void *v1, void *v2, void *v3, void *v4) {
	// set error code to 0.
	return 0;
}

// CNMCOClientObject::GetNexonPassport
// GMS95, 0066D320
char* (__thiscall *_CNMCOClientObject__GetNexonPassport)(void *, char *) = NULL;
char* __fastcall CNMCOClientObject__GetNexonPassport_Hook(void *ecx, void *edx, char *passport) {
	return GetPassport(passport);
}

// GMS126, 006F3630
int (__thiscall *_CLogin__SendCheckPasswordPacket117)(void *, void *, char *, char *) = NULL;
int __fastcall CLogin__SendCheckPasswordPacket117_Hook(void *ecx, void *edx, void *v1, char *maple_id, char *password) {
	SetPassword(password);
	int ret = _CLogin__SendCheckPasswordPacket117(ecx, v1, password, maple_id);
	ClearPassword();
	return ret;
}

// GMS126, 007C2F00
int (__thiscall *_CNMCOClientObject__LoginAuth111)(void *, void *, void *, void *, void *, void *) = NULL;
int __fastcall CNMCOClientObject__LoginAuth111_Hook(void *ecx, void *edx, void *v1, void *v2, void *v3, void *v4, void *v5) {
	return 0;
}

bool NMCO_Hook(Rosemary &r) {
	ULONG_PTR uSendCheckPasswordPacket95 = 0;
	ULONG_PTR uSendCheckPasswordPacket117 = 0;
	ULONG_PTR uLoginAuth95 = 0;
	ULONG_PTR uLoginAuth111 = 0;
	ULONG_PTR uGetNexonPassport95 = 0;

	uSendCheckPasswordPacket95 = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8B ?? 24 ?? ?? ?? ?? 8B ?? 24 ?? ?? ?? ?? 8B F1");
	if (!uSendCheckPasswordPacket95) {
		uSendCheckPasswordPacket117 = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8B F1 83 BE ?? ?? ?? ?? 00 BD 01 00 00 00 89 AC 24 ?? ?? ?? ?? 74");
	}

	uLoginAuth95 = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8B 94 24 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 52 8B 94 24 ?? ?? ?? ?? 52 51 50 8D 4C 24 14 E8");
	if (!uLoginAuth95) {
		uLoginAuth111 = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 56 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8B B4 24 ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 56 52 8B 94 24 ?? ?? ?? ?? 52 51 50 8D 4C 24 1C E8");
	}

	uGetNexonPassport95 = r.Scan(L"6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 56 A1 ?? ?? ?? ?? 33 C4 50 8D 84 24 ?? ?? ?? ?? 64 A3 00 00 00 00 8B B4 24 ?? ?? ?? ?? 8D 4C 24 08 E8 ?? ?? ?? ?? 8D 44 24 08 50 C7 84 24 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 85 C0 74 ?? 68 00 04 00 00");

	SCANRES(uSendCheckPasswordPacket95);
	SCANRES(uSendCheckPasswordPacket117);
	SCANRES(uLoginAuth95);
	SCANRES(uLoginAuth111);
	SCANRES(uGetNexonPassport95);

	if (!uSendCheckPasswordPacket95 && !uSendCheckPasswordPacket117) {
		return false;
	}
	if (!uLoginAuth95 && !uLoginAuth111) {
		return false;
	}
	if (!uGetNexonPassport95) {
		return false;
	}
	if (uSendCheckPasswordPacket95) {
		// arguments 2 (ret 0008)
		SHookFunction(CLogin__SendCheckPasswordPacket, uSendCheckPasswordPacket95);
	}
	if (uSendCheckPasswordPacket117) {
		// arguments 3 (ret 000C)
		SHookFunction(CLogin__SendCheckPasswordPacket117, uSendCheckPasswordPacket117);
	}
	if (uLoginAuth95) {
		// arguments 4 (ret 0010)
		SHookFunction(CNMCOClientObject__LoginAuth, uLoginAuth95);
	}
	if (uLoginAuth111) {
		// arguments 5 (ret 0014)
		SHookFunction(CNMCOClientObject__LoginAuth111, uLoginAuth111);
	}
	SHookFunction(CNMCOClientObject__GetNexonPassport, uGetNexonPassport95);
	return true;
}