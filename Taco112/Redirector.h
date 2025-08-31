#ifndef __REDIRECTOR_H__
#define __REDIRECTOR_H__

#include"../Share/Simple/Simple.h"
#include"../Share/Hook/SimpleHook.h"

#define DLL_NAME L"NexonGuard"
#define INI_FILE_NAME DLL_NAME".ini"

bool Redirector_Start(HMODULE hDll);

#endif