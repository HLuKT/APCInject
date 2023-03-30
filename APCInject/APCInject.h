#pragma once
#include <windows.h>
#include <malloc.h>

HMODULE WINAPI GetModuleBase(LPCWSTR lModuleName);
FARPROC WINAPI GetFuncAddress(HMODULE hMod, char* cFunName);
DWORD GetProcessID();
void XOR(char* data, size_t data_len, char* key, size_t key_len);

