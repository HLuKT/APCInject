#pragma once
#include <Windows.h>
#include<intrin.h>

//������
BOOL TrapFlag();
BOOL CheckRemoteDebuggerPresentAPI();
BOOL HardwareBreakpoints();
//BOOL Interrupt_0x2d();
//BOOL Interrupt_3();
BOOL IsDebuggerPresentAPI();
BOOL MemoryBreakpoints_PageGuard();
BOOL SetHandleInformatiom_ProtectedHandle();
BOOL SharedUserData_KernelDebugger();
BOOL UnhandledExcepFilterTest();

//��ɳ��
/*�������д��ȥ*/
BOOL timing_SetTimer(UINT delayInMillis);
BOOL timing_WaitForSingleObject(UINT delayInMillis);
BOOL timing_sleep_loop(UINT delayInMillis);
/*������벻��д��ȥ*/
BOOL rdtsc_diff_locky();
BOOL rdtsc_diff_vmexit();
BOOL timing_CreateWaitableTimer(UINT delayInMillis);
BOOL timing_CreateTimerQueueTimer(UINT delayInMillis);
VOID CALLBACK CallbackCTQT(PVOID lParam, BOOLEAN TimerOrWaitFired);

//���淽��
BOOL accelerated_sleep();
BOOL disk_size_getdiskfreespace();// 80GB �������Լ�
BOOL mouse_movement();

