#pragma once
#include <Windows.h>
#include<intrin.h>

//反调试
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

//反沙箱
/*恶意代码写进去*/
BOOL timing_SetTimer(UINT delayInMillis);
BOOL timing_WaitForSingleObject(UINT delayInMillis);
BOOL timing_sleep_loop(UINT delayInMillis);
/*恶意代码不用写进去*/
BOOL rdtsc_diff_locky();
BOOL rdtsc_diff_vmexit();
BOOL timing_CreateWaitableTimer(UINT delayInMillis);
BOOL timing_CreateTimerQueueTimer(UINT delayInMillis);
VOID CALLBACK CallbackCTQT(PVOID lParam, BOOLEAN TimerOrWaitFired);

//常规方法
BOOL accelerated_sleep();
BOOL disk_size_getdiskfreespace();// 80GB 背刺我自己
BOOL mouse_movement();

