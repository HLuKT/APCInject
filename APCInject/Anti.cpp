#include"Anti.h"
//AntiDEBUG
/*TrapFlag（陷阱标志位）*/
static BOOL SwallowedException = TRUE;

static LONG CALLBACK VectoredHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	SwallowedException = FALSE;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		return EXCEPTION_CONTINUE_EXECUTION;

	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL TrapFlag()
{
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
	SwallowedException = TRUE;

#ifdef _WIN64
	UINT64 eflags = __readeflags();
#else
	UINT eflags = __readeflags();
#endif
	eflags |= 0x100;
	__writeeflags(eflags);

	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException;
}

/*检查是否正在调试远程进程*/
BOOL CheckRemoteDebuggerPresentAPI()
{
	BOOL bIsDbgPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &bIsDbgPresent);
	return bIsDbgPresent;
}

/*硬件断点*/
BOOL HardwareBreakpoints()
{
	BOOL bResult = FALSE;
	PCONTEXT ctx = PCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));

	if (ctx) {
		SecureZeroMemory(ctx, sizeof(CONTEXT));
		ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (GetThreadContext(GetCurrentThread(), ctx)) {
			if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
				bResult = TRUE;
		}
		VirtualFree(ctx, 0, MEM_RELEASE);
	}
	return bResult;
}

/*Int 2D 检查调试器是否已附加到当前进程
extern "C" void __int2d();
static BOOL SwallowedException = TRUE;
static LONG CALLBACK VectoredHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo)
{
	SwallowedException = FALSE;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL Interrupt_0x2d()
{
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
	SwallowedException = TRUE;
	__int2d();
	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException;
}
*/

/*INT 3 断点
static BOOL SwallowedException = TRUE;
static LONG CALLBACK VectoredHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo)
{
	SwallowedException = FALSE;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
#ifdef _WIN64
		ExceptionInfo->ContextRecord->Rip++;
#else
		ExceptionInfo->ContextRecord->Eip++;
#endif
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL Interrupt_3()
{
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
	SwallowedException = TRUE;
	__debugbreak();
	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException;
}
*/

/*Win32 调试 API*/
BOOL IsDebuggerPresentAPI()
{
	return IsDebuggerPresent();
}

/*将页面标记为保护页，并将返回地址推到堆栈上*/
BOOL MemoryBreakpoints_PageGuard()
{
	UCHAR* pMem = NULL;
	SYSTEM_INFO SystemInfo = { 0 };
	DWORD OldProtect = 0;
	PVOID pAllocation = NULL;

	GetSystemInfo(&SystemInfo);

	pAllocation = VirtualAlloc(NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pAllocation == NULL)
		return FALSE;

	RtlFillMemory(pAllocation, 1, 0xC3);
      
	if (VirtualProtect(pAllocation, SystemInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect) == 0)
		return FALSE;

	__try
	{
		((void(*)())pAllocation)();
	}
	__except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		VirtualFree(pAllocation, 0, MEM_RELEASE);
		return FALSE;
	}

	VirtualFree(pAllocation, 0, MEM_RELEASE);
	return TRUE;
}

/*创建互斥锁*/
BOOL SetHandleInformatiom_ProtectedHandle()
{
	HANDLE hMutex;
	hMutex = CreateMutex(NULL, FALSE, L"Random name");
	if (hMutex) {
		SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
		__try {
			CloseHandle(hMutex);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return TRUE;
		}
	}
	return FALSE;
}

/*检测内核调试器*/
BOOL SharedUserData_KernelDebugger()
{
	const ULONG_PTR UserSharedData = 0x7FFE0000;
	const UCHAR KdDebuggerEnabledByte = *(UCHAR*)(UserSharedData + 0x2D4);
	const BOOLEAN KdDebuggerEnabled = (KdDebuggerEnabledByte & 0x1) == 0x1;
	const BOOLEAN KdDebuggerNotPresent = (KdDebuggerEnabledByte & 0x2) == 0;

	if (KdDebuggerEnabled || !KdDebuggerNotPresent)
		return TRUE;
	return FALSE;
}

/*kernel32 UnhandledExceptionFilter()如果存在调试器,则无法访问此函数*/
BOOL bIsBeinDbg = TRUE;
LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers)
{
	bIsBeinDbg = FALSE;
	return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL UnhandledExcepFilterTest()
{
	LPTOP_LEVEL_EXCEPTION_FILTER Top = SetUnhandledExceptionFilter(UnhandledExcepFilter);
	RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, NULL);
	SetUnhandledExceptionFilter(Top);
	return bIsBeinDbg;
}

//AntiSandBox
/*设置计时器*/
BOOL bProcessed = FALSE;
VOID CALLBACK TimerProc(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTime)
{
	//恶意代码
	bProcessed = TRUE;
}
BOOL timing_SetTimer(UINT delayInMillis)
{
	MSG Msg;
	UINT_PTR iTimerID;

	iTimerID = SetTimer(NULL, 0, delayInMillis, TimerProc);

	if (iTimerID == NULL)
		return TRUE;

	while (GetMessage(&Msg, NULL, 0, 0) & !bProcessed)
	{
		TranslateMessage(&Msg);
		DispatchMessage(&Msg);
	}
	KillTimer(NULL, iTimerID);
	return FALSE;
}

/*创建无信号事件等待超时*/
BOOL timing_WaitForSingleObject(UINT delayInMillis)
{
	HANDLE hEvent;

	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (hEvent == NULL)
	{
		return TRUE;
	}

	DWORD x = WaitForSingleObject(hEvent, delayInMillis);
	//恶意代码
	return FALSE;
}

/*低秒数睡眠*/
BOOL timing_sleep_loop(UINT delayInMillis)
{
	int delayInMillis_divided = delayInMillis / 1000;

	for (int i = 0; i < 1000; i++) {
		Sleep(delayInMillis_divided);
	}
	//恶意代码
	return FALSE;
}

/*计算自复位以来的周期数.可用于检测VM */
#define LODWORD(_qw)    ((DWORD)(_qw))
BOOL rdtsc_diff_locky()
{
	ULONGLONG tsc1;
	ULONGLONG tsc2;
	ULONGLONG tsc3;
	DWORD i = 0;

	for (i = 0; i < 10; i++)
	{
		tsc1 = __rdtsc();
		GetProcessHeap();
		tsc2 = __rdtsc();
		CloseHandle(0);
		tsc3 = __rdtsc();
		if ((LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1)) >= 10)
			return FALSE;
	}
	return TRUE;
}

/*显示虚拟机管理程序的存在*/
BOOL rdtsc_diff_vmexit()
{
	ULONGLONG tsc1 = 0;
	ULONGLONG tsc2 = 0;
	ULONGLONG avg = 0;
	INT cpuInfo[4] = {};

	for (INT i = 0; i < 10; i++)
	{
		tsc1 = __rdtsc();
		__cpuid(cpuInfo, 0);
		tsc2 = __rdtsc();

		avg += (tsc2 - tsc1);
	}

	avg = avg / 10;
	return (avg < 1000 && avg > 0) ? FALSE : TRUE;
}

/*使用SetWaitableTimer进行定时攻击*/
BOOL timing_CreateWaitableTimer(UINT delayInMillis)
{
	HANDLE hTimer;
	LARGE_INTEGER dueTime;

	BOOL bResult = FALSE;

	dueTime.QuadPart = delayInMillis * -10000LL;

	hTimer = CreateWaitableTimer(NULL, TRUE, NULL);

	if (hTimer == NULL)
	{
		return TRUE;
	}

	if (SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE) == FALSE)
	{
		bResult = TRUE;
	}
	else {
		if (WaitForSingleObject(hTimer, INFINITE) != WAIT_OBJECT_0)
		{
			bResult = TRUE;
		}
	}
	CancelWaitableTimer(hTimer);
	CloseHandle(hTimer);
	return bResult;
}

/*使用 CreateTimerQueueTimer 的定时攻击*/
HANDLE g_hEventCTQT = NULL;
BOOL timing_CreateTimerQueueTimer(UINT delayInMillis)
{
	HANDLE hTimerQueue;
	HANDLE hTimerQueueTimer = NULL;
	BOOL bResult = FALSE;

	g_hEventCTQT = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (g_hEventCTQT == NULL)
		return FALSE;

	hTimerQueue = CreateTimerQueue();
	if (hTimerQueue == NULL)
	{
		return TRUE;
	}

	if (CreateTimerQueueTimer(
		&hTimerQueueTimer,
		hTimerQueue,
		&CallbackCTQT,
		reinterpret_cast<PVOID>(0xDEADBEEFULL),
		delayInMillis,
		0,
		WT_EXECUTEDEFAULT) == FALSE)
	{
		bResult = TRUE;
	}
	else {
		if (WaitForSingleObject(g_hEventCTQT, delayInMillis * 10) != WAIT_OBJECT_0)
		{
			bResult = FALSE;
		}
	}
	DeleteTimerQueueEx(hTimerQueue, NULL);
	CloseHandle(g_hEventCTQT);
	return bResult;
}

VOID CALLBACK CallbackCTQT(PVOID lParam, BOOLEAN TimerOrWaitFired)
{
	if (TimerOrWaitFired == TRUE && lParam == reinterpret_cast<PVOID>(0xDEADBEEFULL))
	{
		SetEvent(g_hEventCTQT);
	}
}

//常规Anti
/*睡眠并检查时间是否加速*/
BOOL accelerated_sleep()
{
	DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
	DWORD dwMillisecondsToSleep = 60 * 1000;
	dwStart = GetTickCount();
	Sleep(dwMillisecondsToSleep);
	dwEnd = GetTickCount();
	dwDiff = dwEnd - dwStart;
	if (dwDiff > dwMillisecondsToSleep - 1000)
		return FALSE;
	else
		return TRUE;
}

/*使用 GetDiskFreeSpaceEx 检查磁盘大小*/
BOOL disk_size_getdiskfreespace()
{
	ULONGLONG minHardDiskSize = (80ULL * (1024ULL * (1024ULL * (1024ULL))));
	LPCWSTR pszDrive = NULL;
	BOOL bStatus = FALSE;
	ULARGE_INTEGER totalNumberOfBytes;
	bStatus = GetDiskFreeSpaceEx(pszDrive, NULL, &totalNumberOfBytes, NULL);
	if (bStatus) {
		if (totalNumberOfBytes.QuadPart < minHardDiskSize)  // 80GB
			return TRUE;
	}
	return FALSE;;
}

/*检查鼠标移动*/
BOOL mouse_movement() {
	POINT positionA = {};
	POINT positionB = {};
	GetCursorPos(&positionA);
	Sleep(5000);
	GetCursorPos(&positionB);
	if ((positionA.x == positionB.x) && (positionA.y == positionB.y))
		return TRUE;
	else
		return FALSE;
}
