/// Tool help library.
///
/// Header: tlhelp32.h
/// Library: Kernel32.lib
/// DLL: Kernel32.dll
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.windows.tlhelp32;

version (Windows):

import core.sys.windows.windef : BOOL, BYTE, DWORD, LONG, HMODULE, MAX_PATH, CHAR, WCHAR;
import core.sys.windows.basetsd : HANDLE, ULONG_PTR, SIZE_T;

extern (Windows):

enum MAX_MODULE_NAME32 = 255;

enum {
	/// Indicates that the snapshot handle is to be inheritable.
	TH32CS_INHERIT = 0x80000000,

	/// Includes all heaps of the process specified in th32ProcessID in the
	/// snapshot. To enumerate the heaps, see Heap32ListFirst.
	TH32CS_SNAPHEAPLIST = 0x00000001,

	/// Includes all modules of the process specified in th32ProcessID in
	/// the snapshot. To enumerate the modules, see Module32First. If the
	/// function fails with ERROR_BAD_LENGTH, retry the function until it
	/// succeeds.
	///
	/// 64-bit Windows: Using this flag in a 32-bit process includes the
	/// 32-bit modules of the process specified in th32ProcessID, while
	/// using it in a 64-bit process includes the 64-bit modules. To include
	/// the 32-bit modules of the process specified in th32ProcessID from a
	/// 64-bit process, use the TH32CS_SNAPMODULE32 flag.
	TH32CS_SNAPMODULE = 0x00000008,

	/// Includes all 32-bit modules of the process specified in th32ProcessID
	/// in the snapshot when called from a 64-bit process. This flag can be
	/// combined with TH32CS_SNAPMODULE or TH32CS_SNAPALL. If the function
	/// fails with ERROR_BAD_LENGTH, retry the function until it succeeds.
	TH32CS_SNAPMODULE32 = 0x00000010,

	/// Includes all processes in the system in the snapshot. To enumerate
	/// the processes, see Process32First.
	TH32CS_SNAPPROCESS = 0x00000002,

	/// Includes all threads in the system in the snapshot. To enumerate
	/// the threads, see Thread32First.
	///
	/// To identify the threads that belong to a specific process, compare
	/// its process identifier to the th32OwnerProcessID member of the
	/// THREADENTRY32 structure when enumerating the threads.
	TH32CS_SNAPTHREAD = 0x00000004,
	
	/// Includes all processes and threads in the system, plus the heaps and modules of the process specified in th32ProcessID. Equivalent to specifying the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS, and TH32CS_SNAPTHREAD values combined using an OR operation ('|').
	TH32CS_SNAPALL =
		TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE |
		TH32CS_SNAPPROCESS  | TH32CS_SNAPTHREAD,
}

HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
/*
BOOL Toolhelp32ReadProcessMemory(DWORD th32ProcessID,
	LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T cbRead, SIZE_T *lpNumberOfBytesRead);
*/

struct HEAPENTRY32 {
	SIZE_T    dwSize;
	HANDLE    hHandle;
	ULONG_PTR dwAddress;
	SIZE_T    dwBlockSize;
	DWORD     dwFlags;
	DWORD     dwLockCount;
	DWORD     dwResvd;
	DWORD     th32ProcessID;
	ULONG_PTR th32HeapID;
}
alias LPHEAPENTRY32 = HEAPENTRY32*;

BOOL Heap32First(LPHEAPENTRY32 lphe, DWORD th32ProcessID, ULONG_PTR th32HeapID);
BOOL Heap32Next(LPHEAPENTRY32 lphe);

struct HEAPLIST32 {
	SIZE_T    dwSize;
	DWORD     th32ProcessID;
	ULONG_PTR th32HeapID;
	DWORD     dwFlags;
}
alias LPHEAPLIST32 = HEAPLIST32*;

BOOL Heap32ListFirst(HANDLE hSnapshot, LPHEAPLIST32 lphl);
BOOL Heap32ListNext(HANDLE hSnapshot, LPHEAPLIST32 lphl);

struct MODULEENTRY32 {
	DWORD   dwSize;
	DWORD   th32ModuleID;
	DWORD   th32ProcessID;
	DWORD   GlblcntUsage;
	DWORD   ProccntUsage;
	BYTE    *modBaseAddr;
	DWORD   modBaseSize;
	HMODULE hModule;
	char[MAX_MODULE_NAME32 + 1] szModule;
	char[MAX_PATH]              szExePath;
}
alias LPMODULEENTRY32 = MODULEENTRY32*;

BOOL Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
BOOL Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);

struct MODULEENTRY32W {
	DWORD   dwSize;
	DWORD   th32ModuleID;
	DWORD   th32ProcessID;
	DWORD   GlblcntUsage;
	DWORD   ProccntUsage;
	BYTE    *modBaseAddr;
	DWORD   modBaseSize;
	HMODULE hModule;
	WCHAR[MAX_MODULE_NAME32 + 1] szModule;
	WCHAR[MAX_PATH]              szExePath;
}
alias LPMODULEENTRY32W = MODULEENTRY32W*;

BOOL Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme);
BOOL Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme);

struct PROCESSENTRY32 {
	DWORD     dwSize;
	DWORD     cntUsage;
	DWORD     th32ProcessID;
	ULONG_PTR th32DefaultHeapID;
	DWORD     th32ModuleID;
	DWORD     cntThreads;
	DWORD     th32ParentProcessID;
	LONG      pcPriClassBase;
	DWORD     dwFlags;
	CHAR[MAX_PATH] szExeFile;
}
alias LPPROCESSENTRY32 = PROCESSENTRY32*;

BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

struct PROCESSENTRY32W {
	DWORD     dwSize;
	DWORD     cntUsage;
	DWORD     th32ProcessID;
	ULONG_PTR th32DefaultHeapID;
	DWORD     th32ModuleID;
	DWORD     cntThreads;
	DWORD     th32ParentProcessID;
	LONG      pcPriClassBase;
	DWORD     dwFlags;
	WCHAR[MAX_PATH] szExeFile;
}
alias LPPROCESSENTRY32W = PROCESSENTRY32W*;

BOOL Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
BOOL Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

struct THREADENTRY32 {
	DWORD dwSize;
	DWORD cntUsage;
	DWORD th32ThreadID;
	DWORD th32OwnerProcessID;
	LONG  tpBasePri;
	LONG  tpDeltaPri;
	DWORD dwFlags;
}
alias LPTHREADENTRY32 = THREADENTRY32*;

BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
BOOL Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);