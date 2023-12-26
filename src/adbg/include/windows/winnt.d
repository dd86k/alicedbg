/// Missing definitions for winnt.h.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.windows.winnt;

alias ULONGLONG = ulong;
alias DWORD = uint;

//
// Process specific MEMORY_BASIC_INFORMATION, useful for WoW processes.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
//

struct MEMORY_BASIC_INFORMATION32 {
    DWORD BaseAddress;
    DWORD AllocationBase;
    DWORD AllocationProtect;
    DWORD RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
}

align(16) struct MEMORY_BASIC_INFORMATION64 { 
    ULONGLONG BaseAddress;
    ULONGLONG AllocationBase;
    DWORD     AllocationProtect;
    DWORD     __alignment1;
    ULONGLONG RegionSize;
    DWORD     State;
    DWORD     Protect;
    DWORD     Type;
    DWORD     __alignment2;
}