/// Missing definitions for winnt.h.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.windows.winnt;

// These are redefined for dumps.

enum MAXIMUM_SUPPORTED_EXTENSION_X86 = 512;

struct FLOATING_SAVE_AREA_X86 {
    uint      ControlWord;
    uint      StatusWord;
    uint      TagWord;
    uint      ErrorOffset;
    uint      ErrorSelector;
    uint      DataOffset;
    uint      DataSelector;
    ubyte[80] RegisterArea;
    uint      Cr0NpxState;
}

struct CONTEXT_X86 {
    uint ContextFlags;
    uint Dr0;
    uint Dr1;
    uint Dr2;
    uint Dr3;
    uint Dr6;
    uint Dr7;
    FLOATING_SAVE_AREA_X86 FloatSave;
    uint SegGs;
    uint SegFs;
    uint SegEs;
    uint SegDs;
    uint Edi;
    uint Esi;
    uint Ebx;
    uint Edx;
    uint Ecx;
    uint Eax;
    uint Ebp;
    uint Eip;
    uint SegCs;
    uint EFlags;
    uint Esp;
    uint SegSs;
    ubyte[MAXIMUM_SUPPORTED_EXTENSION_X86] ExtendedRegisters;
}

align(16) struct M128A
{
    ulong Low;
    long High;
}
alias M128A* PM128A;

struct XMM_SAVE_AREA32
{
    ushort ControlWord;
    ushort StatusWord;
    ubyte TagWord;
    ubyte Reserved1;
    ushort ErrorOpcode;
    uint ErrorOffset;
    ushort ErrorSelector;
    ushort Reserved2;
    uint DataOffset;
    ushort DataSelector;
    ushort Reserved3;
    uint MxCsr;
    uint MxCsr_Mask;
    M128A[8] FloatRegisters;
    M128A[16] XmmRegisters;
    ubyte[96] Reserved4;
}
alias XMM_SAVE_AREA32 PXMM_SAVE_AREA32;

align(16) struct CONTEXT_X64
{
    ulong  P1Home;
    ulong  P2Home;
    ulong  P3Home;
    ulong  P4Home;
    ulong  P5Home;
    ulong  P6Home;
    uint   ContextFlags;
    uint   MxCsr;
    ushort SegCs;
    ushort SegDs;
    ushort SegEs;
    ushort SegFs;
    ushort SegGs;
    ushort SegSs;
    uint   EFlags;
    ulong  Dr0;
    ulong  Dr1;
    ulong  Dr2;
    ulong  Dr3;
    ulong  Dr6;
    ulong  Dr7;
    ulong  Rax;
    ulong  Rcx;
    ulong  Rdx;
    ulong  Rbx;
    ulong  Rsp;
    ulong  Rbp;
    ulong  Rsi;
    ulong  Rdi;
    ulong  R8;
    ulong  R9;
    ulong  R10;
    ulong  R11;
    ulong  R12;
    ulong  R13;
    ulong  R14;
    ulong  R15;
    ulong  Rip;
    union
    {
        XMM_SAVE_AREA32 FltSave;
        XMM_SAVE_AREA32 FloatSave;
        struct
        {
            M128A[2] Header;
            M128A[8] Legacy;
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        }
    }
    M128A[26] VectorRegister;
    ulong VectorControl;
    ulong DebugControl;
    ulong LastBranchToRip;
    ulong LastBranchFromRip;
    ulong LastExceptionToRip;
    ulong LastExceptionFromRip;
}

version (Windows):

public import core.sys.windows.winnt;

extern (Windows):

alias ULONGLONG = ulong;
alias DWORD = uint;

enum PROCESS_SUSPEND_RESUME = 0x0800;

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