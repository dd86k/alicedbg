/// Missing definitions for winnt.h.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.windows.winnt;

// NOTE: For minidumps, define the structures with D types.

// Sources:
// - {Windows Kits}\um\winnt.h
// - https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record

extern (Windows):

//
// Public region required for Minidump support
//

alias ULONGLONG = ulong;
alias DWORD = uint;

/// Size of x87 registers in bytes
enum SIZE_OF_80387_REGISTERS = 80;
/// Ditto
enum WOW64_SIZE_OF_80387_REGISTERS = SIZE_OF_80387_REGISTERS;
/// 
enum WOW64_MAXIMUM_SUPPORTED_EXTENSION = 512;
/// Maximum number of exception parameters
enum EXCEPTION_MAXIMUM_PARAMETERS = 15; // valid in 8.1 .. 10.0.17134.0
/// 
enum MAXIMUM_SUPPORTED_EXTENSION = 512;
/// 
enum ARM64_MAX_BREAKPOINTS     = 8;
/// 
enum ARM64_MAX_WATCHPOINTS     = 2;
/// 
enum ARM_MAX_BREAKPOINTS       = 8;
/// 
enum ARM_MAX_WATCHPOINTS       = 1;

struct FLOATING_SAVE_AREA {
    uint ControlWord;
    uint StatusWord;
    uint TagWord;
    uint ErrorOffset;
    uint ErrorSelector;
    uint DataOffset;
    uint DataSelector;
    ubyte[SIZE_OF_80387_REGISTERS] RegisterArea;
    uint Spare0;
}
alias PFLOATING_SAVE_AREA = FLOATING_SAVE_AREA*;

struct X86_NT_CONTEXT {
    uint ContextFlags;
    uint Dr0;
    uint Dr1;
    uint Dr2;
    uint Dr3;
    uint Dr6;
    uint Dr7;
    FLOATING_SAVE_AREA FloatSave;
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
    ubyte[MAXIMUM_SUPPORTED_EXTENSION] ExtendedRegisters;
}
alias PX86_NT_CONTEXT = X86_NT_CONTEXT*;

//
// Windows-specific region
//

version (Windows):

public import core.sys.windows.winnt;

align(16) struct M128A {
    ulong Low;
    long High;
}
alias PM128A = M128A*;

union ARM64_NT_NEON128 {
    struct {
        ULONGLONG Low;
        LONGLONG High;
    }
    double[2] D;
    float[4]  S;
    WORD[8]   H;
    BYTE[16]  B;
}

version (AArch64) { // defined(_ARM64_)
    alias PARM64_NT_NEON128 = ARM64_NT_NEON128*;
    alias NEON128 = ARM64_NT_NEON128;
    alias PNEON128 = NEON128*;
} else {
    struct NEON128 {
        ULONGLONG Low;
        LONGLONG High;
    }
    alias PNEON128 = NEON128*;
}

// NOTE: It's the same layout
public alias WOW64_CONTEXT = X86_NT_CONTEXT;
alias PWOW64_CONTEXT = WOW64_CONTEXT*;

alias WOW64_FLOATING_SAVE_AREA = FLOATING_SAVE_AREA;
alias PWOW64_FLOATING_SAVE_AREA = WOW64_FLOATING_SAVE_AREA;

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

align(16) struct XSAVE_FORMAT { // DECLSPEC_ALIGN(16)
    WORD   ControlWord;
    WORD   StatusWord;
    BYTE  TagWord;
    BYTE  Reserved1;
    WORD   ErrorOpcode;
    DWORD ErrorOffset;
    WORD   ErrorSelector;
    WORD   Reserved2;
    DWORD DataOffset;
    WORD   DataSelector;
    WORD   Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A[8] FloatRegisters;
    
    version (Win64) {
        M128A[16] XmmRegisters;
        BYTE[96]  Reserved4;
    } else {
        M128A[8]  XmmRegisters;
        BYTE[224] Reserved4;
    }
}

alias PXSAVE_FORMAT = XSAVE_FORMAT*;

/// Typedef for pointer returned by exception_info()
struct EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
}

struct EXCEPTION_RECORD {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	EXCEPTION_RECORD* ExceptionRecord;
	PVOID ExceptionAddress;
	DWORD NumberParameters;
	ULONG_PTR[EXCEPTION_MAXIMUM_PARAMETERS] ExceptionInformation;
}


struct EXCEPTION_RECORD32 {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	DWORD ExceptionRecord;
	DWORD ExceptionAddress;
	DWORD NumberParameters;
	DWORD[EXCEPTION_MAXIMUM_PARAMETERS] ExceptionInformation;
}


struct EXCEPTION_RECORD64 {
	DWORD   ExceptionCode;
	DWORD   ExceptionFlags;
	DWORD64 ExceptionRecord;
	DWORD64 ExceptionAddress;
	DWORD   NumberParameters;
	DWORD   __unusedAlignment;
	DWORD64[EXCEPTION_MAXIMUM_PARAMETERS] ExceptionInformation;
}

alias PEXCEPTION_POINTERS = EXCEPTION_POINTERS*;
alias PEXCEPTION_RECORD   = EXCEPTION_RECORD*;
alias PEXCEPTION_RECORD32 = EXCEPTION_RECORD32*;
alias PEXCEPTION_RECORD64 = EXCEPTION_RECORD64*;

// DECLSPEC_NOINITALL?
align(16) struct ARM64_NT_CONTEXT { // DECLSPEC_ALIGN(16)

    //
    // Control flags.
    //

    /* +0x000 */ DWORD ContextFlags;

    //
    // Integer registers
    //

    /* +0x004 */ DWORD Cpsr;       // NZVF + DAIF + CurrentEL + SPSel
    /* +0x008 */ union {
                    struct {
                        DWORD64 X0;
                        DWORD64 X1;
                        DWORD64 X2;
                        DWORD64 X3;
                        DWORD64 X4;
                        DWORD64 X5;
                        DWORD64 X6;
                        DWORD64 X7;
                        DWORD64 X8;
                        DWORD64 X9;
                        DWORD64 X10;
                        DWORD64 X11;
                        DWORD64 X12;
                        DWORD64 X13;
                        DWORD64 X14;
                        DWORD64 X15;
                        DWORD64 X16;
                        DWORD64 X17;
                        DWORD64 X18;
                        DWORD64 X19;
                        DWORD64 X20;
                        DWORD64 X21;
                        DWORD64 X22;
                        DWORD64 X23;
                        DWORD64 X24;
                        DWORD64 X25;
                        DWORD64 X26;
                        DWORD64 X27;
                        DWORD64 X28;
    /* +0x0f0 */        DWORD64 Fp;
    /* +0x0f8 */        DWORD64 Lr;
                    }
                    DWORD64[31] X;
                 }
    /* +0x100 */ DWORD64 Sp;
    /* +0x108 */ DWORD64 Pc;

    //
    // Floating Point/NEON Registers
    //

    /* +0x110 */ ARM64_NT_NEON128[32] V;
    /* +0x310 */ DWORD Fpcr;
    /* +0x314 */ DWORD Fpsr;

    //
    // Debug registers
    //

    /* +0x318 */ DWORD[ARM64_MAX_BREAKPOINTS]   Bcr;
    /* +0x338 */ DWORD64[ARM64_MAX_BREAKPOINTS] Bvr;
    /* +0x378 */ DWORD[ARM64_MAX_WATCHPOINTS]   Wcr;
    /* +0x380 */ DWORD64[ARM64_MAX_WATCHPOINTS] Wvr;
    /* +0x390 */

}

alias PARM64_NT_CONTEXT = ARM64_NT_CONTEXT;

align(8) struct ARM_NT_CONTEXT { // DECLSPEC_ALIGN(8)

    //
    // Control flags.
    //

    DWORD ContextFlags;

    //
    // Integer registers
    //

    DWORD R0;
    DWORD R1;
    DWORD R2;
    DWORD R3;
    DWORD R4;
    DWORD R5;
    DWORD R6;
    DWORD R7;
    DWORD R8;
    DWORD R9;
    DWORD R10;
    DWORD R11;
    DWORD R12;

    //
    // Control Registers
    //

    DWORD Sp;
    DWORD Lr;
    DWORD Pc;
    DWORD Cpsr;

    //
    // Floating Point/NEON Registers
    //

    DWORD Fpscr;
    DWORD Padding;
    union {
        NEON128[16]   Q;
        ULONGLONG[32] D;
        DWORD[32]     S;
    }

    //
    // Debug registers
    //

    DWORD[ARM_MAX_BREAKPOINTS] Bvr;
    DWORD[ARM_MAX_BREAKPOINTS] Bcr;
    DWORD[ARM_MAX_WATCHPOINTS] Wvr;
    DWORD[ARM_MAX_WATCHPOINTS] Wcr;

    DWORD[2] Padding2;
}

alias PARM_NT_CONTEXT = ARM_NT_CONTEXT*;

// DECLSPEC_NOINITALL?
align(16) struct ARM64EC_NT_CONTEXT { // DECLSPEC_ALIGN(16)
    union {
        struct {

            //
            // AMD64 call register home space. These can't be used by ARM64EC
            //

            /* +0x000 */ DWORD64 AMD64_P1Home;
            /* +0x008 */ DWORD64 AMD64_P2Home;
            /* +0x010 */ DWORD64 AMD64_P3Home;
            /* +0x018 */ DWORD64 AMD64_P4Home;
            /* +0x020 */ DWORD64 AMD64_P5Home;
            /* +0x028 */ DWORD64 AMD64_P6Home;

            //
            // Control flags.
            //

            /* +0x030 */ DWORD ContextFlags;

            /* +0x034 */ DWORD AMD64_MxCsr_copy;

            //
            // Segment Registers and processor flags. These can't be used by
            // ARM64EC
            //

            /* +0x038 */ WORD   AMD64_SegCs;
            /* +0x03a */ WORD   AMD64_SegDs;
            /* +0x03c */ WORD   AMD64_SegEs;
            /* +0x03e */ WORD   AMD64_SegFs;
            /* +0x040 */ WORD   AMD64_SegGs;
            /* +0x042 */ WORD   AMD64_SegSs;

            //
            // General purpose flags.
            //

            /* +0x044 */ DWORD AMD64_EFlags;

            //
            // Debug registers
            //

            /* +0x048 */ DWORD64 AMD64_Dr0;
            /* +0x050 */ DWORD64 AMD64_Dr1;
            /* +0x058 */ DWORD64 AMD64_Dr2;
            /* +0x060 */ DWORD64 AMD64_Dr3;
            /* +0x068 */ DWORD64 AMD64_Dr6;
            /* +0x070 */ DWORD64 AMD64_Dr7;

            //
            // Integer registers.
            //

            /* +0x078 */ DWORD64 X8;     // AMD64_Rax
            /* +0x080 */ DWORD64 X0;     // AMD64_Rcx
            /* +0x088 */ DWORD64 X1;     // AMD64_Rdx
            /* +0x090 */ DWORD64 X27;    // AMD64_Rbx
            /* +0x098 */ DWORD64 Sp;     // AMD64_Rsp
            /* +0x0a0 */ DWORD64 Fp;     // AMD64_Rbp
            /* +0x0a8 */ DWORD64 X25;    // AMD64_Rsi
            /* +0x0b0 */ DWORD64 X26;    // AMD64_Rdi
            /* +0x0b8 */ DWORD64 X2;     // AMD64_R8
            /* +0x0c0 */ DWORD64 X3;     // AMD64_R9
            /* +0x0c8 */ DWORD64 X4;     // AMD64_R10
            /* +0x0d0 */ DWORD64 X5;     // AMD64_R11
            /* +0x0d8 */ DWORD64 X19;    // AMD64_R12
            /* +0x0e0 */ DWORD64 X20;    // AMD64_R13
            /* +0x0e8 */ DWORD64 X21;    // AMD64_R14
            /* +0x0f0 */ DWORD64 X22;    // AMD64_R15

            //
            // Program counter.
            //

            /* +0x0f8 */ DWORD64 Pc;     // AMD64_Rip

            //
            // Floating point state.
            //

            struct {
                /* +0x100 */ WORD   AMD64_ControlWord;
                /* +0x102 */ WORD   AMD64_StatusWord;
                /* +0x104 */ BYTE  AMD64_TagWord;
                /* +0x105 */ BYTE  AMD64_Reserved1;
                /* +0x106 */ WORD   AMD64_ErrorOpcode;
                /* +0x108 */ DWORD AMD64_ErrorOffset;
                /* +0x10c */ WORD   AMD64_ErrorSelector;
                /* +0x10e */ WORD   AMD64_Reserved2;
                /* +0x110 */ DWORD AMD64_DataOffset;
                /* +0x114 */ WORD   AMD64_DataSelector;
                /* +0x116 */ WORD   AMD64_Reserved3;

                /* +0x118 */ DWORD AMD64_MxCsr;
                /* +0x11c */ DWORD AMD64_MxCsr_Mask;

                /* +0x120 */ DWORD64 Lr;                 // AMD64_St0_Low
                /* +0x128 */ WORD   X16_0;               // AMD64_St0_High
                /* +0x12a */ WORD   AMD64_St0_Reserved1;
                /* +0x12c */ DWORD AMD64_St0_Reserved2;
                /* +0x130 */ DWORD64 X6;                 // AMD64_St1_Low
                /* +0x138 */ WORD   X16_1;               // AMD64_St1_High
                /* +0x13a */ WORD   AMD64_St1_Reserved1;
                /* +0x13c */ DWORD AMD64_St1_Reserved2;
                /* +0x140 */ DWORD64 X7;                 // AMD64_St2_Low
                /* +0x148 */ WORD   X16_2;               // AMD64_St2_High
                /* +0x14a */ WORD   AMD64_St2_Reserved1;
                /* +0x14c */ DWORD AMD64_St2_Reserved2;
                /* +0x150 */ DWORD64 X9;                 // AMD64_St3_Low
                /* +0x158 */ WORD   X16_3;               // AMD64_St3_High
                /* +0x15a */ WORD   AMD64_St3_Reserved1;
                /* +0x15c */ DWORD AMD64_St3_Reserved2;
                /* +0x160 */ DWORD64 X10;                // AMD64_St4_Low
                /* +0x168 */ WORD   X17_0;               // AMD64_St4_High
                /* +0x16a */ WORD   AMD64_St4_Reserved1;
                /* +0x16c */ DWORD AMD64_St4_Reserved2;
                /* +0x170 */ DWORD64 X11;                // AMD64_St5_Low
                /* +0x178 */ WORD   X17_1;               // AMD64_St5_High
                /* +0x17a */ WORD   AMD64_St5_Reserved1;
                /* +0x17c */ DWORD AMD64_St5_Reserved2;
                /* +0x180 */ DWORD64 X12;                // AMD64_St6_Low
                /* +0x188 */ WORD   X17_2;               // AMD64_St6_High
                /* +0x18a */ WORD   AMD64_St6_Reserved1;
                /* +0x18c */ DWORD AMD64_St6_Reserved2;
                /* +0x190 */ DWORD64 X15;                // AMD64_St7_Low
                /* +0x198 */ WORD   X17_3;               // AMD64_St7_High;
                /* +0x19a */ WORD   AMD64_St7_Reserved1;
                /* +0x19c */ DWORD AMD64_St7_Reserved2;

                /* +0x1a0 */ ARM64_NT_NEON128[16] V;     // AMD64_XmmRegisters[16]
                /* +0x2a0 */ BYTE[96]  AMD64_XSAVE_FORMAT_Reserved4;
            }

            //
            // AMD64 Vector registers.
            //

            /* +0x300 */ ARM64_NT_NEON128[26] AMD64_VectorRegister;
            /* +0x4a0 */ DWORD64 AMD64_VectorControl;

            //
            // AMD64 Special debug control registers.
            //

            /* +0x4a8 */ DWORD64 AMD64_DebugControl;
            /* +0x4b0 */ DWORD64 AMD64_LastBranchToRip;
            /* +0x4b8 */ DWORD64 AMD64_LastBranchFromRip;
            /* +0x4c0 */ DWORD64 AMD64_LastExceptionToRip;
            /* +0x4c8 */ DWORD64 AMD64_LastExceptionFromRip;
            /* +0x4d0 */

        }
        
        //TODO: Define _ARM64EC_
        version (_ARM64EC_) {
            /* CONTEXT */ ARM64EC_NT_CONTEXT AMD64_Context;
        }
    }
}

alias PARM64EC_NT_CONTEXT = ARM64EC_NT_CONTEXT*;

// Original CONTEXT, but renamed for manageability
// DECLSPEC_NOINITALL?
align(16) struct AMD64_NT_CONTEXT { // DECLSPEC_ALIGN(16)
    //
    // Register parameter home addresses.
    //
    // N.B. These fields are for convience - they could be used to extend the
    //      context record in the future.
    //

    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;

    //
    // Control flags.
    //

    DWORD ContextFlags;
    DWORD MxCsr;

    //
    // Segment Registers and processor flags.
    //

    WORD   SegCs;
    WORD   SegDs;
    WORD   SegEs;
    WORD   SegFs;
    WORD   SegGs;
    WORD   SegSs;
    DWORD EFlags;

    //
    // Debug registers
    //

    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;

    //
    // Integer registers.
    //

    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;

    //
    // Program counter.
    //

    DWORD64 Rip;

    //
    // Floating point state.
    //

    union {
        XMM_SAVE_AREA32 FltSave;
        struct {
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

    //
    // Vector registers.
    //

    M128A[26] VectorRegister;
    DWORD64 VectorControl;

    //
    // Special debug control registers.
    //

    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
}

alias PAMD64_NT_CONTEXT = AMD64_NT_CONTEXT*;

version (X86) {
    alias CONTEXT = X86_NT_CONTEXT;
} else version (X86_64) {
    alias CONTEXT = AMD64_NT_CONTEXT;
} else version (Arm) {
    alias CONTEXT = ARM_NT_CONTEXT;
} else version (AArch64) {
    alias CONTEXT = ARM64_NT_CONTEXT;
}

alias PCONTEXT = CONTEXT*;

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
