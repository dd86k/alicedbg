/**
 * WOW64 bindings
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.include.windows.wow64;

version (Win64):

private import adbg.include.windows.windef;

extern (Windows):

BOOL Wow64GetThreadContext(HANDLE, WOW64_CONTEXT*);
BOOL Wow64SetThreadContext(HANDLE, WOW64_CONTEXT*);

struct WOW64_FLOATING_SAVE_AREA {
	DWORD ControlWord;
	DWORD StatusWord;
	DWORD TagWord;
	DWORD ErrorOffset;
	DWORD ErrorSelector;
	DWORD DataOffset;
	DWORD DataSelector;
	BYTE  [WOW64_SIZE_OF_80387_REGISTERS]RegisterArea;
	DWORD Cr0NpxState;
}

struct WOW64_CONTEXT {
	DWORD                    ContextFlags;
	DWORD                    Dr0;
	DWORD                    Dr1;
	DWORD                    Dr2;
	DWORD                    Dr3;
	DWORD                    Dr6;
	DWORD                    Dr7;
	WOW64_FLOATING_SAVE_AREA FloatSave;
	DWORD                    SegGs;
	DWORD                    SegFs;
	DWORD                    SegEs;
	DWORD                    SegDs;
	DWORD                    Edi;
	DWORD                    Esi;
	DWORD                    Ebx;
	DWORD                    Edx;
	DWORD                    Ecx;
	DWORD                    Eax;
	DWORD                    Ebp;
	DWORD                    Eip;
	DWORD                    SegCs;
	DWORD                    EFlags;
	DWORD                    Esp;
	DWORD                    SegSs;
	BYTE                     [WOW64_MAXIMUM_SUPPORTED_EXTENSION]ExtendedRegisters;
}