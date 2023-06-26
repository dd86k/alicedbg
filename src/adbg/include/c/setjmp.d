/**
 * setjmp.h wrapper binding to the C runtime.
 *
 * While there are bindings for posix (core.sys.posix.setjmp), there are none
 * for Windows. This module is still on-going work.
 *
 * Fine on:
 * - dmd-x86_omf
 * - dmd-x86_mscoff
 * - ldc-x86
 * Crashes on:
 * - dmd-x86_64
 * - ldc-x86_64
 * 
 * Windows reference:
 * - "{VisualStudio}\VC\Tools\MSVC\14.15.26726\include\setjmp.h"
 * - "{VisualStudio}\VC\Tools\MSVC\14.16.27023\include\setjmp.h"
 * Glibc reference:
 * - jmp_buf structures: sysdeps/{arch}/jmpbuf-offsets.h
 * - jmp_buf definitions: sysdeps/{arch}/bits/setjmp.h
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.include.c.setjmp;

private import core.stdc.config : c_long;

extern (C):
@system:
@nogc:
nothrow:

version (Windows) {
	version (X86) {
		enum _JBLEN = 16;
		alias int _JBTYPE;

		struct _JUMP_BUFFER {
			int Ebp, Ebx, Edi, Esi, Esp, Eip, Registration,
				TryLevel, Cookie, UnwindFunc;
			int[6] UnwindData;
		}
	} else version (X86_64) {
		//TODO: Fix C0000028 (__chkstk) issue
		//      "An invalid or unaligned stack was encountered during
		//      an unwind operation."
		enum _JBLEN = 16;
		alias _SETJMP_FLOAT128 _JBTYPE;

		struct _SETJMP_FLOAT128 {
			long[2] Part;
		}

		struct _JUMP_BUFFER {
			align (1):
			long Frame, Rbx, Rsp, Rbp, Rsi, Rdi,
				R12, R13, R14, R15, Rip;
			int MxCsr;
			short FpCsr;
			short Spare;
			
			align (16):
			_SETJMP_FLOAT128 Xmm6, Xmm7, Xmm8, Xmm9, Xmm10,
				Xmm11, Xmm12, Xmm13, Xmm14, Xmm15;
		}
	} else version (ARM) {
		enum _JBLEN = 28;
		alias int _JTYPE;

		struct _JUMP_BUFFER {
			int Frame, R4, R5, R6, R7, R8, R9, R10, R11,
				Sp, Pc, Fpscr;
			long[8] D; // D8-D15 VFP/NEON regs
		}
	} else version (Aarch64) {
		enum _JBLEN = 24;
		alias int _JTYPE;

		struct _JUMP_BUFFER {
			long Frame, Reserved,
				X19, X20, X21, X22, X23, // x19 -- x28
				X24, X25, X26, X27, X28, // callee saved registers
				Fp,	// x29 frame pointer
				Lr,	// x30 link register
				Sp;	// x31 stack pointer
			int Fpcr;	// fp control register
			int Fpsr;	// fp status register
			double[8] D;	// D8-D15 FP regs
		}
	} else static assert(0, "Missing setjmp definitions (Windows)");

	// typedef _JBTYPE jmp_buf[_JBLEN];
	//public alias _JBTYPE[_JBLEN] jmp_buf;
	public alias _JUMP_BUFFER jmp_buf;
} else version (CRuntime_Glibc) { // 2.25
	version (X86) {
		struct __jmp_buf {
			int ebx, esi, edi, ebp, esp, eip;
		}
		// typedef int __jmp_buf[6];
	} else version (X86_64) {
		struct __jmp_buf {
			long rbx, rbp, r12, r13, r14, r15, rsp, rip;
		}
		// typedef unsigned long long __jmp_buf[8]
	} else version (ARM) {
		// NOTE: Glibc sysdeps/arm/jmpbuf-unwind.h DOESN'T define a structure
		//       So this is made purely out of the description given
		struct __i128 {
			union {
				ubyte[16] b; short[8] h;
				int[4] d; long[2] q;
			}
		}
		// "The first 26 words are occupied by sp, lr, v1-v6, sl, fp,
		// and d8-d15."
		struct __jmp_buf {
			int sp, lr;
			__i128 v1, v2, v3, v4, v5, v6;
			int sl, fp;
			double d8, d9, d10, d11, d12, d13, d14, d15;
		}
		// typedef int __jmp_buf[64] __attribute__((__aligned__ (8)));
	} else version (Aarch64) {
		struct __jmp_buf {
			ulong x19, x20, x21, x22, x23, x24, x25, x26,
				x27, x28, x29, lr, sp;
			double d8, d9, d10, d11, d12, d13, d14, d15;
		}

		// __extension__ typedef unsigned long long __jmp_buf [22];
	} else static assert(0, "Missing setjmp definitions (Glibc)");
	
	struct __jmp_buf_tag {
		__jmp_buf __jmpbuf;
		int __mask_was_saved;
		c_long __saved_mask; // __sigset_t: unsigned long int
	}

	public alias __jmp_buf_tag jmp_buf;
} else version (CRuntime_Musl) { // 1.20
	version (X86) {
		// typedef unsigned long __jmp_buf[6];
		alias c_long[6] __jmp_buf;
	} else version (X86_64) {
		// typedef unsigned long __jmp_buf[8];
		alias c_long[8] __jmp_buf;
	} else version (ARM) {
		// typedef unsigned long long __jmp_buf[32];
		alias ulong[32] __jmp_buf;
	} else version (AArch64) {
		// typedef unsigned long __jmp_buf[22];
		alias c_ulong[22] __jmp_buf;
	} else static assert(0, "Missing setjmp definitions (Musl)");

	struct __jmp_buf_tag {
		__jmp_buf __jb;
		ulong __fl;
		ulong[128 / c_long.sizeof] __ss;
	}
	alias __jmp_buf_tag jmp_buf;
} else static assert(0, "Missing setjmp definitions");

/// 
int setjmp(ref jmp_buf);
/// 
void longjmp(ref jmp_buf, int);
