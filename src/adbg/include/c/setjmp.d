/// setjmp.h binding.
///
/// While there are bindings for posix (core.sys.posix.setjmp), there are none
/// for Windows.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.c.setjmp;

import adbg.include.c.config : c_long, c_ulong, c_longint, c_ulongint;
import adbg.include.d.config : D_FEATURE_NORETURN;

extern (C):
@system:
@nogc:
nothrow:

// {VisualStudio}\VC\Tools\MSVC\14.32.31326\include\setjmp.h
version (Windows) {
	version (X86) {
		private enum _JBLEN = 16;
		private alias int _JBTYPE;

		struct _JUMP_BUFFER {
			int Ebp, Ebx, Edi, Esi, Esp, Eip, Registration,
				TryLevel, Cookie, UnwindFunc;
			int[6] UnwindData;
		}
		
		static assert (_JUMP_BUFFER.sizeof == _JBTYPE.sizeof * _JBLEN);
	} else version (X86_64) {
		//TODO: Fix C0000028 (__chkstk) issue
		//      "An invalid or unaligned stack was encountered during
		//      an unwind operation."
		// Fine on:
		// - dmd-x86_omf
		// - dmd-x86_mscoff
		// - ldc-x86
		// - ldc-x86_64 with setjmpex
		// Crashes on:
		// - dmd-x86_64
		private enum _JBLEN = 16;
		private alias _SETJMP_FLOAT128 _JBTYPE;

		struct _SETJMP_FLOAT128 {
			long[2] Part;
		}

		struct _JUMP_BUFFER {
			align (1):
			ulong Frame, Rbx, Rsp, Rbp, Rsi, Rdi,
				R12, R13, R14, R15, Rip;
			c_ulong MxCsr;
			ushort FpCsr;
			ushort Spare;
			
			align (16):
			_SETJMP_FLOAT128 Xmm6, Xmm7, Xmm8, Xmm9, Xmm10,
				Xmm11, Xmm12, Xmm13, Xmm14, Xmm15;
		}
		
		static assert (_JUMP_BUFFER.sizeof == _JBTYPE.sizeof * _JBLEN);
	} else version (ARM) {
		private enum _JBLEN = 28;
		private alias int _JTYPE;

		struct _JUMP_BUFFER {
			int Frame, R4, R5, R6, R7, R8, R9, R10, R11,
				Sp, Pc, Fpscr;
			long[8] D; // D8-D15 VFP/NEON regs
		}
		
		static assert (_JUMP_BUFFER.sizeof == _JBTYPE.sizeof * _JBLEN);
	} else version (AArch64) {
		private enum _JBLEN = 24;
		private alias int _JTYPE;

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
		
		static assert (_JUMP_BUFFER.sizeof == _JBTYPE.sizeof * _JBLEN);
	} else static assert(0, "Missing setjmp definitions (Windows)");

	public alias _JUMP_BUFFER jmp_buf; // typedef _JBTYPE jmp_buf[_JBLEN];
} else version (CRuntime_Glibc) { // 2.25
	version (X86) { // sysdeps/x86/bits/setjmp.h
		struct __jmp_buf {
			int ebx, esi, edi, ebp, esp, eip;
		}
		// typedef int __jmp_buf[6];
	} else version (X86_64) { // sysdeps/x86_64/jmpbuf-offsets.h
		struct __jmp_buf {
			long rbx, rbp, r12, r13, r14, r15, rsp, rip;
		}
		// typedef unsigned long long __jmp_buf[8]
	} else version (ARM) {
		// sysdeps/arm/bits/setjmp.h
		// sysdebs/arm/include/bits/setjmp.h
		// sysdebs/arm/setjmp.S
		
		// "The exact set of registers saved may depend on the particular core
		// in use, as some coprocessor registers may need to be saved. The C
		// Library ABI requires that the buffer be 8-byte aligned, and
		// recommends that the buffer contain 64 words.  The first 26 words
		// are occupied by sp, lr, v1-v6, sl, fp, and d8-d15."
		union __jmp_buf {
			alias buf this;
			align(8) int[64] buf;
			struct {
				int sp, lr;
				float v1, v2, v3, v4, v5, v6; // VFP registers
				int sl, fp;
				double d8, d9, d10, d11, d12, d13, d14, d15;
			}
		}
		// typedef int __jmp_buf[64] __attribute__((__aligned__ (8)));
		static assert(__jmp_buf.sizeof == int.sizeof * 64);
	} else version (AArch64) { // sysdeps/aarch64/jmpbuf-offsets.h
		struct __jmp_buf {
			ulong x19, x20, x21, x22, x23, x24, x25, x26,
				x27, x28, x29, reserved_, lr, sp;
			double d8, d9, d10, d11, d12, d13, d14, d15;
		}
		// __extension__ typedef unsigned long long __jmp_buf [22];
		static assert(__jmp_buf.sizeof == ulong.sizeof * 22);
	} else static assert(0, "Missing setjmp definitions (Glibc)");
	
	// setjmp/setjmp.h
	// bits/sigset.h
	struct __jmp_buf_tag {
		__jmp_buf __jmpbuf;
		int __mask_was_saved;
		c_ulongint __saved_mask; // typedef unsigned long int __sigset_t;
	}

	public alias __jmp_buf_tag jmp_buf;
} else version (CRuntime_Musl) { // 1.20
	version (X86) {
		alias c_ulong[6] __jmp_buf; // typedef unsigned long __jmp_buf[6];
	} else version (X86_64) {
		alias c_ulong[8] __jmp_buf; // typedef unsigned long __jmp_buf[8];
	} else version (ARM) {
		alias ulong[32] __jmp_buf; // typedef unsigned long long __jmp_buf[32];
	} else version (AArch64) {
		alias c_ulong[22] __jmp_buf; // typedef unsigned long __jmp_buf[22];
	} else static assert(0, "Missing setjmp definitions (Musl)");

	struct __jmp_buf_tag {
		__jmp_buf __jb;
		ulong __fl;
		ulong[128 / c_long.sizeof] __ss;
	}
	alias __jmp_buf_tag jmp_buf;
} else version (CRuntime_Bionic) {
	version (X86) {
		enum _JBLEN = 10;
	} else version (X86_64) {
		enum _JBLEN = 11;
	} else version (ARM) {
		enum _JBLEN = 64;
	} else version (AArch64) {
		enum _JBLEN = 32;
	}
	
	alias jmp_buf = c_long[_JBLEN];
} else static assert(0, "Missing setjmp definitions");

version (Win32) { // Required by DMD, works with LDC
	/// 
	int _setjmp(ref jmp_buf);
	alias setjmp = _setjmp;
} else version (Win64) { // Required by LDC, doesn't work with DMD
	/// 
	int _setjmpex(ref jmp_buf);
	alias setjmp = _setjmpex;
} else {
	/// 
	int setjmp(ref jmp_buf);
}

static if (D_FEATURE_NORETURN) {
	/// 
	noreturn longjmp(ref jmp_buf, int);
} else {
	/// 
	void longjmp(ref jmp_buf, int);
}