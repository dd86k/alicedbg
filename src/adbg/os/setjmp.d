/**
 * setjmp.h wrapper binding to the C runtime.
 *
 * This brings back the setjmp wrapper that D once had at std.c.setjmp (~v0.91,
 * found at https://forum.dlang.org/post/c7fb8q$25oi$1@digitaldaemon.com),
 * which should of been at core.stdc.setjmp by now, but is nowhere to be found.
 * In fact, there are bindings in core.stdc.posix.setjmp, so recent that it
 * includes RISC-V, but alas, no Windows version to be found.
 *
 * What's more scary is that, upon downloading the old 0.9x archives held
 * nothing for a std.c.setjmp module.
 * 
 * Windows reference:
 * - "[VisualStudio]\VC\Tools\MSVC\14.15.26726\include\setjmp.h"
 * - "[VisualStudio]\VC\Tools\MSVC\14.16.27023\include\setjmp.h"
 * Glibc reference:
 * - jmp_buf structures: sysdeps/{arch}/jmpbuf-offsets.h
 * - jmp_buf definitions: sysdeps/{arch}/bits/setjmp.h
 *
 * License: BSD 3-Clause
 */
module adbg.os.setjmp;

private import core.stdc.config : c_long;

extern (C):

version (Windows) {
	version (X86) {
		enum _JBLEN = 16;
		alias int _JBTYPE;

		struct __JUMP_BUFFER {
			c_long Ebp, Ebx, Edi, Esi, Esp, Eip, Registration,
				TryLevel, Cookie, UnwindFunc;
			c_long [6]UnwindData;
		}
	} else
	version (X86_64) {
		enum _JBLEN = 16;
		alias _SETJMP_FLOAT128 _JBTYPE;

		struct _SETJMP_FLOAT128 { align(16):
			ulong [2]Part;
		}

		struct _JUMP_BUFFER {
			ulong Frame, Rbx, Rsp, Rbp, Rsi, Rdi,
				R12, R13, R14, R15, Rip;
			uint MxCsr;
			ushort FpCsr;
			ushort Spare;
			_SETJMP_FLOAT128 Xmm6, Xmm7, Xmm8, Xmm9, Xmm10,
				Xmm11, Xmm12, Xmm13, Xmm14, Xmm15;
		}
	} else
	version (ARM) {
		enum _JBLEN = 28;
		alias int _JTYPE;

		struct _JUMP_BUFFER {
			uint Frame, R4, R5, R6, R7, R8, R9, R10, R11,
				Sp, Pc, Fpscr;
			ulong [8]D; // D8-D15 VFP/NEON regs
		}
	} else
	version (Aarch64) {
		enum _JBLEN = 24;
		alias int _JTYPE;

		struct _JUMP_BUFFER {
			ulong Frame, Reserved,
				X19, X20, X21, X22, X23, // x19 -- x28
				X24, X25, X26, X27, X28, // callee saved registers
				Fp,	// x29 frame pointer
				Lr,	// x30 link register
				Sp;	// x31 stack pointer
			uint Fpcr;	// fp control register
			uint Fpsr;	// fp status register
			double [8]D;	// D8-D15 FP regs
		}
	} else
	static assert(0, "Missing setjmp definitions (Windows)");

	// typedef _JBTYPE jmp_buf[_JBLEN];
	public alias _JBTYPE[_JBLEN] jmp_buf;
} else
version (CRuntime_Glibc) {
	version (X86) {
		struct __jmp_buf {
			uint ebx, esi, edi, ebp, esp, eip;
		}

		// typedef int __jmp_buf[6];
		public alias int[6] jmp_buf;
	} else
	version (X86_64) {
		struct __jmp_buf {
			ulong rbx, rbp, r12, r13, r14, r15, rsp, rip;
		}

		// __extension__ typedef long long int __jmp_buf[8];
		public alias ulong[8] jmp_buf;
	} else
	version (ARM) {
		// NOTE: Glibc sysdeps/arm/jmpbuf-unwind.h DOESN'T define a structure
		//       So this is made purely out of the description given
		struct __i128 {
			union {
				ubyte [16]b; ushort [8]h;
				uint [4]d; ulong [2]q;
			}
		}
		// "The first 26 words are occupied by sp, lr, v1-v6, sl, fp,
		// and d8-d15."
		struct __jmp_buf {
			uint sp, lr;
			__i128 v1, v2, v3, v4, v5, v6;
			uint sl, fp;
			double d8, d9, d10, d11, d12, d13, d14, d15;
		}
		// typedef int __jmp_buf[64] __attribute__((__aligned__ (8)));
		alias int[64] jmp_buf;
	} else
	version (Aarch64) {
		struct __jmp_buf {
			ulong x19, x20, x21, x22, x23, x24, x25, x26,
				x27, x28, x29, lr, sp;
			double d8, d9, d10, d11, d12, d13, d14, d15;
		}

		// __extension__ typedef unsigned long long __jmp_buf [22];
		alias ulong[22] jmp_buf;
	} else
	static assert(0, "Missing setjmp definitions (Glibc)");
} else
version (CRuntime_Musl) {
	struct __jmp_buf_tag {
		__jmp_buf __jb;
		ulong __fl;
		ulong[128/long.sizeof] __ss;
	}
	alias __jmp_buf_tag jmp_buf;
} else
static assert(0, "Missing setjmp definitions");

int setjmp(ref jmp_buf e);
void longjmp(ref jmp_buf e, int s);

unittest {
	jmp_buf j = void;
	int e = setjmp(j);
	if (e) {
		assert(e == 0xdd);
	} else {
		longjmp(j, 0xdd);
		assert(0);
	}
}