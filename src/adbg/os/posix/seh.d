/**
 * SEH wrapper for Posix
 *
 * License: BSD 3-clause
 */
module adbg.os.posix.seh;

version (Posix):

import adbg.debugger.exception;
import adbg.os.setjmp;
import core.sys.posix.signal;
import core.sys.posix.ucontext;

//TODO: adbg_seh_set (Posix)

extern (C):
__gshared:

struct checkpoint_t {
	jmp_buf buffer;
	int value;
	exception_t exception;
}

public int adbg_seh_set(checkpoint_t *c) {
	import core.stdc.string : memcpy;
	if (sehinit == false) {
		sigaction_t sa = void;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_SIGINFO;
		sa.sa_sigaction = &adbg_seh_action;
		if (sigaction(SIGSEGV, &sa, cast(sigaction_t*)0) == -1 ||
			sigaction(SIGTRAP, &sa, cast(sigaction_t*)0) == -1 ||
			sigaction(SIGFPE, &sa, cast(sigaction_t*)0) == -1 ||
			sigaction(SIGILL, &sa, cast(sigaction_t*)0) == -1 ||
			sigaction(SIGBUS, &sa, cast(sigaction_t*)0) == -1) {
			return 1;
		}
		sehinit = true;
	}
//	memcpy(&mjbuf, &c.buffer, jmp_buf.sizeof);
//	if ((c.value = setjmp(mjbuf)) != 0)
//		memcpy(&c.exception, &mexception, exception_t.sizeof);
	return 0;
}

private:

jmp_buf mjbuf;
exception_t mexception;
bool sehinit;

/// See http://man7.org/linux/man-pages/man2/sigaction.2.html
void adbg_seh_action(int sig, siginfo_t *si, void *p) {
	ucontext_t *ctx = cast(ucontext_t*)p;
	mcontext_t *m = &ctx.uc_mcontext;

	mexception.oscode = sig;
	// HACK: Missing ref'd D bindings to Musl
	version (CRuntime_Glibc)
		mexception.addr = si._sifields._sigfault.si_addr;
	else version (CRuntime_Musl)
		mexception.addr = si.__si_fields.__sigfault.si_addr;
	else static assert(0, "hack me");

	mexception.pid = mexception.tid = 0;
	adbg_ex_ctx_init(&mexception, InitPlatform.Native);
	version (X86) {
		mexception.regcount = 10;
		version (CRuntime_Glibc) {
			mexception.registers[0].u32 = m.gregs[REG_EIP];
			mexception.registers[1].u32 = m.gregs[REG_EFL];
			mexception.registers[2].u32 = m.gregs[REG_EAX];
			mexception.registers[3].u32 = m.gregs[REG_EBX];
			mexception.registers[4].u32 = m.gregs[REG_ECX];
			mexception.registers[5].u32 = m.gregs[REG_EDX];
			mexception.registers[6].u32 = m.gregs[REG_ESP];
			mexception.registers[7].u32 = m.gregs[REG_EBP];
			mexception.registers[8].u32 = m.gregs[REG_ESI];
			mexception.registers[9].u32 = m.gregs[REG_EDI];
			/*
			m.gregs[REG_CS], m.gregs[REG_DS], m.gregs[REG_ES],
			m.gregs[REG_FS], m.gregs[REG_GS], m.gregs[REG_SS],
			*/
		} else
		version (CRuntime_Musl) {
			mexception.registers[0].u32 = m.__space[REG_EIP];
			mexception.registers[1].u32 = m.__space[REG_EFL];
			mexception.registers[2].u32 = m.__space[REG_EAX];
			mexception.registers[3].u32 = m.__space[REG_EBX];
			mexception.registers[4].u32 = m.__space[REG_ECX];
			mexception.registers[5].u32 = m.__space[REG_EDX];
			mexception.registers[6].u32 = m.__space[REG_ESP];
			mexception.registers[7].u32 = m.__space[REG_EBP];
			mexception.registers[8].u32 = m.__space[REG_ESI];
			mexception.registers[9].u32 = m.__space[REG_EDI];
		}
	} else
	version (X86_64) {
		mexception.regcount = 18;
		version (CRuntime_Glibc) {
			mexception.registers[0].u64 = m.gregs[REG_RIP];
			mexception.registers[1].u32 = cast(uint)m.gregs[REG_EFL];
			mexception.registers[2].u64 = m.gregs[REG_RAX];
			mexception.registers[3].u64 = m.gregs[REG_RBX];
			mexception.registers[4].u64 = m.gregs[REG_RCX];
			mexception.registers[5].u64 = m.gregs[REG_RDX];
			mexception.registers[6].u64 = m.gregs[REG_RSP];
			mexception.registers[7].u64 = m.gregs[REG_RBP];
			mexception.registers[8].u64 = m.gregs[REG_RSI];
			mexception.registers[9].u64 = m.gregs[REG_RDI];
			mexception.registers[10].u64 = m.gregs[REG_R8];
			mexception.registers[11].u64 = m.gregs[REG_R9];
			mexception.registers[12].u64 = m.gregs[REG_R10];
			mexception.registers[13].u64 = m.gregs[REG_R11];
			mexception.registers[14].u64 = m.gregs[REG_R12];
			mexception.registers[15].u64 = m.gregs[REG_R13];
			mexception.registers[16].u64 = m.gregs[REG_R14];
			mexception.registers[17].u64 = m.gregs[REG_R15];
			/*
			cast(ushort)m.gregs[REG_CSGSFS],
			cast(ushort)(m.gregs[REG_CSGSFS] >> 16),
			cast(ushort)(m.gregs[REG_CSGSFS] >> 32),
			*/
		} else
		version (CRuntime_Musl) {
			mexception.registers[0].u64 = m.__space[16];
			mexception.registers[1].u32 = cast(uint)m.__space[17];
			mexception.registers[2].u64 = m.__space[13];
			mexception.registers[3].u64 = m.__space[11];
			mexception.registers[4].u64 = m.__space[14];
			mexception.registers[5].u64 = m.__space[12];
			mexception.registers[6].u64 = m.__space[15];
			mexception.registers[7].u64 = m.__space[10];
			mexception.registers[8].u64 = m.__space[9];
			mexception.registers[9].u64 = m.__space[8];
			mexception.registers[10].u64 = m.__space[0];
			mexception.registers[11].u64 = m.__space[1];
			mexception.registers[12].u64 = m.__space[2];
			mexception.registers[13].u64 = m.__space[3];
			mexception.registers[14].u64 = m.__space[4];
			mexception.registers[15].u64 = m.__space[5];
			mexception.registers[16].u64 = m.__space[6];
			mexception.registers[17].u64 = m.__space[7];
		}
	}
//	longjmp(&mjbuf, 1);
}
