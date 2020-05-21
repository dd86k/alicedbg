/**
 * SEH wrapper for Posix
 *
 * License: BSD 3-Clause
 */
module adbg.os.posix.seh;

version (Posix):

import core.sys.posix.signal;
import core.sys.posix.ucontext;
import adbg.debugger.exception;
import adbg.os.setjmp;

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
		sigaction_t sa;
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
	mexception.addr = si._sifields._sigfault.si_addr;
	mexception.pid = mexception.tid = 0;
	adbg_ex_ctx_init(&mexception, InitPlatform.Native);
	version (X86) {
		mexception.regcount = 10;
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
	version (X86_64) {
		mexception.regcount = 18;
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
	}
//	longjmp(&mjbuf, 1);
}
