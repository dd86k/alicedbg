/**
 * SEH wrapper for Posix
 */
module os.posix.seh;

version (Posix):

import debugger.exception : exception_t;

import core.sys.posix.signal;
import core.sys.posix.ucontext;
import core.stdc.stdio : printf;
import core.stdc.stdlib : exit;
//import os.setjmp;

extern (C):
__gshared:

/// 
/// 
/// 
public int seh_init(void function(exception_t*) f) {
	sigaction_t sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &pe_sigaction;
	if (sigaction(SIGSEGV, &sa, cast(sigaction_t*)0) == -1 ||
		sigaction(SIGTRAP, &sa, cast(sigaction_t*)0) == -1 ||
		sigaction(SIGFPE, &sa, cast(sigaction_t*)0) == -1 ||
		sigaction(SIGILL, &sa, cast(sigaction_t*)0) == -1) {
		return 1;
	}

	//externhandler = f;
	//TODO: Set externhandler

	return 0;
}

private:

void function(exception_t*) externhandler;

/// See http://man7.org/linux/man-pages/man2/sigaction.2.html
void pe_sigaction(int sig, siginfo_t *si, void *p) {
	ucontext_t *ctx = cast(ucontext_t*)p;
	mcontext_t m = ctx.uc_mcontext;

	version (X86)
	printf(
	"\n"~
	"*************\n" ~
	"* EXCEPTION *\n" ~
	"*************\n" ~
	"Code: %X  Address: %X\n" ~
	"EIP=%08X  EFLAG=%08X\n" ~
	"EAX=%08X  EBX=%08X  ECX=%08X  EDX=%08X\n" ~
	"EDI=%08X  ESI=%08X  EBP=%08X  ESP=%08X\n" ~
	"CS=%04X  DS=%04X  ES=%04X  FS=%04X  GS=%04X  SS=%04X\n",
	sig, cast(uint)si._sifields._sigfault.si_addr,
	m.gregs[REG_EIP], m.gregs[REG_EFL],
	m.gregs[REG_EAX], m.gregs[REG_EBX], m.gregs[REG_ECX], m.gregs[REG_EDX],
	m.gregs[REG_EDI], m.gregs[REG_ESI], m.gregs[REG_EBP], m.gregs[REG_ESP],
	m.gregs[REG_CS], m.gregs[REG_DS], m.gregs[REG_ES],
	m.gregs[REG_FS], m.gregs[REG_GS], m.gregs[REG_SS],
	);
	else
	version (X86_64)
	printf(
	"\n"~
	"*************\n" ~
	"* EXCEPTION *\n" ~
	"*************\n" ~
	"Code: %X  Address: %lX\n" ~
	"RIP=%016lX  EFLAG=%08X\n" ~
	"RAX=%016lX  RBX=%016lX  RCX=%016lX  RDX=%016lX\n" ~
	"RDI=%016lX  RSI=%016lX  RBP=%016lX  RSP=%016lX\n" ~
	" R8=%016lX   R9=%016lX  R10=%016lX  R11=%016lX\n" ~
	"R12=%016lX  R13=%016lX  R14=%016lX  R15=%016lX\n" ~
	"CS=%04X  GS=%04X  FS=%04X\n",
	sig, cast(ulong)si._sifields._sigfault.si_addr,
	m.gregs[REG_RIP], m.gregs[REG_EFL],
	m.gregs[REG_RAX], m.gregs[REG_RBX], m.gregs[REG_RCX], m.gregs[REG_RDX],
	m.gregs[REG_RDI], m.gregs[REG_RSI], m.gregs[REG_RBP], m.gregs[REG_RSP],
	m.gregs[REG_R8],  m.gregs[REG_R9],  m.gregs[REG_R10], m.gregs[REG_R11],
	m.gregs[REG_R12], m.gregs[REG_R13], m.gregs[REG_R14], m.gregs[REG_R15],
	cast(ushort)m.gregs[REG_CSGSFS],
	cast(ushort)(m.gregs[REG_CSGSFS] >> 16),
	cast(ushort)(m.gregs[REG_CSGSFS] >> 32),
	);

	exit(sig);
}
