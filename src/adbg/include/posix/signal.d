/// Missing POSIX signal definitions.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.posix.signal;

version (CRuntime_Glibc) { // 2.25
	public import core.sys.posix.signal :
		siginfo_t,
		SIGSEGV, SIGFPE, SIGILL, SIGINT, SIGTERM, SIGABRT,
		SIGTRAP, SIGBUS;
} else version (CRuntime_Musl) { // 1.20
	enum SIGHUP	= 1;	/// 
	enum SIGINT	= 2;	/// 
	enum SIGQUIT	= 3;	/// 
	enum SIGILL	= 4;	/// 
	enum SIGTRAP	= 5;	/// 
	enum SIGABRT	= 6;	/// 
	enum SIGIOT	= SIGABRT;	/// 
	enum SIGBUS	= 7;	/// 
	enum SIGFPE	= 8;	/// 
	enum SIGKILL	= 9;	/// 
	enum SIGUSR1	= 10;	/// 
	enum SIGSEGV	= 11;	/// 
	enum SIGUSR2	= 12;	/// 
	enum SIGPIPE	= 13;	/// 
	enum SIGALRM	= 14;	/// 
	enum SIGTERM	= 15;	/// 
	enum SIGSTKFLT	= 16;	/// 
	enum SIGCHLD	= 17;	/// 
	enum SIGCONT	= 18;	/// 
	enum SIGSTOP	= 19;	/// 
	enum SIGTSTP	= 20;	/// 
	enum SIGTTIN	= 21;	/// 
	enum SIGTTOU	= 22;	/// 
	enum SIGURG	= 23;	/// 
	enum SIGXCPU	= 24;	/// 
	enum SIGXFSZ	= 25;	/// 
	enum SIGVTALRM	= 26;	/// 
	enum SIGPROF	= 27;	/// 
	enum SIGWINCH	= 28;	/// 
	enum SIGIO	= 29;	/// 
	enum SIGPOLL	= 29;	/// 
	enum SIGPWR	= 30;	/// 
	enum SIGSYS	= 31;	/// 
	enum SIGUNUSED	= SIGSYS;	/// 
}

public import core.sys.posix.signal;