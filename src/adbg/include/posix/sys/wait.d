/// Fixing improper sys/wait.h definitions.
///
/// Existing definitions are defined with extern (D), which tricks the
/// compiler to define it as an external function, leading to linking issues.
///
/// This module defines these macros, as inlined functions:
/// WEXITSTATUS, WTERMSIG, WSTOPSIG, WIFEXITED, WIFSIGNALED, WIFSTOPPED,
/// WIFCONTINUED, and WCOREDUMP.
///
/// It also defines these values to be used in wait(2) functions:
/// WNOHANG, WUNTRACED, WSTOPPED, WCONTINUED, WNOWAIT, WEXITED, and WTRAPPED
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.posix.sys.wait;

version (Posix):

public import core.sys.posix.sys.wait;

pragma(inline, true):

version (linux) {
	// NOTE: wstatus
	//       Bits  Description (Linux)
	//       6:0   Signo that caused child to exit
	//             0x7f if child stopped/continued
	//             or zero if child exited without signal
	//        7    Core dumped
	//       15:8  exit value (or returned main value)
	//             or signal that cause child to stop/continue
	
	// Shared at least across Glibc and Musl
	enum WNOHANG    = 1;
	enum WUNTRACED  = 2;
	
	enum WSTOPPED   = 2;
	enum WEXITED    = 4;
	enum WCONTINUED = 8;
	enum WNOWAIT    = 0x1000000;
	
	enum __WNOTHREAD = 0x20000000;
	enum __WALL      = 0x40000000;
	enum __WCLONE    = 0x80000000;
		
	int WEXITSTATUS(int s)	{ return (s & 0xff00) >> 8; }
	int WTERMSIG(int s)	{ return s & 0x7f; }
	int WSTOPSIG(int s)	{ return WEXITSTATUS(s); }
	
	bool WIFCONTINUED(int s)	{ return s == 0xffff; }
	
	int WCOREDUMP(int s)	{ return s & 0x80; }
	
	version (CRuntime_Glibc) {
		// Source: bits/waitstatus.h
		//         sysdeps/unix/sysv/linux/bits/waitflags.h
		
		bool WIFEXITED(int s)	{ return WTERMSIG(s) == 0; }
		bool WIFSIGNALED(int s)	{ return (cast(byte)((s & 0x7f) + 1) >> 1) > 0; }
		bool WIFSTOPPED(int s)	{ return (s & 0xff) == 0x7f; }
		
		/*
		#define	__W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
		#define	__W_STOPCODE(sig)	((sig) << 8 | 0x7f)
		*/
	} else version (CRuntime_Musl) {
		// Source: include/sys/wait.h
		
		bool WIFEXITED(int s)	{ return !WTERMSIG(s); }
		bool WIFSIGNALED(int s)	{ return (s&0xffff)-1U < 0xffu; }
		bool WIFSTOPPED(int s)	{ return cast(short)(((s&0xffff)*0x10001U)>>8) > 0x7f00; }
	} else static assert(0, "Define wait.h macros (Linux)");
} else version (FreeBSD) {
	// Source: sys/sys/wait.h
	
	enum WNOHANG	= 1;
	enum WUNTRACED	= 2;
	enum WSTOPPED	= WUNTRACED;
	enum WCONTINUED	= 4;
	enum WNOWAIT	= 8;
	enum WEXITED	= 16;
	enum WTRAPPED	= 32;
	
	enum WLINUXCLONE	= 0x80000000; // Wait for kthread spawned from linux_clone.
	
	enum _WSTOPPED	= 0x7f; // 0177, _WSTATUS if process is stopped
	
	int _WSTATUS(int x)	{ return x & 0x7f; } // 0177
	
	int WEXITSTATUS(int x)	{ return x >> 8; }
	int WTERMSIG(int x)	{ return _WSTATUS(x); }
	alias WSTOPSIG = WEXITSTATUS;
	
	bool WIFSTOPPED(int x)	{ return _WSTATUS(x) == _WSTOPPED; }
	bool WIFSIGNALED(int x)	{ return _WSTATUS(x) != _WSTOPPED && _WSTATUS(x) != 0 && x != 0x13; }
	bool WIFEXITED(int x)	{ return _WSTATUS(x) == 0; }
	
	bool WIFCONTINUED(int x)	{ return x == 0x13; }	// 0x13 == SIGCONT
	
	// #if __BSD_VISIBLE
	int WCOREDUMP(int x)	{ return x & 0x80; }
	
	/*
	#define	W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
	#define	W_STOPCODE(sig)		((sig) << 8 | _WSTOPPED)
	*/
} else static assert(0, "Define wait.h macros");