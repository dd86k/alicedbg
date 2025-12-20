/// Process management
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.base;

// TODO: Internal process flags
//       - Debugger is active on this process
//       - Debugger is attached to this process
//       - Process is stopped from an external event (one or more threads are stopped)
//       - Process is paused from debugger
//       - Process exited
//       - Memory handle is opened on this process
// TODO: Process Pause/Resume
//       Windows: NtSuspendProcess/NtResumeProcess or SuspendThread/ResumeThread
//       Linux: Send SIGSTOP/SIGCONT signals via kill(2)
// TODO: Functions to spawn process without debugger.
// TODO: Functions to attach process without debugger.
// TODO: Rename module to adbg.process.process.

import adbg.include.c.stdlib; // malloc, calloc, free, exit;
import adbg.include.c.stdarg;
import adbg.error;
import adbg.machines;
import adbg.utils.list;
import adbg.process.exception : adbg_exception_t;
import core.stdc.string : memset;

version (Windows) {
	import adbg.include.windows.winbase;
	import adbg.include.windows.tlhelp32;
} else version (Posix) {
	import adbg.include.posix.unistd;
	import core.stdc.ctype : isdigit;
	import core.sys.posix.fcntl;
	import core.sys.posix.dirent;
	import adbg.include.c.stdio;  // snprintf;
	import adbg.include.linux.personality;
}

extern (C):

/// Process status
enum AdbgProcessState : ubyte {
	unknown,	/// Process status is not known.
	created,	/// Process was created by debugger and waiting to run.
	running,	/// Process is running.
	stopped,	/// Process is paused due to an exception or by the debugger.
	exited,	/// Process exited.
}

/// Process creation source.
enum AdbgCreation : ubyte {
	unattached,
	unloaded = unattached, // Older alias
	attached,
	spawned,
}

package enum {
	/// Debugger is attached.
	ADBG_PROCESS_ATTACHED = 1,
	/// Process has stopped.
	ADBG_PROCESS_STOPPED  = 1 << 1,
	/// Process has exited.
	ADBG_PROCESS_EXITED   = 1 << 2,
}

package enum {
	/// Linux: /proc/PID/mem couldn't be opened, so do not depend on it
	__PROC_STATUS_NO_PROC_MEM = 1 << 16,
}

// TODO: Any params used to spawn/attach to a process SHOULD be held in a new structure
//       Either "adbg_debugger_t" (if generic oriented) or "adbg_tracee_t"
//       adbg_process_t should only have PID.
/// Represents an instance of a process.
struct adbg_process_t {
version (Windows) {
	DWORD orig_pid;	/// Original Process ID created by debugger
	HANDLE orig_handle;	/// Original Process Handle
	char *orig_args;	/// Saved arguments when process was launched
	DWORD pid;	/// Process ID
	uint option_timeout;
}
version (Posix) {
	pid_t orig_pid;	/// Original spawned PID
	char **orig_argv;	/// Saved arguments when process was launched
	pid_t pid;	/// Event Process ID
			// On Linux, the starting thread ID is the same as the process ID
}
version (linux) {
	int procmemfd;	/// Internal memory file handle to /proc/PID/mem
	deprecated alias mhandle = procmemfd; // Older alias
}
	/// Internal status
	int status;
	
	// TODO: Remove state & creation to rely on statuses
	//       - debugger attached
	//       - process is stopped
	//       - process exited
	/// Last known process status.
	deprecated AdbgProcessState state;
	/// Process' creation source.
	deprecated AdbgCreation creation;
	
	// HACK: Event user data (when attached in wait)
	void *udata;
}

void adbg_process_free(adbg_process_t *proc) {
	version(Trace) trace("proc=%p", proc);
	if (proc == null)
		return;
	version (Windows) {
		if (proc.orig_args) free(proc.orig_args);
		CloseHandle(proc.orig_handle);
	}
	version (Posix) {
		if (proc.orig_argv) free(proc.orig_argv);
	}
	version (linux) {
		if (proc.procmemfd) close(proc.procmemfd);
	}
	free(proc);
}

/// Get the debuggee's current status.
/// Params: tracee = Debugged process.
/// Returns: Debuggee status.
AdbgProcessState adbg_process_status(adbg_process_t *tracee) pure {
	if (tracee == null) return AdbgProcessState.unknown;
	return tracee.state;
}
/// Get the debuggee current status as a string.
/// Params: tracee = Debugged process.
/// Returns: Debuggee status string.
const(char)* adbg_process_status_string(adbg_process_t *tracee) pure {
	static immutable const(char) *default_ = "unknown";
	if (tracee == null)
		return default_;
	final switch (tracee.state) with (AdbgProcessState) {
	case created:	return "created";
	case running:	return "running";
	case stopped:	return "stopped";
	case exited:	return "exited";
	case unknown:	return default_;
	}
}

/// Get the process ID.
/// Params: proc = Process instance.
/// Returns: PID or 0 on error.
int adbg_process_id(adbg_process_t *proc) {
	if (proc == null) return 0;
	return proc.pid;
}

/// Get the process file path.
///
/// The string is null-terminated.
/// Params:
/// 	proc = Process instance.
/// 	buffer = Buffer.
/// 	bufsize = Size of the buffer.
/// Returns: String length; Or zero on error.
size_t adbg_process_path(adbg_process_t *proc, char *buffer, size_t bufsize) {
	version(Trace) trace("proc=%p buffer=%p bufsize=%zd", proc, buffer, bufsize);
	
	if (proc == null || buffer == null || bufsize == 0) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	
	version(Trace) trace("pid=%d", proc.pid);
	
version (Windows) {
	// Get process handle
	HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, proc.pid);
	if (hproc == null) {
		adbg_oops(AdbgError.os);
		return 0;
	}
	scope(exit) CloseHandle(hproc);
	
	// NOTE: Process path
	//       GetModuleFileNameA: Requires module handle
	//       GetProcessImageFileNameA: Returns native path (not Win32 path)
	//       QueryFullProcessImageNameA: Works fine for now
	
	DWORD r = cast(DWORD)bufsize;
	if (QueryFullProcessImageNameA(hproc, 0, buffer, &r) == FALSE) {
		adbg_oops(AdbgError.os);
		return 0;
	}
	return r;
} else version (linux) {
	enum PATHBFSZ = 32; // int.min is "-2147483648", 11 chars
	char[PATHBFSZ] pathbuf = void; // Path buffer
	
	// NOTE: procfs process paths
	//       /exe: Link to executable
	//       /cmdline: Process command line as invoked
	//       /comm: Default program name or thread-set name
	
	// readlink does not append null, this is done later
	snprintf(pathbuf.ptr, PATHBFSZ, "/proc/%d/exe", proc.pid);
	ssize_t r = readlink(pathbuf.ptr, buffer, bufsize);
	if (r < 0) {
		adbg_oops(AdbgError.crt);
		return 0;
	}
	buffer[r] = 0;
	return r;
} else {
	adbg_oops(AdbgError.unimplemented);
	return 0;
}
}

version (X86_64) {
	private enum PERSO32 = AdbgMachine.i386;
	version (Win64) version = WinPersonality;
	version (linux) version = LinuxPersonality;
}
version (AArch64) {
	private enum PERSO32 = AdbgMachine.arm;
	version (Win64) version = WinPersonality; // V2 when IsWow64Process2 avail
	version (linux) version = LinuxPersonality;
}

/// Get the current runtime machine platform.
///
/// This is useful when the debugger is dealing with a process running
/// under a subsystem such as WoW or lib32-on-linux64 programs.
/// Params: proc = Process instance.
/// Returns: Machine platform.
AdbgMachine adbg_process_machine(adbg_process_t *proc) {
	if (proc == null)
		return AdbgMachine.unknown;
	
version (WinPersonality) {
	HANDLE phandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, cast(DWORD)proc.pid);
	if (phandle) {
		scope(exit) CloseHandle(phandle);
		// TODO: Check with IsWow64Process2 when able
		//       Important for AArch32 support on AArch64
		//       with GetProcAddress("kernel32", "IsWow64Process2")
		//       Introduced in Windows 10, version 1511
		//       IsWow64Process: 32-bit proc. under aarch64 returns FALSE
		BOOL w64 = void;
		if (IsWow64Process(phandle, &w64) && w64) return PERSO32;
	}
}
version (LinuxPersonality) {
	char[64] path = void;
	if (snprintf(path.ptr, 64, "/proc/%d/personality", proc.pid) <= 0)
		return adbg_machine_current();
	int fd = open(path.ptr, O_RDONLY);
	if (fd < 0)
		return adbg_machine_current();
	enum RDLEN = 16;
	if (read(fd, path.ptr, RDLEN)) // re-use buffer that's no longer needed
		return adbg_machine_current();
	path[RDLEN] = 0;
	char *end = void;
	uint personality = cast(uint)strtol(path.ptr, &end, 16);
	enum LINUX32 = PER_LINUX_32BIT | PER_LINUX32 | PER_LINUX32_3GB;
	if (personality & LINUX32) return PERSO32;
}
	return adbg_machine_current();
}

//
// Process list
//

/// Create a list of processes running on the system.
/// Returns: Internal list; Or null on error.
void* adbg_process_list_new() {
	enum INITCAP = 32;
version (Windows) {
	list_t *list = adbg_list_new(adbg_process_t.sizeof, INITCAP);
	if (list == null)
		return null;
	
	// NOTE: CreateToolhelp32Snapshot is preferred over EnumProcesses, because:
	//       - There is no additional buffer to create.
	//       - The list is already ordered.
	//       - Using NtQuerySystemInformation would be clunky.
	//         https://gist.github.com/hasherezade/c3f82fb3099fb5d1afd84c9e8831af1e
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnap == INVALID_HANDLE_VALUE) {
		adbg_list_close(list);
		adbg_oops(AdbgError.os);
		return null;
	}
	scope(exit) CloseHandle(hsnap);
	
	PROCESSENTRY32 entry = void;
	if (Process32First(hsnap, &entry) == FALSE) {
		adbg_list_close(list);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	adbg_process_t proc = void;
	memset(&proc, 0, adbg_process_t.sizeof);
	do {
		// Ignore Idle and System
		switch (entry.th32ProcessID) {
		case 0, 4: continue;
		default:
		}
		
		proc.pid = entry.th32ProcessID;
		list = adbg_list_add(list, &proc);
		if (list == null)
			return null;
	} while (Process32Next(hsnap, &entry));
	
	return list;
} else version (linux) {
	list_t *list = adbg_list_new(adbg_process_t.sizeof, INITCAP);
	if (list == null)
		return null;
	
	DIR *procfd = opendir("/proc");
	if (procfd == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	scope (exit) closedir(procfd);
	
	// Populate list
	adbg_process_t t = void;
	memset(&t, 0, adbg_process_t.sizeof);
	for (dirent *procent = void; (procent = readdir(procfd)) != null;) {
		// If not directory starting with a digit, skip entry
		if (procent.d_type != DT_DIR)
			continue;
		if (isdigit(procent.d_name[0]) == 0)
			continue;
		
		t.pid = atoi(procent.d_name.ptr);
		list = adbg_list_add(list, &t);
		if (list == null)
			return null;
	}
	return list;
} else {
	adbg_oops(AdbgError.unimplemented);
	return null;
}
}

/// Get a process out of a list created by `adbg_process_list_new`.
/// Params:
/// 	proclist = List instance.
/// 	index = Item index.
/// Returns: Process instance pointer; Or null on error.
adbg_process_t* adbg_process_list_get(void *proclist, size_t index) {
	if (proclist == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return cast(adbg_process_t*)adbg_list_get(cast(list_t*)proclist, index);
}

/// Close the process list created by `adbg_process_list_new`.
/// Params: proclist = List instance.
void adbg_process_list_close(void *proclist) {
	if (proclist == null) return;
	adbg_list_close(cast(list_t*)proclist);
}
