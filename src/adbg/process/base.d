/// Process management
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.base;

// TODO: Internal process flags
//       Has memory handle, process-debugger relation, debugger/process options, etc.
// TODO: Process Pause/Resume
//       Windows: NtSuspendProcess/NtResumeProcess or SuspendThread/ResumeThread
//       Linux: Send SIGSTOP/SIGCONT signals via kill(2)
// TODO: List threads of process (maybe in a module called threading.d)

import adbg.include.c.stdlib; // malloc, calloc, free, exit;
import adbg.include.c.stdarg;
import adbg.error;
import adbg.process.exception : adbg_exception_t, adbg_exception_translate;
import adbg.machines;
import adbg.utils.strings;
import adbg.utils.list;
import core.stdc.string;

version (Windows) {
	import adbg.include.windows.wow64apiset;
	import adbg.include.windows.psapi_dyn;
	import adbg.include.windows.winnt;
	import adbg.include.windows.winbase;
	import adbg.include.windows.tlhelp32;
} else version (Posix) {
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd;
	import adbg.include.posix.sys.wait;
	import adbg.utils.math;
	import core.stdc.ctype : isdigit;
	import core.stdc.errno;
	import core.sys.posix.fcntl;
	import core.sys.posix.dirent;
	import core.sys.posix.libgen : basename;
	import adbg.include.c.stdio;  // snprintf;
	import adbg.platform : ADBG_CHILD_STACK_SIZE;
	import adbg.include.linux.personality;
}

extern (C):

/// Process status
enum AdbgProcStatus : ubyte {
	unknown,	/// Process status is not known.
	unloaded = unknown,	/// Process is unloaded.
	loaded,	/// Process is loaded and waiting to run.
	standby = loaded,	/// Alias for loaded.
	running,	/// Process is running.
	paused,	/// Process is paused due to an exception or by the debugger.
}

//TODO: Rename to AdbgDebuggerRelation
/// Process creation source.
enum AdbgCreation : ubyte {
	unattached,
	unloaded = unattached, // Older alias
	attached,
	spawned,
}

/// Represents an instance of a process.
struct adbg_process_t {
version (Windows) { // Original identifiers; Otherwise informal
	// NOTE: PID and TID usage
	//       The Process and Thread IDs are used to open handles
	//       This is done on a per-function basis for permissions
	//       and memory management (opening and closing handles)
	//       purposes.
	int pid;	/// Process identificiation number
	int tid;	/// Thread identification number
	char *args;	/// Saved arguments when process was launched
	// TODO: Deprecate hpid and htid
	HANDLE htid;	/// Thread handle
	HANDLE hpid;	/// Process handle
}
version (Posix) {
	pid_t pid;	/// Process ID
	char **argv;	/// Saved arguments when process was launched
}
version (linux) {
	int mhandle;	/// Internal memory file handle to /proc/PID/mem
	bool memfailed;	/// Set if we fail to open /proc/PID/mem
}
	/// Last known process status.
	AdbgProcStatus status;
	/// Process' creation source.
	AdbgCreation creation;
	/// List of threads
	list_t *thread_list;
}

void adbg_process_free(adbg_process_t *proc) {
	if (proc == null)
		return;
	version (Windows) {
		if (proc.args) free(proc.args);
		CloseHandle(proc.hpid);
		CloseHandle(proc.htid);
	}
	version (Posix) {
		if (proc.argv) free(proc.argv);
		version (linux) if (proc.mhandle) close(proc.mhandle);
	}
	adbg_list_free(proc.thread_list);
	free(proc);
}

/// Get the debuggee's current status.
/// Params: tracee = Debugged process.
/// Returns: Debuggee status.
AdbgProcStatus adbg_process_status(adbg_process_t *tracee) pure {
	if (tracee == null) return AdbgProcStatus.unknown;
	return tracee.status;
}
/// Get the debuggee current status as a string.
/// Params: tracee = Debugged process.
/// Returns: Debuggee status string.
const(char)* adbg_process_status_string(adbg_process_t *tracee) pure {
	static immutable const(char) *default_ = "unknown";
	if (tracee == null)
		return default_;
	const(char) *m = void;
	switch (tracee.status) with (AdbgProcStatus) {
	case unloaded:	m = "unloaded"; break;
	case loaded:	m = "loaded"; break;
	case running:	m = "running"; break;
	case paused:	m = "paused"; break;
	default:	return default_;
	}
	return m;
}

/// Get the process ID.
/// Params: proc = Process instance.
/// Returns: PID or 0 on error.
int adbg_process_pid(adbg_process_t *proc) {
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
	version (Trace)
		trace("pid=%d buffer=%p bufsize=%zd base=%d", pid, buffer, bufsize, absolute);
	
	if (proc == null || buffer == null || bufsize == 0) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	
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

/// Get the current runtime machine platform.
///
/// This is useful when the debugger is dealing with a process running
/// under a subsystem such as WoW or lib32-on-linux64 programs.
/// Params: proc = Debuggee process.
/// Returns: Machine platform.
AdbgMachine adbg_process_machine(adbg_process_t *proc) {
	if (proc == null)
		return AdbgMachine.unknown;
	
version (Win64) {
	// TODO: Check with IsWow64Process2 when able
	//       Important for AArch32 support on AArch64
	//       with GetProcAddress("kernel32", "IsWow64Process2")
	//       Introduced in Windows 10, version 1511
	//       IsWow64Process: 32-bit proc. under aarch64 returns FALSE
	BOOL w64 = void;
	version (X86_64)  if (IsWow64Process(proc.hpid, &w64) && w64) return AdbgMachine.i386;
	version (AArch64) if (IsWow64Process(proc.hpid, &w64) && w64) return AdbgMachine.arm;
}
version (linux) {
	char[64] path = void;
	if (snprintf(path.ptr, 64, "/proc/%d/personality", proc.pid) <= 0)
		return adbg_machine_default();
	int fd = open(path.ptr, O_RDONLY);
	if (fd < 0)
		return adbg_machine_default();
	if (read(fd, path.ptr, 8)) // re-use buffer that's no longer needed
		return adbg_machine_default();
	path[8] = 0;
	char *end = void;
	uint personality = cast(uint)strtol(path.ptr, &end, 16);
	version (X86_64)  if (personality & ADDR_LIMIT_32BIT) return AdbgMachine.i386;
	version (AArch64) if (personality & ADDR_LIMIT_32BIT) return AdbgMachine.arm;
}
	return adbg_machine_default();
}

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
		adbg_list_free(list);
		adbg_oops(AdbgError.os);
		return null;
	}
	scope(exit) CloseHandle(hsnap);
	
	PROCESSENTRY32 proc = void;
	if (Process32First(hsnap, &proc) == FALSE) {
		adbg_list_free(list);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	adbg_process_t t = void;
	memset(&t, 0, adbg_process_t.sizeof);
	do {
		// Ignore Idle and System
		switch (proc.th32ProcessID) {
		case 0, 4: continue;
		default:
		}
		
		t.pid = proc.th32ProcessID;
		t.hpid = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, proc.th32ProcessID);
		list = adbg_list_add(list, &t);
	} while (Process32Next(hsnap, &proc));
	
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
	
version (Windows) {
	list_t *list = cast(list_t*)proclist;
	adbg_process_t *proc = void;
	for (size_t i; (proc = cast(adbg_process_t*)adbg_list_get(list, i)) != null; ++i) {
		CloseHandle(proc.hpid);
	}
}
	
	adbg_list_free(cast(list_t*)proclist);
}
