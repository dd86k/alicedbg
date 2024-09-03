/// Process management
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.base;

//TODO: Process Pause/Resume
//      Windows: NtSuspendProcess/NtResumeProcess or SuspendThread/ResumeThread
//      Linux: Send SIGSTOP/SIGCONT signals via kill(2)
//TODO: List threads of process (maybe in a module called threading.d)

import adbg.include.c.stdlib; // malloc, calloc, free, exit;
import adbg.include.c.stdarg;
import adbg.error;
import adbg.utils.strings;
import adbg.process.exception : adbg_exception_t, adbg_exception_translate;
import adbg.machines;
import core.stdc.string;

version (Windows) {
	import adbg.include.windows.wow64apiset;
	import adbg.include.windows.psapi_dyn;
	import adbg.include.windows.winnt;
	import core.sys.windows.winbase;
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
}

//version (CRuntime_Glibc)
//	version = USE_CLONE;

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

//TODO: Deprecate and remove static buffer in process struct
enum ADBG_PROCESS_NAME_LENGTH = 256;

/// Represents an instance of a process.
struct adbg_process_t {
	version (Windows) { // Original identifiers; Otherwise informal
		int pid;	/// Process identificiation number
		int tid;	/// Thread identification number
		HANDLE hpid;	/// Process handle
		HANDLE htid;	/// Thread handle
		char *args;	/// Saved arguments when process was launched
		// TODO: Deprecate and remove wow64 field
		//       Make function to query process machine type
		version (Win64) int wow64;
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
	//TODO: Deprecate and remove static buffer in process struct
	/// Process base module name.
	char[ADBG_PROCESS_NAME_LENGTH] name;
}

void adbg_process_free(adbg_process_t *proc) {
	if (proc == null)
		return;
	version (Windows) {
		if (proc.args) free(proc.args);
	}
	version (Posix) {
		if (proc.argv) free(proc.argv);
	}
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

/// Get the process' ID;
/// Params: tracee = Debuggee process.
/// Returns: PID or 0 on error.
int adbg_process_get_pid(adbg_process_t *tracee) {
	if (tracee == null) return 0;
	return tracee.pid;
}

//TODO: Last parameter could be an enum
//      AdbgProcNameInclude
//      - program basename (only)
//      - program full path
//      - program full path and command-line arguments
/// Get the process file path.
///
/// The string is null-terminated.
/// Bug: On Windows, GetModuleFileNameA causes a crash with MSVC malloc buffers.
/// Params:
/// 	pid = Process ID.
/// 	buffer = Buffer.
/// 	bufsize = Size of the buffer.
/// 	absolute = Request for absolute path; Otherwise base filename.
/// Returns: String length; Or zero on error.
size_t adbg_process_get_name(int pid, char *buffer, size_t bufsize, bool absolute) {
	version (Trace)
		trace("pid=%d buffer=%p bufsize=%zd base=%d", pid, buffer, bufsize, absolute);
	
	if (pid <= 0 || buffer == null || bufsize == 0) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	
version (Windows) {
	if (__dynlib_psapi_load()) // Sets error
		return 0;
	
	// Get process handle
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (procHandle == null) {
		adbg_oops(AdbgError.os);
		return 0;
	}
	scope(exit) CloseHandle(procHandle);
	
	//TODO: Try with the following?
	//      1. 
	//      GetProcessImageFileNameA + GetModuleHandleA
	//      + GetModuleBaseNameA <- base=true
	//      + GetModuleFileNameA <- base=false
	//      2. 
	//      GetProcessImageFileNameA
	//      + cut string manually <- base=true
	//      + PathGetDriveNumberA <- base=false
	//
	//      QueryFullProcessImageName
	
	DWORD needed = void;
	DWORD pidlist = void;
	if (EnumProcesses(&pidlist, DWORD.sizeof, &needed) == FALSE) {
		adbg_oops(AdbgError.os);
		return 0;
	}
	//TODO: Check every PID to match?
	HMODULE hmod = void;
	if (absolute == false && EnumProcessModules(procHandle, &hmod, hmod.sizeof, &needed)) {
		adbg_oops(AdbgError.os);
		return 0;
	}
	
	// NOTE: GetModuleFileNameA requires module handle
	// NOTE: GetProcessImageFileNameA returns native path (not Win32 path)
	// NOTE: QueryFullProcessImageNameA is Vista and later
	// Get filename or basename
	uint bf = cast(uint)bufsize;
	uint r = absolute ?
		GetModuleFileNameA(hmod, buffer, bf) :
		GetModuleBaseNameA(procHandle, hmod, buffer, bf);
	buffer[r] = 0;
	if (r == 0) adbg_oops(AdbgError.os);
	return r;
} else version (linux) {
	enum PATHBFSZ = 32; // int.min is "-2147483648", 11 chars
	char[PATHBFSZ] pathbuf = void; // Path buffer
	
	// NOTE: readlink does not append null, this is done later
	snprintf(pathbuf.ptr, PATHBFSZ, "/proc/%d/exe", pid);
	ssize_t r = readlink(pathbuf.ptr, buffer, bufsize);
	
	// NOTE: cmdline arguments end with one null byte, and an extra null byte at the very end
	/*snprintf(pathbuf.ptr, PATHBFSZ, "/proc/%d/cmdline", pid);
	int cmdlinefd = open(pathbuf.ptr, O_RDONLY);
	if (cmdlinefd > 0) {
		r = read(cmdlinefd, buffer, bufsize);
		if (r <= 0) {
			adbg_oops(AdbgError.os);
			return 0;
		}
		buffer[r] = 0;
		close(cmdlinefd);
	}*/
	
	// Error reading /cmdline, retry with /comm
	// e.g., kthread
	// NOTE: comm strings can only be up to 16 characters
	if (r <= 0) {
		snprintf(pathbuf.ptr, PATHBFSZ, "/proc/%d/comm", pid);
		int commfd = open(pathbuf.ptr, O_RDONLY);
		if (commfd == -1) {
			adbg_oops(AdbgError.os);
			return 0;
		}
		scope(exit) close(commfd);
		
		// Read into buffer
		size_t rdsize = min(bufsize, 16); // Can only read up to 16 chars
		r = read(commfd, buffer, rdsize);
		if (r < 0) {
			adbg_oops(AdbgError.os);
			return 0;
		}
		buffer[r - 1] = 0; // Delete newline
		
		// Return now since comm values aren't worth path manipulation
		return r;
	}
	
	// Base path requested and got absolute instead
	// e.g. /usr/bin/cat to cat
	if (absolute == false && buffer[0] == '/') {
		// Find the last occurance of '/'
		char *last = strrchr(buffer, '/');
		if (last == null) {
			adbg_oops(AdbgError.assertion);
			return 0;
		}
		++last; // We're looking past '/'
		
		// Write into buffer
		for (r = 0; last[r]; ++r)
			buffer[r] = last[r];
	} 
	//TODO: Name is not absolute, search in PATH
	/* else if (absolute && buffer[0] != '/') {
		
	}*/

	buffer[r < bufsize ? r : r - 1] = 0;
	return r;
} else {
	adbg_oops(AdbgError.unimplemented);
	return 0;
}
}
unittest {
	//TODO: Test one character buffers
}

/// Get the current runtime machine platform.
///
/// This is useful when the debugger is dealing with a process running
/// under a subsystem such as WoW or lib32-on-linux64 programs.
/// Params: tracee = Debuggee process.
/// Returns: Machine platform.
AdbgMachine adbg_process_get_machine(adbg_process_t *tracee) {
	if (tracee == null)
		return AdbgMachine.unknown;
	
	//TODO: There's probably a way to remotely check this
	//      Windows: IsWow64Process/IsWow64Process2 with process handle
	version (Win64) {
		if (tracee.wow64) return AdbgMachine.i386;
	}
	
	return adbg_machine_default();
}

// TODO: Switch to adbg.utils.list
/// Get a list of process IDs running.
///
/// This function allocates memory. The list passed will need to be closed
/// using `free(3)`. To get the name of a process, call `adbg_process_get_name`.
///
/// Windows: The list is populated by system order using `EnumProcesses`.
/// Linux: The list is populated by process ID using procfs.
///
/// Params:
/// 	count = Process list structure instance.
/// 	... = Options, terminated by 0.
/// Returns: List of PIDs; Or null on error.
int* adbg_process_list(size_t *count, ...) {
	if (count == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	enum CAPACITY = 5_000; // * 4 = ~20K
	
	int *plist = void;
	
version (Windows) {
	if (__dynlib_psapi_load())
		return null;
	
	// Allocate temp PID buffer
	uint hsize = cast(uint)(CAPACITY * HMODULE.sizeof);
	DWORD *pidlist = cast(DWORD*)malloc(hsize);
	if (pidlist == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	scope(exit) free(pidlist);
	
	// Enumerate processes
	// Note that "needed" is reusable after getting the count
	//TODO: Adjust temporary buffer after calling this
	DWORD needed = void;
	if (EnumProcesses(pidlist, hsize, &needed) == FALSE) {
		adbg_oops(AdbgError.os);
		return null;
	}
	DWORD proccount = needed / DWORD.sizeof;
	
	plist = cast(int*)malloc(proccount * int.sizeof);
	if (plist == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Skip PID 0 (idle) and 4 (system)
	enum SKIP = 2;
	memcpy(plist, pidlist + SKIP, (proccount * DWORD.sizeof) - (SKIP * DWORD.sizeof));
	*count = proccount - SKIP;
} else version (linux) {
	// Count amount of entries to allocate
	size_t cnt; // minimum amount of entries
	DIR *procfd = opendir("/proc");
	if (procfd == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	scope (exit) closedir(procfd);
	
	for (dirent *procent = void; (procent = readdir(procfd)) != null;) {
		// If not directory starting with a digit, skip entry
		if (procent.d_type != DT_DIR)
			continue;
		if (isdigit(procent.d_name[0]) == 0)
			continue;
		
		++cnt;
	}
	
	// Allocate list
	plist = cast(int*)malloc(cnt * int.sizeof);
	if (plist == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	*count = cnt;
	
	// Populate list
	rewinddir(procfd);
	size_t i;
	for (dirent *procent = void; (procent = readdir(procfd)) != null;) {
		// If not directory starting with a digit, skip entry
		if (procent.d_type != DT_DIR)
			continue;
		if (isdigit(procent.d_name[0]) == 0)
			continue;
		
		// Set PID
		plist[i++] = atoi(procent.d_name.ptr);
	}
}

	return plist;
}

//TODO: Deprecate process enumeration routines

/// Options for adbg_process_enumerate.
enum AdbgProcessEnumerateOption {
	/// Set the size of the dynamic buffer for the list of processes.
	/// Default: 1000
	/// Type: uint
	capcity = 1,
	/// This option is not yet implemented.
	sort = 2,
}
/// Sort option for AdbgProcessEnumerateOption.sort.
enum AdbgProcessEnumerateSort {
	/// Sort processes by system (Windows' default).
	system,
	/// Sort processes by ID (Linux's default).
	id,
	/// Sort processes by basename.
	process,
}

/// Structure used with `adbg_process_enumerate`.
///
/// This holds the list of processes and a count.
struct adbg_process_list_t {
	/// Allocated list of processes.
	adbg_process_t *processes;
	/// Number of processes.
	size_t count;
}
/// Enumerate running processes.
///
/// This function allocates memory. The list passed will need to be closed
/// using `adbg_process_enumerate_close`.
///
/// On Windows, the list is populated by system order using `EnumProcesses`.
/// On Linux, the list is populated by process ID using procfs.
///
/// Params:
/// 	list = Process list structure instance.
/// 	... = Options, terminated by 0.
/// Returns: Zero for success; Or error code.
int adbg_process_enumerate(adbg_process_list_t *list, ...) {
	// NOTE: KEEP THIS FUNCTION AROUND AND DO NOT TOUCH IT
	//
	//       This function *must* be kept around until I understand why both
	//       GetModuleBaseNameA and GetModuleFileNameA work here but not
	//       when used separaterely from EnumProcesses/EnumProcessModules.
	//
	//       Also, on Linux, this somehow gets the comm value, while
	//       the new function does not.
	
	if (list == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	/// Default fixed buffer size.
	enum DEFAULT_CAPACITY = 1000;
	
	va_list options = void;
	va_start(options, list);
	uint capacity = DEFAULT_CAPACITY;
L_OPTION:
	switch (va_arg!int(options)) {
	case 0: break;
	case AdbgProcessEnumerateOption.capcity:
		capacity = va_arg!uint(options);
		if (capacity <= 0)
			return adbg_oops(AdbgError.invalidValue);
		goto L_OPTION;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	// Allocate main buffer
	list.processes = cast(adbg_process_t*)malloc(capacity * adbg_process_t.sizeof);
	if (list.processes == null)
		return adbg_oops(AdbgError.crt);
	
	version (Windows) {
		if (__dynlib_psapi_load()) {
			free(list.processes);
			return adbg_errno();
		}
		
		// Allocate temp PID buffer
		uint hsize = cast(uint)(capacity * HMODULE.sizeof);
		DWORD *pidlist = cast(DWORD*)malloc(hsize);
		if (pidlist == null) {
			free(list.processes);
			return adbg_oops(AdbgError.crt);
		}
		scope(exit) free(pidlist);
		
		// Enumerate processes
		// Note that "needed" is reusable after getting the count
		DWORD needed = void;
		if (EnumProcesses(pidlist, hsize, &needed) == FALSE) {
			free(pidlist);
			return adbg_oops(AdbgError.os);
		}
		DWORD proccount = needed / DWORD.sizeof;
		size_t count; /// Final count
		for (DWORD i; i < proccount && count < capacity; ++i) {
			int pid = pidlist[i];
			
			HANDLE procHandle = OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				FALSE, pid);
			if (procHandle == null)
				continue;
			
			adbg_process_t *proc = &list.processes[count++];
			proc.pid = pid;
			proc.hpid = procHandle;
			proc.tid = 0;
			
			//TODO: Is EnumProcessModules really necessary?
			HMODULE hmod = void;
			if (EnumProcessModules(procHandle, &hmod, hmod.sizeof, &needed)) {
				proc.hpid = hmod;
				
				DWORD len = GetModuleBaseNameA(
					procHandle, hmod, proc.name.ptr, ADBG_PROCESS_NAME_LENGTH);
				if (len > 0) {
					proc.name[len] = 0;
				} else {
					goto L_NONAME;
				}
			} else {
			L_NONAME:
				strcpy(proc.name.ptr, "<unknown>");
				proc.hpid = null;
			}
			
			CloseHandle(procHandle);
		}
		list.count = count;
		return 0;
	} else version (linux) {
		//TODO: Consider pre-running /proc to get initial count
		size_t count;
		DIR *procfd = opendir("/proc");
		for (dirent *procent = void; (procent = readdir(procfd)) != null;) {
			// If not directory starting with a digit, skip entry
			if (procent.d_type != DT_DIR)
				continue;
			if (isdigit(procent.d_name[0]) == 0)
				continue;
			
			/// Minimum read size, avoid overwriting
			enum READSZ = MIN!(adbg_process_t.name.sizeof, dirent.d_name.sizeof);
			
			// Set PID
			adbg_process_t *proc = &list.processes[count++];
			proc.pid = atoi(procent.d_name.ptr);
			
			// Read /cmdline into process.name buffer
			enum TBUFSZ = 32;
			char[TBUFSZ] proc_comm = void; // Path buffer
			snprintf(proc_comm.ptr, TBUFSZ, "/proc/%s/cmdline", procent.d_name.ptr);
			int cmdlinefd = open(proc_comm.ptr, O_RDONLY);
			if (cmdlinefd == -1)
				continue;
			scope(exit) close(cmdlinefd);
			ssize_t r = read(cmdlinefd, proc.name.ptr, READSZ);
			
			// Get a baseline from /cmdline or /comm
			if (procent.d_name[0] && r > 0) { // /cmdline populated
				// NOTE: Yes, dangerous, but works under Glibc and musl.
				//TODO: Test under Bionic, uClibc, etc.
				strcpy(proc.name.ptr, basename(proc.name.ptr));
			} else { // /cmdline empty, retrying with /comm
				snprintf(proc_comm.ptr, TBUFSZ, "/proc/%s/comm", procent.d_name.ptr);
				int commfd = open(proc_comm.ptr, O_RDONLY);
				if (commfd == -1)
					continue;
				scope(exit) close(commfd);
				r = read(commfd, proc.name.ptr, READSZ);
				if (r < 0)
					continue;
				proc.name[r - 1] = 0; // Delete newline
			}
		}
		list.count = count;
		return 0;
	} else {
		return adbg_oops(AdbgError.unimplemented);
	}
}

unittest {
	adbg_process_list_t list = void;
	assert(adbg_process_enumerate(&list, 0) == 0);
	version (TestVerbose) {
		import core.stdc.stdio : printf;
		foreach (adbg_process_t proc; list.processes[0..list.count]) {
			printf("%5u %s\n",
				adbg_process_get_pid(&proc),
				proc.name.ptr);
		}
	}
	assert(list.count);
	adbg_process_enumerate_close(&list);
}

void adbg_process_enumerate_close(adbg_process_list_t *list) {
	if (list == null) return;
	if (list.processes) free(list.processes);
}
