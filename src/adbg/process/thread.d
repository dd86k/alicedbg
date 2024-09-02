/// Thread management.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.thread;

import adbg.error;
import adbg.process.base;
import adbg.utils.list;

version (Windows) {
	import adbg.include.windows.tlhelp32;
	import core.sys.windows.basetsd : HANDLE;
	import core.sys.windows.winbase : INVALID_HANDLE_VALUE, CloseHandle;
	import core.sys.windows.windef : FALSE;
} else version (linux) {
	import core.stdc.ctype : isdigit;
	import core.stdc.stdio : snprintf;
	import core.stdc.stdlib : atoi;
	import core.sys.posix.dirent;
	import core.sys.posix.libgen : basename;
}

/// Get a list of threads for running process.
/// Params:
/// 	process = Process.
/// Returns: Thread list.
void* adbg_thread_list(adbg_process_t *process) {
version (Windows) {
	if (process == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (process.pid == 0) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	list_t *list = adbg_list_new(int.sizeof, 16);
	if (list == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, process.pid);
	if (snap == INVALID_HANDLE_VALUE) {
		adbg_oops(AdbgError.os);
		adbg_list_free(list);
		return null;
	}
	scope(exit) CloseHandle(snap);
	
	THREADENTRY32 te32 = void;
	te32.dwSize = THREADENTRY32.sizeof;
	if (Thread32First(snap, &te32) == FALSE) {
		adbg_oops(AdbgError.os);
		adbg_list_free(list);
		return null;
	}
	
	do {
		if (te32.th32OwnerProcessID != process.pid)
			continue;
		
		list = adbg_list_add(list, &te32.th32ThreadID);
		if (list == null) {
			adbg_oops(AdbgError.crt);
			adbg_list_free(list);
			return null;
		}
	} while (Thread32Next(snap, &te32));
	
	return list;
} else version (linux) {
	if (process == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (process.pid == 0) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	list_t *list = adbg_list_new(int.sizeof, 16);
	if (list == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	enum BSZ = 32; // "/proc/4294967295/task/".sizeof == 22
	char[BSZ] path = void;
	int l = snprintf(path.ptr, BSZ, "/proc/%u/task", process.pid);
	if (l < 0) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	DIR *procfd = opendir(path.ptr);
	if (procfd == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	scope (exit) closedir(procfd);
	
	// Go through kernel thread IDs
	for (dirent *entry = void; (entry = readdir(procfd)) != null;) {
		version (Trace) trace("entry=%s", entry.d_name.ptr);
		
		// readdir() includes "." and ".."
		if (isdigit(entry.d_name[0]) == 0)
			continue;
		
		int tid = atoi( basename(entry.d_name.ptr) );
		list = adbg_list_add(list, &tid);
		if (list == null) {
			adbg_oops(AdbgError.crt);
			adbg_list_free(list);
			return null;
		}
	}
	
	return list;
} else {
	adbg_oops(AdbgError.unimplemented);
	return null;
}
}

int adbg_thread_list_get(void *list, size_t index) {
	if (list == null)
		return 0;
	int *tid = cast(int*)adbg_list_get(cast(list_t*)list, index);
	return tid ? *tid : 0;
}

void adbg_thread_list_free(void *list) {
	if (list == null)
		return;
	adbg_list_free(cast(list_t*)list);
}
