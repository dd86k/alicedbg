/// Implements threading facilities.
///
/// No user code should be using this directly, as it is used internally.
///
/// The threading model used might depend on the compilation target.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.os.threads;

import adbg.os.mutex;
import core.stdc.stdlib : malloc, calloc, free;
import core.stdc.string : memset;
import core.sys.posix.sys.mman;

// NOTE: Thread models
//
//       NT RTL
//         Mentioned through headers, means native WindowsNT threads, but this
//         isn't generally available to Windows user applications.
//
//       Win32
//         Base model with CreateThread and (not) TerminateThread.
//
//       Libcmt (recommended Win32 wrapper for msvc)
//         Uses _beginthread/_beginthreadex and _endthread/_endthreadex.
//         https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/beginthread-beginthreadex?view=msvc-170
//         https://learn.microsoft.com/en-us/cpp/parallel/multithreading-with-c-and-win32?view=msvc-170
//
//       MFC
//         Uses AfxBeginThread that returns CWinThread.
//         https://learn.microsoft.com/en-us/cpp/parallel/multithreading-terminating-threads?view=msvc-170
//
//       PThread (POSIX Threads)
//         On Windows, in rare cases, when a wrapper like MinGW or Mingw-w64 is involved,
//         it might use a PThreads model. Usually doesn't (at least using DMD and LDC).

// TODO: Error codes
// Optional: Thread priority
// Optional: Thread names (SetThreadDescription: Windows 10+; pthread_set_name_np: Linux/macOS)

version (Windows) {
	//version = Win32Threads;
	version = LibcmtThreads;
	//version = MFCThreads;
	//version = PosixThreads;
	
	// winbase.h, version 10.0.19041.0
	enum STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000;
} else version (Posix) {
	version = PosixThreads;
}

version (Win32Threads) {
	import core.sys.windows.winbase;
	import core.sys.windows.windef;
	
	private alias HANDLE thread_handle_t;
} else version (LibcmtThreads) {
	import core.stdc.stdint : uintptr_t;
	
	// Returns -1 on error
	extern (C)
	uintptr_t _beginthread(void function(void*) fn, uint stk, void *args);
	extern (C)
	void _endthread();
	
	// Returns 0 on error
	extern (C)
	uintptr_t _beginthreadex(void *sec, uint stk, uint function(void*) fn, void *args, uint flags, uint *thraddr);
	extern (C)
	void _endthreadex(uint code);
	
	// In MS examples, this is casted to HANDLE for WaitForSingleObject.
	private alias uintptr_t thread_handle_t;
} else version (MFCThreads) {
	struct CWinThread;
	/* C++
	CWinThread* AfxBeginThread(
		AFX_THREADPROC pfnThreadProc,
		LPVOID pParam,
		int nPriority = THREAD_PRIORITY_NORMAL,
		UINT nStackSize = 0,
		DWORD dwCreateFlags = 0,
		LPSECURITY_ATTRIBUTES lpSecurityAttrs = NULL);

	CWinThread* AfxBeginThread(
		CRuntimeClass* pThreadClass,
		int nPriority = THREAD_PRIORITY_NORMAL,
		UINT nStackSize = 0,
		DWORD dwCreateFlags = 0,
		LPSECURITY_ATTRIBUTES lpSecurityAttrs = NULL);
	*/
	// Callback: UINT __cdecl MyControllingFunction( LPVOID pParam );
	static assert(0, "TODO: MFCThreads");
} else version (PosixThreads) {
	import core.sys.posix.pthread;
	
	// pthread_t is typically c_ulong
	private alias pthread_t thread_handle_t;
}

extern (C):

enum {
	/// Status: Thread is running
	__OSTHREAD_RUNNING = 1,
	/// Status: Thread has been requested to be canceled
	__OSTHREAD_CANCELED = 4,
	
	// No error.
	//__OSTERR_OK = 0,
	// 
	//__OSTERR_NOALLOC = -2,
}

struct __osthread_t {
	thread_handle_t handle;
	int function(__osthread_t*, void*) ufunc;
	void *udata;
	int status;
	int code;
	// NOTE: Mutexes
	//       Not a performance option v. atomics, but offers more
	//       consistent and deterministic behavior
	os_mutex_t mutex;
	version (Win32Threads) uint tid;
	version (LibcmtThreads) uint tid;
}

const(char)* osthrmodel() {
	version (Win32Threads)
		return "win32";
	version (LibcmtThreads)
		return "libcmt";
	version (MFCThreads)
		return "mfc";
	version (PosixThreads)
		return "pthread";
}

/// Sleep caller thread by this amount of time.
/// Params: ms = Milliseconds.
void ossleep(uint ms) {
version (Windows) {
	import core.sys.windows.winbase : Sleep;
	Sleep(ms);
} else version (Posix) {
	// usleep is removed in POSIX.1-2008
	import core.sys.posix.time : nanosleep, timespec, time_t;
	import core.stdc.config : c_long;
	import core.stdc.errno : errno, EINTR;
	timespec r = void, s = void;
	s.tv_sec   = cast(time_t)(ms / 1000);
	s.tv_nsec  = cast(c_long)((ms % 1000) * 1_000_000); // milli -> micro -> nano
Lsleep:
	// On success, quit
	if (nanosleep(&s, &r) >= 0)
		return;
	// Not interrupted means something else happened
	if (errno != EINTR)
		return;
	// Retry with remaining time
	s.tv_sec = r.tv_sec;
	s.tv_nsec = r.tv_nsec;
	goto Lsleep;
} // version (Posix)
}

/// Create and execute a new remote thread.
///
/// New threads need to use `osthrcancel
/// Params:
/// 	func = Function (must be externed as C).
/// 	data = Pointer to data to be passed to function.
/// 	size = Stack size in Bytes. 0 meaning to use the default size.
/// Returns: Thread instance, or null on error.
__osthread_t* osthrnew(int function(__osthread_t*, void*) func, void *data = null, size_t size = 0) {
	assert(func, "func is null");
	
	__osthread_t* thread = cast(__osthread_t*)calloc(1, __osthread_t.sizeof);
	if (thread == null) {
		return null;
	}
	/*__osthread_t* thread = cast(__osthread_t*)mmap(null, 4096,
		PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, 0, 0);
	if (thread == MAP_FAILED)
		return null;*/
	if (osmutexinit(&thread.mutex) < 0) {
		free(thread);
		return null;
	}
	
	thread.ufunc = func;
	thread.udata = data;
version (Win32Threads) {
	enum THREAD_FLAGS = STACK_SIZE_PARAM_IS_A_RESERVATION;
	thread.handle = CreateThread(
		null,                // lpThreadAttributes
		cast(SIZE_T)size,    // dwStackSize
		&osthrhandle,        // lpStartAddress
		thread,              // lpParameter
		THREAD_FLAGS,        // dwCreationFlags
		&thread.tid);        // lpThreadId
	if (thread.handle == null) {
		free(thread);
		return null;
	}
	
	return thread;
} else version (LibcmtThreads) {
	enum THREAD_FLAGS = STACK_SIZE_PARAM_IS_A_RESERVATION;
	thread.handle = _beginthreadex( // Same parameters/returns as CreateThread
		null,                // security
		cast(uint)size,      // stack_size
		&osthrhandle,        // start_address
		thread,              // arglist
		THREAD_FLAGS,        // initflags
		&thread.tid);        // thrdaddr
	if (thread.handle == 0) {
		free(thread);
		return null;
	}
	
	return thread;
} else version (MFCThreads) {
	static assert(0, "TODO: MFCThreads");
} else version (PosixThreads) {
	int r = pthread_create(&thread.handle, null, &osthrhandle, thread);
	if (r) {
		free(thread);
		return null;
	}
	
	return thread;
} else {
	static assert(0, "Threading API unavailable");
} // version (PosixThreads)
}

// Thread handler for Win32 threads
version (Win32Threads)
private
uint osthrhandle(void *data) {
	assert(data, "data is null");
	__osthread_t *thread = cast(__osthread_t*)data;
	
	osmutexacquire(&thread.mutex);
	thread.status |= __OSTHREAD_RUNNING;
	osmutexrelease(&thread.mutex);
	
	int rc = thread.func(thread, thread.udata);
	
	osmutexacquire(&thread.mutex);
	thread.status &= ~__OSTHREAD_RUNNING;
	thread.code = rc;
	osmutexrelease(&thread.mutex);
	
	return rc; // implicit ExitThread(code)
}

// Thread handler for Win32-CRT threads
// _beginthread: __cdecl void function(void*)
// _beginthreadex: __stdcall unsigned function(void*)
version (LibcmtThreads)
extern (Windows) // __stdcall
private
uint osthrhandle(void *data) {
	assert(data, "data is null");
	__osthread_t *thread = cast(__osthread_t*)data;
	
	osmutexacquire(&thread.mutex);
	thread.status |= __OSTHREAD_RUNNING;
	osmutexrelease(&thread.mutex);
	
	int rc = thread.ufunc(thread, thread.udata);
	
	osmutexacquire(&thread.mutex);
	thread.status &= ~__OSTHREAD_RUNNING;
	thread.code = rc;
	osmutexrelease(&thread.mutex);
	
	return rc; // implicit _endthreadex(code);
}

// Thread handler for MFC threads
version (MFCThreads)
extern (Windows)
private
void osthrhandle(void *data) {
	assert(data, "data is null");
	__osthread_t *thread = cast(__osthread_t*)data;
	
	osmutexacquire(&thread.mutex);
	thread.status |= __OSTHREAD_RUNNING;
	osmutexrelease(&thread.mutex);
	
	int rc = thread.ufunc(thread, thread.udata);
	
	osmutexacquire(&thread.mutex);
	thread.status &= ~__OSTHREAD_RUNNING;
	thread.code = rc;
	osmutexrelease(&thread.mutex);
	
	AfxEndThread(rc, TRUE);
}

version (PosixThreads)
private
void* osthrhandle(void *data) {
	assert(data, "data is null");
	__osthread_t *thread = cast(__osthread_t*)data;
	
	osmutexacquire(&thread.mutex);
	thread.status |= __OSTHREAD_RUNNING;
	osmutexrelease(&thread.mutex);
	
	int rc = thread.ufunc(thread, thread.udata);
	
	osmutexacquire(&thread.mutex);
	thread.status &= ~__OSTHREAD_RUNNING;
	thread.code = rc;
	osmutexrelease(&thread.mutex);
	
	pthread_exit(&thread.code);
	return null;
}

/// Detach a thread (only available on POSIX threads).
/// Params: thread = Thread.
/// Returns: Zero on success, otherwise error number.
version (PosixThreads)
int osthrdetach(__osthread_t *thread) {
	assert(thread, "thread is NULL");
	
	if (pthread_detach(thread.handle))
		return -1;
	
	return 0;
}

/// Wait for a thread to finish.
///
/// If a thread was detached, it is no longer joinable.
/// Params: thread = Thread.
/// Returns: Exit code, or -1 on error.
int osthrjoin(__osthread_t *thread) {
	assert(thread, "thread is NULL");
	
	// Because we manually save exit code, no need to use OS functions
	// to get the remote thread's exit code.
version (PosixThreads) {
	void *ret = void;
	if (pthread_join(thread.handle, &ret))
		return -1;
	
	int code = thread.code;
	
	osthrdestroy(thread);
	
	return code;
} else { // Libcmt/Win32, MFC will be implemented later
	// If MS examples casts the thread handle, so can I.
	HANDLE handle = cast(HANDLE)thread.handle;
	assert(handle, "handle is NULL"); // TODO: Handle as error
	DWORD r = WaitForSingleObject(handle, INFINITE);
	CloseHandle(handle); // close anyway
	
	int code = thread.code;
	osthrdestroy(thread);
	
	// r: WAIT_ABANDONED, WAIT_OBJECT_0+n, WAIT_TIMEOUT, WAIT_FAILED
	// Right now, if anything happened, consider as error.
	return r ? -1 : code;
}
	return 0;
}

/// Request cancelation of a thread.
/// Params: thread = Thread.
void osthrcancel(__osthread_t *thread) {
	assert(thread, "thread is null");
	
	// TODO: Consider atomic
	osmutexacquire(&thread.mutex);
	thread.status |= __OSTHREAD_CANCELED;
	osmutexrelease(&thread.mutex);
}

/// Get internal status flags.
///
/// Allows manually querying for RUNNING and CANCELED statuses.
/// Params: thread = Thread.
/// Returns: Status flags.
int osthrstatus(__osthread_t *thread) {
	assert(thread, "thread is null");
	
	// TODO: Consider atomic
	osmutexacquire(&thread.mutex);
	int status = thread.status;
	osmutexrelease(&thread.mutex);
	
	return status;
}

/// Destroy a thread. Called internally when remote thread finishes.
/// Params: thread = Thread.
private
void osthrdestroy(__osthread_t *thread) {
	assert(thread, "thread is null");
	
	osmutexdestroy(&thread.mutex);
	free(thread);
}