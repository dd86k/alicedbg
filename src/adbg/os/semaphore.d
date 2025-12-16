/// Semaphone primitive.
///
/// No user code should be using this directly, as it is used internally.
///
/// Windows: Uses Win32 API.
/// POSIX: Uses POSIX semaphores (sem_* functions).
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.os.semaphore;

/* Semaphore resources

Win32: CreateSemaphoreA/W, CreateSemaphoreWA/W, OpenSemaphoreW, ReleaseSemaphore,
       WaitForSingleObject, CloseHandle
       https://learn.microsoft.com/en-us/windows/win32/sync/semaphore-objects
       https://learn.microsoft.com/en-us/windows/win32/sync/using-semaphore-objects

POSIX: sem_close(3), sem_destroy(3), sem_getvalue(3), sem_init(3),
       sem_open(3), sem_post(3), sem_unlink(3), sem_wait(3), pthreads(7),
       shm_overview(7), alarm(3)
       https://manned.org/man/sem_overview
*/

version (Windows) {
	import core.sys.windows.winbase;
	import core.sys.windows.basetsd;
	import core.sys.windows.windef : TRUE, FALSE, BOOL, WAIT_TIMEOUT, DWORD;
	
	private alias os_semaphore = HANDLE;
	private enum MAX_SEM_COUNT = int.max; // example doesn't elaborate
} else version (Posix) {
	import core.sys.posix.semaphore;
	import core.stdc.errno : errno, ETIMEDOUT;
	
	private alias os_semaphore = sem_t;
	
	// SEM_VALUE_MAX is not defined anywhere in druntime.
	version (CRuntime_Glibc)
		private enum uint SEM_VALUE_MAX = 2147483647;
	version (CRuntime_Bionic)
		private enum uint SEM_VALUE_MAX = 0x3fffffff;
	version (CRuntime_Musl)
		private enum uint SEM_VALUE_MAX = 0x7fffffff;
}

/// Represents an OS semaphore.
struct os_semaphore_t {
	os_semaphore handle;
}

/// Create a new semaphore.
/// Params: sem = os_semaphore_t pointer instance.
/// Returns: Error code.
int os_sem_create(os_semaphore_t *sem) {
	assert(sem, "null ptr");
version (Windows) {
	sem.handle = CreateSemaphoreA(
		null,          // default security
		0,             // initial count
		MAX_SEM_COUNT, // maximum count
		null);         // unnamed
	if (sem.handle == null)
		return GetLastError();
} else version (Posix) {
	// pshared=0 -> shared between threads of a process
	// pshared>0 -> shared between processes (using shm)
	if (sem_init(&sem.handle, 0, 0) < 0)
		return errno;
} else static assert(false, "osseminit");
	return 0;
}

/// Closes an opened semaphore.
/// Params: sem = os_semaphore_t pointer instance.
/// Returns: Error code.
void os_sem_close(os_semaphore_t *sem) {
	assert(sem, "null ptr");
version (Windows) {
	CloseHandle(sem.handle);
} else version (Posix) {
	sem_close(&sem.handle);
} else static assert(false, "osseminit");

	import core.stdc.string : memset;
	memset(sem, 0, os_semaphore_t.sizeof);
}

/// Notify semaphore.
/// Params: sem = os_semaphore_t pointer instance.
/// Returns: Error code.
int os_sem_notify(os_semaphore_t *sem) {
	assert(sem, "null ptr");
version (Windows) {
	if (ReleaseSemaphore(sem.handle, 1, null) == FALSE)
		return GetLastError();
} else version (Posix) {
	if (sem_post(&sem.handle) < 0)
		return errno;
} else static assert(false, "ossemwaittime");
	return 0;
}

/// Wait on a semaphore for a notification.
/// Params: sem = os_semaphore_t pointer instance.
/// Returns: Error code.
int os_sem_wait(os_semaphore_t *sem) {
	assert(sem, "null ptr");
version (Windows) {
	DWORD r = WaitForSingleObject(sem.handle, INFINITE);
	switch (r) {
	case WAIT_OBJECT_0: return 0;
	default:            return GetLastError();
	}
} else version (Posix) {
	if (sem_wait(&sem.handle) < 0)
		return errno;
	return 0;
} else static assert(false, "ossemwait");
}

// NOTE: ms could be turned into a "duration" structure at some point
/// Wait on a semaphore for limited amount of time.
/// Params:
///     sem = os_semaphore_t pointer instance.
///     ms  = Timeout in millisecond.
///     status = Status pointer. Updated to 1 if timedout, or 0 otherwise
/// Returns: Error code.
int os_sem_waitfor(os_semaphore_t *sem, uint ms, int *status) {
	assert(sem, "null ptr");
version (Windows) {
	DWORD r = WaitForSingleObject(sem.handle, ms);
	switch (r) {
	case WAIT_OBJECT_0:
		if (status) *status = 0;
		break;
	case WAIT_TIMEOUT:
		if (status) *status = 1;
		break;
	default:
		return GetLastError();
	}
} else version (Posix) {
	import core.sys.posix.time : timespec, clock_gettime, CLOCK_REALTIME, time_t;
	import core.stdc.config : c_long;
	
	time_t secs = ms / 1000;
	c_long nsec = (ms % 1000) * 1_000_000;
	
	timespec ts = void;
	if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
		return errno;
	ts.tv_sec  += secs;
	ts.tv_nsec += nsec;
	
	// nsec overflow
	enum nsec1sec = 1_000_000_000;
	if (ts.tv_nsec >= nsec1sec) {
		++ts.tv_sec;
		ts.tv_nsec -= nsec1sec;
	}
	
	// wait at absolute time
	if (sem_timedwait(&sem.handle, &ts) < 0) {
		int e = errno;
		if (e == ETIMEDOUT && status)
			*status = 1;
		return e;
	} else if (status)
		*status = 0;
} else static assert(false, "ossemwaittime");
	return 0;
}
