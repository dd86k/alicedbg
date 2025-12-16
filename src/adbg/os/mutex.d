/// Mutex primitive.
///
/// No user code should be using this directly, as it is used internally.
///
/// Windows: Uses Mutex API and not CriticalSection since the latter isn't cross-process.
/// POSIX: Uses pthread mutex API to be available cross-process.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.os.mutex;

import adbg.utils.bit : BIT;

version (Windows) {
	import core.sys.windows.winbase :
		GetLastError, CloseHandle,
		CreateMutexA, WaitForSingleObject,
		ReleaseMutex,
		INFINITE,
		WAIT_OBJECT_0, WAIT_ABANDONED_0, WAIT_FAILED;
	import core.sys.windows.windef : HANDLE, FALSE, TRUE, WAIT_TIMEOUT;
	
	private alias os_mutex = HANDLE;
} else version (Posix) {
	import core.sys.posix.pthread :
		pthread_mutex_t,
		pthread_mutex_init, pthread_mutex_destroy,
		pthread_mutex_lock, pthread_mutex_trylock, pthread_mutex_timedlock,
		pthread_mutex_unlock;
	
	// Only defined for Darwin and Solaris:
	// pthread_mutex_getprioceiling, pthread_mutex_setprioceiling;
	
	private alias os_mutex = pthread_mutex_t;
}

// Assumptions:
// - .handle is handled by the underlaying system for errors
struct os_mutex_t {
	os_mutex handle;
}

// Having an explicit initiation function makes for a better garantee that only
// one thread will initiate the mutex, verify the return for errors, and
// hopefully avoid other threads access internals.
/// Initiate a new mutex.
/// Params: mutex = os_mutex_t instance.
/// Returns: OS error code.
int os_mutex_init(os_mutex_t *mutex) {
version (Windows) {
	// Nameless Mutex that cannot be inherited
	mutex.handle = CreateMutexA(null, FALSE, null);
	if (mutex.handle == null)
		return GetLastError();
} else version (Posix) {
	// pthread_mutex_init always return zero
	pthread_mutex_init(&mutex.handle, null);
} else static assert(false, "os_mutex_init");
	return 0;
}

/// Destroy mutex.
/// Params: mutex = os_mutex_t instance.
void os_mutex_destroy(os_mutex_t *mutex) {
	if (mutex == null) assert(0, "null mutex");

version (Windows) {
	CloseHandle(mutex.handle);
} else version (Posix) {
	pthread_mutex_destroy(&mutex.handle);
} else static assert(false, "os_mutex_destroy");
}

/// Acquire exclusive access to mutex.
/// Params: mutex = os_mutex_t instance.
/// Returns: OS error code.
int os_mutex_acquire(os_mutex_t *mutex) {
	if (mutex == null) assert(0, "null mutex");

version (Windows) {
	// wait function is used to acquire exclusive access to mutex
	uint rc = WaitForSingleObject(mutex.handle, INFINITE);
	switch (rc) {
	case WAIT_OBJECT_0, WAIT_TIMEOUT:
		return 0;
	default: // WAIT_ABANDONED, WAIT_FAILED
		return GetLastError();
	}
} else version (Posix) {
	return pthread_mutex_lock(&mutex.handle);
} else static assert(false, "os_mutex_acquire");
}

/// Acquire exclusive access to mutex, but only try for this amount of time.
/// Params:
///     mutex = os_mutex_t instance.
///     ms = Timeout in millisecond.
/// Returns: OS error code.
int os_mutex_acquirefor(os_mutex_t *mutex, uint ms, int *status) {
	if (mutex == null) assert(0, "null mutex");
	
version (Windows) {
	// wait function is used to acquire exclusive access to mutex
	uint rc = WaitForSingleObject(mutex.handle, ms);
	switch (rc) {
	case WAIT_OBJECT_0:
		if (status) *status = 0;
		return 0;
	case WAIT_TIMEOUT:
		if (status) *status = 1;
		return 0;
	default: // WAIT_ABANDONED, WAIT_FAILED
		return GetLastError();
	}
} else version (Posix) {
	import core.sys.posix.time : timespec, clock_gettime, CLOCK_REALTIME, time_t;
	import core.stdc.config : c_long;
	import core.stdc.errno : errno, ETIMEDOUT;
	
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
	
	int rc = pthread_mutex_timedlock(&mutex.handle, &ts);
	switch (rc) {
	case 0:
		if (status) *status = 0;
		return 0;
	case ETIMEDOUT:
		if (status) *status = 1;
		return 0;
	default:
		return rc;
	}
} else static assert(false, "os_mutex_acquirefor");
}

/// Release exclusive access from mutex.
/// Params: mutex = os_mutex_t instance.
/// Returns: OS error code.
int os_mutex_release(os_mutex_t *mutex) {
	if (mutex == null) assert(0, "null mutex");

version (Windows) {
	if (ReleaseMutex(mutex.handle) == FALSE)
		return GetLastError();
	return 0;
} else version (Posix) {
	return pthread_mutex_unlock(&mutex.handle);
} else static assert(false, "os_mutex_acquirefor");
}
