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
	
	private alias HANDLE mutex_handle_t;
} else version (Posix) {
	import core.sys.posix.pthread :
		pthread_mutex_t,
		pthread_mutex_init, pthread_mutex_destroy,
		pthread_mutex_lock, pthread_mutex_trylock, pthread_mutex_timedlock,
		pthread_mutex_unlock;
		// Only defined for Darwin and Solaris:
		// pthread_mutex_getprioceiling, pthread_mutex_setprioceiling;
	
	private alias pthread_mutex_t mutex_handle_t;
}

// Assumptions:
// - .handle is handled by the underlaying system for errors
struct os_mutex_t {
	mutex_handle_t handle;
	int error;
}

// Having an explicit initiation function makes for a better garantee that only
// one thread will initiate the mutex, verify the return for errors, and
// hopefully avoid other threads access internals.
int osmutexinit(os_mutex_t *mutex) {
version (Windows) {
	// Nameless Mutex that cannot be inherited
	mutex.handle = CreateMutexA(null, FALSE, null);
	if (mutex.handle == null) {
		mutex.error = GetLastError();
		return -1;
	}
	mutex.error = 0;
	return 0;
} else version (Posix) {
	// always return zero...
	mutex.error = pthread_mutex_init(&mutex.handle, null);
	if (mutex.error)
		return -1;
	return 0;
} // version (Posix)
}

void osmutexdestroy(os_mutex_t *mutex) {
	if (mutex == null) assert(0, "null mutex");

version (Windows) {
	CloseHandle(mutex.handle);
} else version (Posix) {
	pthread_mutex_destroy(&mutex.handle);
} // version (Posix)
}

int osmutexacquire(os_mutex_t *mutex) {
	if (mutex == null) assert(0, "null mutex");

version (Windows) {
	// wait function is used to acquire exclusive access to mutex
	uint rc = WaitForSingleObject(mutex.handle, INFINITE);
	switch (rc) {
	case WAIT_OBJECT_0, WAIT_TIMEOUT:
		return 0;
	default: // WAIT_ABANDONED, WAIT_FAILED
		mutex.error = GetLastError();
		return -1;
	}
} else version (Posix) {
	mutex.error = pthread_mutex_lock(&mutex.handle);
	if (mutex.error)
		return -1;
	return 0;
} // version (Posix)
}

int osmutexacquiret(os_mutex_t *mutex, uint ms) {
	if (mutex == null) assert(0, "null mutex");
	
version (Windows) {
	// wait function is used to acquire exclusive access to mutex
	uint rc = WaitForSingleObject(mutex.handle, ms);
	switch (rc) {
	case WAIT_OBJECT_0:
		return 0;
	case WAIT_TIMEOUT:
		return 1;
	default: // WAIT_ABANDONED, WAIT_FAILED
		mutex.error = GetLastError();
		return -1;
	}
} else version (Posix) {
	import core.sys.posix.time : timespec;
	import core.stdc.errno : ETIMEDOUT;
	timespec s = void;
	s.tv_sec   =  ms / 1000;
	s.tv_nsec  = (ms % 1000) * 1_000_000; // milli -> micro -> nano
	int rc = pthread_mutex_timedlock(&mutex.handle, &s);
	switch (rc) {
	case 0:
		return 0;
	case ETIMEDOUT:
		return 1;
	default:
		mutex.error = rc;
	}
	return -1;
} // version (Posix)
}

int osmutexrelease(os_mutex_t *mutex) {
	if (mutex == null) assert(0, "null mutex");

version (Windows) {
	if (ReleaseMutex(mutex.handle) == FALSE) {
		mutex.error = GetLastError();
		return -1;
	}
	return 0;
} else version (Posix) {
	int rc = pthread_mutex_unlock(&mutex.handle);
	if (rc) {
		mutex.error = rc;
		return -1;
	}
	return 0;
} // version (Posix)
}
