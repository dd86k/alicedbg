/// Condition variable primitive.
///
/// No user code should be using this directly, as it is used internally.
///
/// Windows: Uses Condition Variable API (Vista+).
/// POSIX: Uses pthread condition variable API.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.os.condvar;

import adbg.os.lock;

version (Windows) {
	import core.sys.windows.winbase :
		LPCRITICAL_SECTION,
		INFINITE,
		GetLastError;
	import core.sys.windows.windef :
		BOOL, FALSE, DWORD;
	import core.sys.windows.winerror : ERROR_TIMEOUT;

	// CONDITION_VARIABLE API (Vista+)
	// Not available in druntime.
	struct CONDITION_VARIABLE {
		void* Ptr;
	}
	extern (Windows) {
		void InitializeConditionVariable(CONDITION_VARIABLE*);
		BOOL SleepConditionVariableCS(CONDITION_VARIABLE*, LPCRITICAL_SECTION, DWORD);
		void WakeConditionVariable(CONDITION_VARIABLE*);
		void WakeAllConditionVariable(CONDITION_VARIABLE*);
	}

	private alias os_condvar = CONDITION_VARIABLE;
} else version (Posix) {
	import core.sys.posix.pthread :
		pthread_cond_t,
		pthread_cond_init, pthread_cond_destroy,
		pthread_cond_wait, pthread_cond_timedwait,
		pthread_cond_signal, pthread_cond_broadcast,
		pthread_mutex_t;

	private alias os_condvar = pthread_cond_t;
}

struct os_condvar_t {
	os_condvar handle;
}

/// Initialize a new condition variable.
/// Params: cv = os_condvar_t instance.
/// Returns: OS error code.
int os_condvar_init(os_condvar_t *cv) {
	assert(cv, "null condvar");
version (Windows) {
	InitializeConditionVariable(&cv.handle);
} else version (Posix) {
	pthread_cond_init(&cv.handle, null);
} else static assert(false, "os_condvar_init");
	return 0;
}

/// Destroy condition variable.
/// Params: cv = os_condvar_t instance.
void os_condvar_destroy(os_condvar_t *cv) {
	assert(cv, "null condvar");
version (Windows) {
	// No-op on Windows: CONDITION_VARIABLE has no resources to release.
} else version (Posix) {
	pthread_cond_destroy(&cv.handle);
} else static assert(false, "os_condvar_destroy");
}

/// Wait on a condition variable. The lock must be held by the caller.
/// Params:
///     cv = os_condvar_t instance.
///     lock = os_lock_t instance (must be held).
/// Returns: OS error code.
int os_condvar_wait(os_condvar_t *cv, os_lock_t *lock) {
	assert(cv, "null condvar");
	assert(lock, "null lock");
version (Windows) {
	if (SleepConditionVariableCS(&cv.handle, cast(LPCRITICAL_SECTION)&lock.handle, INFINITE) == FALSE)
		return GetLastError();
	return 0;
} else version (Posix) {
	return pthread_cond_wait(&cv.handle, &lock.handle);
} else static assert(false, "os_condvar_wait");
}

/// Wait on a condition variable for a limited amount of time.
/// The lock must be held by the caller.
/// Params:
///     cv = os_condvar_t instance.
///     lock = os_lock_t instance (must be held).
///     ms = Timeout in milliseconds.
///     status = Status pointer. Updated to 1 if timed out, or 0 otherwise.
/// Returns: OS error code.
int os_condvar_waitfor(os_condvar_t *cv, os_lock_t *lock, uint ms, int *status) {
	assert(cv, "null condvar");
	assert(lock, "null lock");
version (Windows) {
	if (SleepConditionVariableCS(&cv.handle, cast(LPCRITICAL_SECTION)&lock.handle, ms)) {
		if (status) *status = 0;
		return 0;
	}
	DWORD err = GetLastError();
	//enum ERROR_TIMEOUT = 0x5B4;
	if (err == ERROR_TIMEOUT) {
		if (status) *status = 1;
		return 0;
	}
	return err;
} else version (Posix) {
	import core.sys.posix.time : timespec, clock_gettime, CLOCK_REALTIME, time_t;
	import core.stdc.config : c_long;
	import core.stdc.errno : ETIMEDOUT;

	time_t secs = ms / 1000;
	c_long nsec = (ms % 1000) * 1_000_000;

	timespec ts = void;
	if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
		import core.stdc.errno : errno;
		return errno;
	}
	ts.tv_sec  += secs;
	ts.tv_nsec += nsec;

	// nsec overflow
	enum nsec1sec = 1_000_000_000;
	if (ts.tv_nsec >= nsec1sec) {
		++ts.tv_sec;
		ts.tv_nsec -= nsec1sec;
	}

	int rc = pthread_cond_timedwait(&cv.handle, &lock.handle, &ts);
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
} else static assert(false, "os_condvar_waitfor");
}

/// Wake one thread waiting on the condition variable.
/// Params: cv = os_condvar_t instance.
/// Returns: OS error code.
int os_condvar_signal(os_condvar_t *cv) {
	assert(cv, "null condvar");
version (Windows) {
	WakeConditionVariable(&cv.handle);
	return 0;
} else version (Posix) {
	return pthread_cond_signal(&cv.handle);
} else static assert(false, "os_condvar_signal");
}

/// Wake all threads waiting on the condition variable.
/// Params: cv = os_condvar_t instance.
/// Returns: OS error code.
int os_condvar_broadcast(os_condvar_t *cv) {
	assert(cv, "null condvar");
version (Windows) {
	WakeAllConditionVariable(&cv.handle);
	return 0;
} else version (Posix) {
	return pthread_cond_broadcast(&cv.handle);
} else static assert(false, "os_condvar_broadcast");
}
