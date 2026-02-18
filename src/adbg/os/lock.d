/// Lightweight lock primitive.
///
/// No user code should be using this directly, as it is used internally.
///
/// Windows: Uses CriticalSection API (intra-process only, but faster than Mutex).
/// POSIX: Uses pthread mutex API.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.os.lock;

version (Windows) {
	import core.sys.windows.winbase :
		CRITICAL_SECTION, LPCRITICAL_SECTION,
		InitializeCriticalSection,
		DeleteCriticalSection,
		EnterCriticalSection,
		LeaveCriticalSection;

	private alias os_lock = CRITICAL_SECTION;
} else version (Posix) {
	import core.sys.posix.pthread :
		pthread_mutex_t,
		pthread_mutex_init, pthread_mutex_destroy,
		pthread_mutex_lock, pthread_mutex_unlock;

	private alias os_lock = pthread_mutex_t;
}

struct os_lock_t {
	os_lock handle;
}

/// Initialize a new lock.
/// Params: lock = os_lock_t instance.
/// Returns: OS error code.
int os_lock_init(os_lock_t *lock) {
	assert(lock, "null lock");
version (Windows) {
	InitializeCriticalSection(&lock.handle);
} else version (Posix) {
	pthread_mutex_init(&lock.handle, null);
} else static assert(false, "os_lock_init");
	return 0;
}

/// Destroy lock.
/// Params: lock = os_lock_t instance.
void os_lock_destroy(os_lock_t *lock) {
	assert(lock, "null lock");
version (Windows) {
	DeleteCriticalSection(&lock.handle);
} else version (Posix) {
	pthread_mutex_destroy(&lock.handle);
} else static assert(false, "os_lock_destroy");
}

/// Acquire exclusive access to lock.
/// Params: lock = os_lock_t instance.
/// Returns: OS error code.
int os_lock_acquire(os_lock_t *lock) {
	assert(lock, "null lock");
version (Windows) {
	EnterCriticalSection(&lock.handle);
	return 0;
} else version (Posix) {
	return pthread_mutex_lock(&lock.handle);
} else static assert(false, "os_lock_acquire");
}

/// Release exclusive access from lock.
/// Params: lock = os_lock_t instance.
/// Returns: OS error code.
int os_lock_release(os_lock_t *lock) {
	assert(lock, "null lock");
version (Windows) {
	LeaveCriticalSection(&lock.handle);
	return 0;
} else version (Posix) {
	return pthread_mutex_unlock(&lock.handle);
} else static assert(false, "os_lock_release");
}
