import adbg.os.threads;

// Expects no data, returns 0
extern (C)
int threadfunc0(__osthread_t *thread, void *data) {
	assert(data == null);
	return 0;
}
unittest {
	__osthread_t *t = osthrnew(&threadfunc0);
	assert(t, "t == NULL");
	assert(osthrjoin(t) == 0, "osthrjoin(t) != 0");
}

// Expects no data, returns 1
extern (C)
int threadfunc1(__osthread_t *thread, void *data) {
	assert(data == null);
	return 1;
}
unittest {
	__osthread_t *t = osthrnew(&threadfunc1);
	assert(t, "t == NULL");
	assert(osthrjoin(t) == 1, "osthrjoin(t) != 1");
}

// Expects data, returns 0
enum FUNC2DATA0 = 3;
enum FUNC2DATA1 = 300;
extern (C)
int threadfunc2(__osthread_t *thread, void *data) {
	assert(data);
	*cast(int*)data = FUNC2DATA1;
	return 0;
}
unittest {
	__gshared int a = FUNC2DATA0;
	__osthread_t *t = osthrnew(&threadfunc2, &a);
	assert(t, "t == NULL");
	assert(osthrjoin(t) == 0, "osthrjoin(t) != 0");
	assert(a == FUNC2DATA1, "a != FUNC2DATA1");
}

// Expects data, returns 1
enum FUNC3DATA0 = 5;
enum FUNC3DATA1 = 500;
extern (C)
int threadfunc3(__osthread_t *thread, void *data) {
	assert(data);
	*cast(int*)data = FUNC3DATA1;
	return 1;
}
unittest {
	__gshared int a = FUNC3DATA0;
	__osthread_t *t = osthrnew(&threadfunc3, &a);
	assert(t, "t == NULL");
	assert(osthrjoin(t) == 1, "osthrjoin(t) != 1");
	assert(a == FUNC3DATA1, "a != FUNC3DATA1");
}