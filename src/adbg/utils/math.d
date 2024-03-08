/// Math utilities.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.utils.math;

/// Choose the highest number.
template MAX(size_t a, size_t b) {
	enum MAX = a >= b ? a : b;
}
/// Choose the lowest number.
template MIN(size_t a, size_t b) {
	enum MIN = a <= b ? a : b;
}

@system unittest {
	static assert(MAX!(1, 2) == 2);
	static assert(MAX!(2, 2) == 2);
	static assert(MIN!(1, 2) == 1);
	static assert(MIN!(1, 1) == 1);
}

size_t max(size_t a, size_t b) {
	return a >= b ? a : b;
}
size_t min(size_t a, size_t b) {
	return a <= b ? a : b;
}

/// Make a constant binary size (base 1024^3).
template GiB(int a) {
	enum ulong GiB = a * 1024L * 1024L * 1024L;
}
/// Make a constant binary size (base 1024^2).
template MiB(int a) {
	enum ulong MiB = a * 1024L * 1024L;
}
/// Make a constant binary size (base 1024^1).
template KiB(int a) {
	enum ulong KiB = a * 1024L;
}

@system unittest {
	static assert(KiB!1 == 1024);
	static assert(KiB!2 == 1024 * 2);
	static assert(MiB!1 == 1024 * 1024);
	static assert(MiB!3 == 1024 * 1024 * 3);
	static assert(GiB!1 == 1024 * 1024 * 1024);
	static assert(GiB!4 == 1024L * 1024 * 1024 * 4);
}