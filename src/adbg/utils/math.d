/// Math utilities.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.utils.math;

/// Choose the highest number.
/// Params:
/// 	a = Number 1.
/// 	b = Number 2.
template MAX(size_t a, size_t b) {
	enum MAX = a >= b ? a : b;
}
/// Choose the lowest number.
/// Params:
/// 	a = Number 1.
/// 	b = Number 2.
template MIN(size_t a, size_t b) {
	enum MIN = a <= b ? a : b;
}
extern (D) unittest {
	static assert(MAX!(1, 2) == 2);
	static assert(MAX!(2, 2) == 2);
	static assert(MIN!(1, 2) == 1);
	static assert(MIN!(1, 1) == 1);
}

size_t max(size_t a, size_t b) {
	return a >= b ? a : b;
}
extern (D) unittest {
	assert(max(1, 3) == 3);
	assert(max(2, 3) == 3);
	assert(max(3, 3) == 3);
	assert(max(4, 3) == 4);
}
size_t min(size_t a, size_t b) {
	return a <= b ? a : b;
}
extern (D) unittest {
	assert(min(1, 3) == 1);
	assert(min(2, 3) == 2);
	assert(min(3, 3) == 3);
	assert(min(4, 3) == 3);
}

/// Make a constant binary size (base 1024^3).
/// Params: a = Base size.
template GiB(int a) {
	enum ulong GiB = a * 1024L * 1024L * 1024L;
}
/// Make a constant binary size (base 1024^2).
/// Params: a = Base size.
template MiB(int a) {
	enum ulong MiB = a * 1024L * 1024L;
}
/// Make a constant binary size (base 1024^1).
/// Params: a = Base size.
template KiB(int a) {
	enum ulong KiB = a * 1024L;
}

extern (D) unittest {
	static assert(KiB!1 == 1024);
	static assert(KiB!2 == 1024 * 2);
	static assert(MiB!1 == 1024 * 1024);
	static assert(MiB!3 == 1024 * 1024 * 3);
	static assert(GiB!1 == 1024 * 1024 * 1024);
	static assert(GiB!4 == 1024L * 1024 * 1024 * 4);
}

/// Perform a division and round the result upwards.
///
/// Initially created for PDB to get the number of blocks from a stream size and blocksize.
/// Params:
///   a = Numerator.
///   b = Denominator.
/// Returns: Result.
uint ceildiv32(uint a, uint b) pure {
	return (a + b + 1) / b;
}
extern (D) unittest {
	assert(ceildiv32(0, 512) == 1);
	assert(ceildiv32(50, 512) == 1);
	assert(ceildiv32(512, 512) == 2);
	assert(ceildiv32(768, 512) == 2);
	assert(ceildiv32(1024, 512) == 3);
}