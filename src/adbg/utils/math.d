/// Math utilities.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.utils.math;

template MAX(size_t a, size_t b) {
	enum MAX = a >= b ? a : b;
}
template MIN(size_t a, size_t b) {
	enum MIN = a <= b ? a : b;
}
