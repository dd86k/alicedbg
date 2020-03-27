/**
 * Bit manipulation utility module.
 *
 * This (will) include bit swapping functions, and some extras (such as the
 * BIT template to help selecting bits).
 *
 * The cswap functions are not templates, because structure fields are read
 * at runtime.
 *
 * License: BSD 3-Clause
 */
module utils.bit;

extern (C):

/// Create a 1-bit bitmask with a bit position (LSB, 0-based, 1 << a).
template BIT(int n) { enum { BIT = 1 << n } }

version (LittleEndian)
	private enum TE = 0;
else
	private enum TE = 1;

/// Conditionally swap if specified target endian does not match compiled
/// target.
/// Params:
/// 	v = 16-bit value
/// 	e = Target endian (0=Little, 1=Big)
/// Returns: Byte-swapped 16-bit value if TargetEndian is different
ushort cswap16(ushort v, int e) {
	return e == TE ? v : bswap16(v);
}

/// Conditionally swap if specified target endian does not match compiled
/// target.
/// Params:
/// 	v = 32-bit value
/// 	e = Target endian (0=Little, 1=Big)
/// Returns: Byte-swapped 32-bit value if TargetEndian is different
uint cswap32(uint v, int e) {
	return e == TE ? v : bswap32(v);
}

/// Conditionally swap if specified target endian does not match compiled
/// target.
/// Params:
/// 	v = 64-bit value
/// 	e = Target endian (0=Little, 1=Big)
/// Returns: Byte-swapped 64-bit value if TargetEndian is different
ulong cswap64(ulong v, int e) {
	return e == TE ? v : bswap64(v);
}

pragma(inline, true): // Encourage inlining

/// Byte-swap an 16-bit value.
/// Params: v = 16-bit value
/// Returns: Byte-swapped value
ushort bswap16(ushort v) {
	return cast(ushort)(v >> 8 | v << 8);
}

/// Byte-swap an 32-bit value.
/// Params: v = 32-bit value
/// Returns: Byte-swapped value
/// Notes:
/// Shamelessly taken from https://stackoverflow.com/a/19560621
/// Only LDC is able to pick this up as BSWAP
uint bswap32(uint v) {
	v = (v >> 16) | (v << 16);
	return ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8);
}

/// Byte-swap an 64-bit value.
/// Params: v = 64-bit value
/// Returns: Byte-swapped value
/// Notes:
/// Shamelessly taken from https://stackoverflow.com/a/19560621
/// Only LDC is able to pick this up as BSWAP
ulong bswap64(ulong v) {
	v = (v >> 32) | (v << 32);
	v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
	return ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
}

unittest {
	assert(bswap16(0xAABB) == 0xBBAA);
	assert(bswap32(0xAABBCCDD) == 0xDDCCBBAA);
	assert(bswap64(0xAABBCCDD_11223344) == 0x44332211_DDCCBBAA);
}