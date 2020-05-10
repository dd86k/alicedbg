/**
 * Bit manipulation utility module.
 *
 * This includes bit swapping functions, and some extras (such as the
 * BIT template to help selecting bits).
 *
 * Most useful being the fswap variants, which depending on the requested
 * endian (compared to the target's), return a function for bulk processing.
 *
 * License: BSD 3-Clause
 */
module adbg.utils.bit;

extern (C):

/// Create a 1-bit bitmask with a bit position (0-based, 1 << a).
template BIT(int n) { enum { BIT = 1 << n } }

version (LittleEndian)
	private enum TE = 0; /// Target Endian
else
	private enum TE = 1; /// Target Endian

pragma(inline, true): // Encourage inlining whenever possible

/// Return a function pointer depending if requested endian matches target
/// endian. If it matches identical, this function returns a function that
/// returns the same value. If it does not match, this function returns
/// a function that effectively byte swaps the value. This is useful for bulk
/// operations, such as parsing header data or processing disassembly.
/// Params: e = Target endian (0=Little, 1=Big)
/// Returns: Function pointer
ushort function(ushort) adbg_util_fswap16(int e) {
	if (e == TE)	// Same endian, send bogus function
		return &adbg_util_bswap16nop;
	else	// Different endian, send bswap function
		return &adbg_util_bswap16;
}

/// Return a function pointer depending if requested endian matches target
/// endian. If it matches identical, this function returns a function that
/// returns the same value. If it does not match, this function returns
/// a function that effectively byte swaps the value. This is useful for bulk
/// operations, such as parsing header data or processing disassembly.
/// Params: e = Target endian (0=Little, 1=Big)
/// Returns: Function pointer
uint function(uint) adbg_util_fswap32(int e) {
	if (e == TE)	// Same endian, send bogus function
		return &adbg_util_bswap32nop;
	else	// Different endian, send bswap function
		return &adbg_util_bswap32;
}

/// Return a function pointer depending if requested endian matches target
/// endian. If it matches identical, this function returns a function that
/// returns the same value. If it does not match, this function returns
/// a function that effectively byte swaps the value. This is useful for bulk
/// operations, such as parsing header data or processing disassembly.
/// Params: e = Target endian (0=Little, 1=Big)
/// Returns: Function pointer
ulong function(ulong) adbg_util_fswap64(int e) {
	if (e == TE)	// Same endian, send bogus function
		return &adbg_util_bswap64nop;
	else	// Different endian, send bswap function
		return &adbg_util_bswap64;
}

/// No-op swap for fswap16.
/// Params: v = 16-bit value
/// Returns: Same value
ushort adbg_util_bswap16nop(ushort v) {
	return v;
}
/// No-op swap for fswap32.
/// Params: v = 32-bit value
/// Returns: Same value
uint adbg_util_bswap32nop(uint v) {
	return v;
}
/// No-op swap for fswap64.
/// Params: v = 64-bit value
/// Returns: Same value
ulong adbg_util_bswap64nop(ulong v) {
	return v;
}

/// Byte-swap an 16-bit value.
/// Params: v = 16-bit value
/// Returns: Byte-swapped value
ushort adbg_util_bswap16(ushort v) {
	return cast(ushort)(v >> 8 | v << 8);
}

/// Byte-swap an 32-bit value.
/// Params: v = 32-bit value
/// Returns: Byte-swapped value
/// Notes:
/// Shamelessly taken from https://stackoverflow.com/a/19560621
/// Only LDC is able to pick this up as BSWAP
uint adbg_util_bswap32(uint v) {
	v = (v >> 16) | (v << 16);
	return ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8);
}

/// Byte-swap an 64-bit value.
/// Params: v = 64-bit value
/// Returns: Byte-swapped value
/// Notes:
/// Shamelessly taken from https://stackoverflow.com/a/19560621
/// Only LDC is able to pick this up as BSWAP
ulong adbg_util_bswap64(ulong v) {
	v = (v >> 32) | (v << 32);
	v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
	return ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
}

unittest {
	assert(adbg_util_bswap16(0xAABB) == 0xBBAA);
	assert(adbg_util_bswap32(0xAABBCCDD) == 0xDDCCBBAA);
	assert(adbg_util_bswap64(0xAABBCCDD_11223344) == 0x44332211_DDCCBBAA);
	version (LittleEndian) {
		// LSB matches
		assert(adbg_util_cswap16(0xAABB, 0) == 0xAABB);
		assert(adbg_util_cswap32(0xAABBCCDD, 0) == 0xAABBCCDD);
		assert(adbg_util_cswap64(0xAABBCCDD_11223344, 0) == 0xAABBCCDD_11223344);
		// MSB does not match
		assert(adbg_util_cswap16(0xAABB, 1) == 0xBBAA);
		assert(adbg_util_cswap32(0xAABBCCDD, 1) == 0xDDCCBBAA);
		assert(adbg_util_cswap64(0xAABBCCDD_11223344, 1) == 0x44332211_DDCCBBAA);
	} else {
		// LSB does not match
		assert(adbg_util_cswap16(0xAABB, 0) == 0xBBAA);
		assert(adbg_util_cswap32(0xAABBCCDD, 0) == 0xDDCCBBAA);
		assert(adbg_util_cswap64(0xAABBCCDD_11223344, 0) == 0x44332211_DDCCBBAA);
		// MSB matches
		assert(adbg_util_cswap16(0xAABB, 1) == 0xAABB);
		assert(adbg_util_cswap32(0xAABBCCDD, 1) == 0xAABBCCDD);
		assert(adbg_util_cswap64(0xAABBCCDD_11223344, 1) == 0xAABBCCDD_11223344);
	}
}