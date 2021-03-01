/**
 * Bit manipulation utility module.
 *
 * This includes bit swapping functions, and some extras (such as the
 * BIT template to help selecting bits).
 *
 * Most useful being the fswap variants, which depending on the requested
 * endian (compared to the target's), return a function for bulk processing.
 *
 * License: BSD-3-Clause
 */
module adbg.utils.bit;

import adbg.platform;

extern (C):

/// Create a 1-bit bitmask with a bit position (0-based, 1 << a).
/// Params: n = Bit position (0-based)
template BIT(int n) if (n < 32) { enum { BIT = 1 << n } }

/// Convert bits to bytes.
/// Params: n = Number of bits
template BITS(int n) if (n % 8 == 0) { enum { BITS = n << 3 } }

/// Turn a 4-character string into a 4-byte number
/// Params: s = 4-character string
template char4i32(char[4] s) {
	version (BigEndian)
		enum { char4i32 = (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | (s[3]) }
	else
		enum { char4i32 = (s[3] << 24) | (s[2] << 16) | (s[1] << 8) | (s[0]) }
}

/// Force a 16-bit number to be in little-endian in memory.
/// Params: n = 16-bit number 
template littlei16(int n) {
	version (BigEndian)
		enum { littlei16 = adbg_util_bswap16(n) }
	else
		enum { littlei16 = n }
}
/// Force a 32-bit number to be in little-endian in memory.
/// Params: n = 32-bit number 
template littlei32(int n) {
	version (BigEndian)
		enum { littlei32 = adbg_util_bswap32(n) }
	else
		enum { littlei32 = n }
}
/// Force a 64-bit number to be in little-endian in memory.
/// Params: n = 64-bit number 
template littlei64(int n) {
	version (BigEndian)
		enum { littlei64 = adbg_util_bswap64(n) }
	else
		enum { littlei64 = n }
}

/// Force a 16-bit number to be in big-endian in memory.
/// Params: n = 16-bit number 
template bigi16(int n) {
	version (LittleEndian)
		enum { bigi16 = adbg_util_bswap16(n) }
	else
		enum { bigi16 = n }
}
/// Force a 32-bit number to be in big-endian in memory.
/// Params: n = 32-bit number 
template bigi32(int n) {
	version (LittleEndian)
		enum { bigi32 = adbg_util_bswap32(n) }
	else
		enum { bigi32 = n }
}
/// Force a 64-bit number to be in big-endian in memory.
/// Params: n = 64-bit number 
template bigi64(int n) {
	version (LittleEndian)
		enum { bigi64 = adbg_util_bswap64(n) }
	else
		enum { bigi64 = n }
}

version (LittleEndian)
	private enum TE = 0; /// Target Endian
else
	private enum TE = 1; /// Target Endian

alias fswap16 = ushort function(ushort);
alias fswap32 = uint function(uint);
alias fswap64 = ulong function(ulong);

/// Return a function pointer depending if requested endian matches target
/// endian. If it matches identical, this function returns a function that
/// returns the same value. If it does not match, this function returns
/// a function that effectively byte swaps the value. This is useful for bulk
/// operations, such as parsing header data or processing disassembly.
/// Params: e = Endian (0=Little, 1=Big)
/// Returns: fswap16 function pointer
ushort function(ushort) adbg_util_fswap16(int e) {
	return e == TE ? &adbg_util_nop16 : &adbg_util_bswap16;
}

/// Return a function pointer depending if requested endian matches target
/// endian. If it matches identical, this function returns a function that
/// returns the same value. If it does not match, this function returns
/// a function that effectively byte swaps the value. This is useful for bulk
/// operations, such as parsing header data or processing disassembly.
/// Params: e = Endian (0=Little, 1=Big)
/// Returns: fswap32 function pointer
uint function(uint) adbg_util_fswap32(int e) {
	return e == TE ? &adbg_util_nop32 : &adbg_util_bswap32;
}

/// Return a function pointer depending if requested endian matches target
/// endian. If it matches identical, this function returns a function that
/// returns the same value. If it does not match, this function returns
/// a function that effectively byte swaps the value. This is useful for bulk
/// operations, such as parsing header data or processing disassembly.
/// Params: e = Endian (0=Little, 1=Big)
/// Returns: fswap64 function pointer
ulong function(ulong) adbg_util_fswap64(int e) {
	return e == TE ? &adbg_util_nop64 : &adbg_util_bswap64;
}

private ushort adbg_util_nop16(ushort v) pure { return v; }
private uint adbg_util_nop32(uint v) pure { return v; }
private ulong adbg_util_nop64(ulong v) pure { return v; }

/// Byte-swap an 16-bit value.
/// Params: v = 16-bit value
/// Returns: Byte-swapped value
ushort adbg_util_bswap16(ushort v) pure nothrow @nogc {
	return cast(ushort)(v >> 8 | v << 8);
}

/// Byte-swap an 32-bit value.
/// Params: v = 32-bit value
/// Returns: Byte-swapped value
/// Notes:
/// Shamelessly taken from https://stackoverflow.com/a/19560621
/// Only LDC is able to pick this up as BSWAP.
/// If x86 inline assembly is available, DMD uses the BSWAP instruction.
uint adbg_util_bswap32(uint v) pure nothrow @nogc {
	v = (v >> 16) | (v << 16);
	return ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8);
}

/// Byte-swap an 64-bit value.
/// Params: v = 64-bit value
/// Returns: Byte-swapped value
/// Notes:
/// Shamelessly taken from https://stackoverflow.com/a/19560621
/// Only LDC is able to pick this up as BSWAP.
/// If x86 inline assembly is available, DMD uses the BSWAP instruction.
ulong adbg_util_bswap64(ulong v) pure nothrow @nogc {
	v = (v >> 32) | (v << 32);
	v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
	return ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
}

/// 
unittest {
	enum N16 = 0xAABB; enum R16 = 0xBBAA;
	enum N32 = 0xAABBCCDD; enum R32 = 0xDDCCBBAA;
	enum N64 = 0xAABBCCDD_11223344; enum R64 = 0x44332211_DDCCBBAA;
	
	assert(adbg_util_bswap16(N16) == R16, "bswap16");
	assert(adbg_util_bswap32(N32) == R32, "bswap32");
	assert(adbg_util_bswap64(N64) == R64, "bswap64");
	
	version (LittleEndian) {
		fswap16 l16 = adbg_util_fswap16(0);
		fswap32 l32 = adbg_util_fswap32(0);
		fswap64 l64 = adbg_util_fswap64(0);
		fswap16 m16 = adbg_util_fswap16(1);
		fswap32 m32 = adbg_util_fswap32(1);
		fswap64 m64 = adbg_util_fswap64(1);
		// LSB matches, no swapping occurs
		assert(l16(N16) == N16, "fswap16-lsb");
		assert(l32(N32) == N32, "fswap32-lsb");
		assert(l64(N64) == N64, "fswap64-lsb");
		// MSB does not match
		assert(m16(N16) == R16, "fswap16-msb");
		assert(m32(N32) == R32, "fswap32-msb");
		assert(m64(N64) == R64, "fswap64-msb");
	} else {
		fswap16 l16 = adbg_util_fswap16(0);
		fswap32 l32 = adbg_util_fswap32(0);
		fswap64 l64 = adbg_util_fswap64(0);
		fswap16 m16 = adbg_util_fswap16(1);
		fswap32 m32 = adbg_util_fswap32(1);
		fswap64 m64 = adbg_util_fswap64(1);
		// LSB does not match
		assert(l16(N16) == R16, "fswap16-lsb");
		assert(l32(N32) == R32, "fswap32-lsb");
		assert(l64(N64) == R64, "fswap64-lsb");
		// MSB matches, no swapping occurs
		assert(m16(N16) == N16, "fswap16-msb");
		assert(m32(N32) == N32, "fswap32-msb");
		assert(m64(N64) == N64, "fswap64-msb");
	}
}