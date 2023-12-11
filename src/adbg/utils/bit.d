/// Bit manipulation utility module.
///
/// This includes bit swapping functions, and some extras (such as the
/// BIT template to help selecting bits).
///
/// Most useful being the fswap variants, which depending on the requested
/// endian (compared to the target's), return a function for bulk processing.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.utils.bit;

import adbg.platform;

extern (C):

//TODO: Consider renaming to adbg.utils.memory
//TODO: INT16/INT32/INT64 templates (auto swap)
//      e.g., I16BE!64

/// Create a 1-bit bitmask with a bit position (0-based, 1 << a).
/// Params: n = Bit position (0-based)
template BIT(int n) if (n < 32) { enum { BIT = 1 << n } }
@system unittest {
	assert(BIT!0 == 1);
	assert(BIT!1 == 0b10);
	assert(BIT!2 == 0b100);
	assert(BIT!4 == 0b1_0000);
}

/// Turn a 2-character string into a 2-byte number
/// Params: s = 2-character string
template CHAR16(char[2] s) {
	version (BigEndian)
		enum ushort CHAR16 = (s[0] << 8) | s[1];
	else
		enum ushort CHAR16 = (s[1] << 8) | s[0];
}
/// 
@system unittest {
	version (LittleEndian) assert(CHAR16!"MZ" == 0x5a4d);
	version (BigEndian)    assert(CHAR16!"MZ" == 0x4d5a);
}

/// Turn a 4-character string into a 4-byte number
/// Params: s = 4-character string
template CHAR32(char[4] s) {
	version (BigEndian)
		enum uint CHAR32 = (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
	else
		enum uint CHAR32 = (s[3] << 24) | (s[2] << 16) | (s[1] << 8) | s[0];
}
/// 
@system unittest {
	version (LittleEndian) assert(CHAR32!"ABCD" == 0x44434241);
	version (BigEndian)    assert(CHAR32!"ABCD" == 0x41424344);
}

/// Ensure endianness on 16-bit number.
/// Params:
///   v = Value.
///   little = Little-endianness desired.
/// Returns: Potentially swapped value.
ushort adbg_util_ensure16(ushort v, bool little) pure {
	return little == PLATFORM_LSB ? v : adbg_util_bswap16(v);
}
/// Ensure endianness on 32-bit number.
/// Params:
///   v = Value.
///   little = Little-endianness desired.
/// Returns: Potentially swapped value.
uint adbg_util_ensure32(uint v, bool little) pure {
	return little == PLATFORM_LSB ? v : adbg_util_bswap32(v);
}
/// Ensure endianness on 64-bit number.
/// Params:
///   v = Value.
///   little = Little-endianness desired.
/// Returns: Potentially swapped value.
ulong adbg_util_ensure64(ulong v, bool little) pure {
	return little == PLATFORM_LSB ? v : adbg_util_bswap64(v);
}

struct adbg_swapper_t {
	swapfunc16 swap16;
	swapfunc32 swap32;
	swapfunc64 swap64;
}

adbg_swapper_t adbg_util_swapper(bool little) {
	adbg_swapper_t swapper = void;
	if (little == PLATFORM_LSB) {
		swapper.swap16 = &adbg_util_nop16;
		swapper.swap32 = &adbg_util_nop32;
		swapper.swap64 = &adbg_util_nop64;
	} else {
		swapper.swap16 = &adbg_util_bswap16;
		swapper.swap32 = &adbg_util_bswap32;
		swapper.swap64 = &adbg_util_bswap64;
	}
	return swapper;
}

alias swapfunc16 = ushort function(ushort);
alias swapfunc32 = uint function(uint);
alias swapfunc64 = ulong function(ulong);

private ushort adbg_util_nop16(ushort v) pure { return v; }
private uint adbg_util_nop32(uint v) pure { return v; }
private ulong adbg_util_nop64(ulong v) pure { return v; }

/// Byte-swap an 16-bit value.
/// Params: v = 16-bit value
/// Returns: Byte-swapped value
ushort adbg_bswap16(ushort v) pure {
	return cast(ushort)(v >> 8 | v << 8);
}

/// Byte-swap an 32-bit value.
/// Params: v = 32-bit value
/// Returns: Byte-swapped value
uint adbg_bswap32(uint v) pure {
	import core.bitop : bswap;
	return bswap(v); // Intrinsic
	// Source: https://stackoverflow.com/a/19560621
	//v = (v >> 16) | (v << 16);
	//return ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8);
}

/// Byte-swap an 64-bit value.
/// Params: v = 64-bit value
/// Returns: Byte-swapped value
ulong adbg_bswap64(ulong v) pure {
	// NOTE: Only recent versions of DMD inlines the intrinsic
	import adbg.include.d.config : D_FEATURE_BSWAP64;
	static if (D_FEATURE_BSWAP64) {
		import core.bitop : bswap;
		return bswap(v); // Intrinsic
	} else {
		// Source: https://stackoverflow.com/a/19560621
		v = (v >> 32) | (v << 32);
		v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
		return ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
	}
}

// Old names
//TODO: Deprecate old names
public alias adbg_util_bswap16 = adbg_bswap16;
public alias adbg_util_bswap32 = adbg_bswap32;
public alias adbg_util_bswap64 = adbg_bswap64;

/// 
unittest {
	enum N16 = 0xAABB; enum R16 = 0xBBAA;
	enum N32 = 0xAABBCCDD; enum R32 = 0xDDCCBBAA;
	enum N64 = 0xAABBCCDD_11223344; enum R64 = 0x44332211_DDCCBBAA;
	
	assert(adbg_bswap16(N16) == R16, "bswap16");
	assert(adbg_bswap32(N32) == R32, "bswap32");
	assert(adbg_bswap64(N64) == R64, "bswap64");
}