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
/// License: BSD-3-Clause-Clear
module adbg.utils.bit;

import adbg.platform;
import core.bitop : bswap;

// TODO: Helper for array of bits (checking/unchecking array of bytes)
// TODO: adbg_bit_listget
//       Base pointer to item list (void*)
//       Index to item list (size_t)
//       Base range pointer (void*)
//       Range size in item count (size_t)
//       Size of one item (size_t)

extern (C):

/// Create a 1-bit bitmask with a bit position (0-based, 1 << a).
/// Params: n = Bit position (0-based)
template BIT(int n) if (n < 32) { enum { BIT = 1 << n } }
extern (D) unittest {
	assert(BIT!0 == 1 << 0);
	assert(BIT!1 == 1 << 1);
	assert(BIT!2 == 1 << 2);
	assert(BIT!4 == 1 << 4);
	assert(BIT!4 == 0b1_0000);
	assert(BIT!4 == 16);
}

// Form a ushort from byte values
template I16(ubyte b1, ubyte b2) {
	version (BigEndian)
		enum ushort I16 = (b1 << 8) | b2;
	else
		enum ushort I16 = (b2 << 8) | b1;
}
extern (D) unittest {
	version (BigEndian) assert(I16!(0xaa, 0xbb) == 0xaabb);
	else                assert(I16!(0xaa, 0xbb) == 0xbbaa);
}

// Form an array using a 16-bit number
template ARRAY16(ushort n) {
	version (BigEndian)
		enum ubyte[2] ARRAY16 = [ n >> 8, n & 255 ];
	else
		enum ubyte[2] ARRAY16 = [ n & 255, n >> 8 ];
}
extern (D) unittest {
	version (BigEndian) assert(ARRAY16!(0xaabb) == [ 0xaa, 0xbb ]);
	else                assert(ARRAY16!(0xaabb) == [ 0xbb, 0xaa ]);
}

// Form an array using a 32-bit number
template ARRAY32(uint n) {
	version (BigEndian)
		enum ubyte[4] ARRAY32 = [ n >> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255 ];
	else
		enum ubyte[4] ARRAY32 = [ n & 255, (n >> 8) & 255, (n >> 16) & 255, n >> 24 ];
}
extern (D) unittest {
	version (BigEndian) assert(ARRAY32!(0xaabbccdd) == [ 0xaa, 0xbb, 0xcc, 0xdd ]);
	else                assert(ARRAY32!(0xaabbccdd) == [ 0xdd, 0xcc, 0xbb, 0xaa ]);
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

/// Turn a 8-character string into a 8-byte number
/// Params: s = 8-character string
template CHAR64(char[8] s) {
	version (BigEndian)
		enum ulong CHAR64 =
			(cast(ulong)s[0] << 56) | (cast(ulong)s[1] << 48) |
			(cast(ulong)s[2] << 40) | (cast(ulong)s[3] << 32) |
			(cast(ulong)s[4] << 24) | (cast(ulong)s[5] << 16) |
			(cast(ulong)s[6] << 8)  | s[7];
	else
		enum ulong CHAR64 =
			(cast(ulong)s[7] << 56) | (cast(ulong)s[6] << 48) |
			(cast(ulong)s[5] << 40) | (cast(ulong)s[4] << 32) |
			(cast(ulong)s[3] << 24) | (cast(ulong)s[2] << 16) |
			(cast(ulong)s[1] << 8)  | s[0];
}
/// 
@system unittest {
	version (LittleEndian) assert(CHAR64!"ABCDabcd" == 0x6463626144434241);
	version (BigEndian)    assert(CHAR64!"ABCDabcd" == 0x4142434461626364);
}

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
		return bswap(v); // Intrinsic
	} else {
		// Source: https://stackoverflow.com/a/19560621
		v = (v >> 32) | (v << 32);
		v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
		return ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
	}
}

/// 
@system unittest {
	enum N16 = 0xAABB; enum R16 = 0xBBAA;
	enum N32 = 0xAABBCCDD; enum R32 = 0xDDCCBBAA;
	enum N64 = 0xAABBCCDD_11223344; enum R64 = 0x44332211_DDCCBBAA;
	
	assert(adbg_bswap16(N16) == R16, "bswap16");
	assert(adbg_bswap32(N32) == R32, "bswap32");
	assert(adbg_bswap64(N64) == R64, "bswap64");
}

uint adbg_bits_extract32(uint v, uint len, uint pos) {
	return (v >> pos) & ((1 << len) - 1);
}
@system unittest {
	uint flags = 0b1010_1111_0000_0011_0000;
	assert(adbg_bits_extract32(flags, 1, 0) == 0);
	assert(adbg_bits_extract32(flags, 1, 1) == 0);
	assert(adbg_bits_extract32(flags, 2, 4) == 3);
	assert(adbg_bits_extract32(flags, 4, 12) == 0xf);
	assert(adbg_bits_extract32(flags, 4, 16) == 0b1010);
}

size_t adbg_alignup(size_t x, int s) {
	size_t mask = s - 1;
	return (x + mask) & (~mask);
}
@system unittest {
	assert(adbg_alignup(0, uint.sizeof) == 0);
	assert(adbg_alignup(1, uint.sizeof) == 4);
	assert(adbg_alignup(2, uint.sizeof) == 4);
	assert(adbg_alignup(3, uint.sizeof) == 4);
	assert(adbg_alignup(4, uint.sizeof) == 4);
	assert(adbg_alignup(5, uint.sizeof) == 8);
	assert(adbg_alignup(6, uint.sizeof) == 8);
	assert(adbg_alignup(7, uint.sizeof) == 8);
	assert(adbg_alignup(8, uint.sizeof) == 8);
	assert(adbg_alignup(9, uint.sizeof) == 12);
	assert(adbg_alignup(0, ulong.sizeof) == 0);
	assert(adbg_alignup(1, ulong.sizeof) == 8);
	assert(adbg_alignup(2, ulong.sizeof) == 8);
	assert(adbg_alignup(3, ulong.sizeof) == 8);
	assert(adbg_alignup(4, ulong.sizeof) == 8);
	assert(adbg_alignup(5, ulong.sizeof) == 8);
	assert(adbg_alignup(6, ulong.sizeof) == 8);
	assert(adbg_alignup(7, ulong.sizeof) == 8);
	assert(adbg_alignup(8, ulong.sizeof) == 8);
	assert(adbg_alignup(9, ulong.sizeof) == 16);
}

// Ditto but returns long unconditionally
long adbg_alignup64(long x, int s) {
	long mask = s - 1;
	return (x + mask) & (~mask);
}

size_t adbg_aligndown(size_t x, int s) {
	size_t mask = s - 1;
	return x - (x & mask);
}
@system unittest {
	assert(adbg_aligndown(0, uint.sizeof) == 0);
	assert(adbg_aligndown(1, uint.sizeof) == 0);
	assert(adbg_aligndown(2, uint.sizeof) == 0);
	assert(adbg_aligndown(3, uint.sizeof) == 0);
	assert(adbg_aligndown(4, uint.sizeof) == 4);
	assert(adbg_aligndown(5, uint.sizeof) == 4);
	assert(adbg_aligndown(6, uint.sizeof) == 4);
	assert(adbg_aligndown(7, uint.sizeof) == 4);
	assert(adbg_aligndown(8, uint.sizeof) == 8);
	assert(adbg_aligndown(9, uint.sizeof) == 8);
	assert(adbg_aligndown(0, ulong.sizeof) == 0);
	assert(adbg_aligndown(1, ulong.sizeof) == 0);
	assert(adbg_aligndown(2, ulong.sizeof) == 0);
	assert(adbg_aligndown(3, ulong.sizeof) == 0);
	assert(adbg_aligndown(4, ulong.sizeof) == 0);
	assert(adbg_aligndown(5, ulong.sizeof) == 0);
	assert(adbg_aligndown(6, ulong.sizeof) == 0);
	assert(adbg_aligndown(7, ulong.sizeof) == 0);
	assert(adbg_aligndown(8, ulong.sizeof) == 8);
	assert(adbg_aligndown(9, ulong.sizeof) == 8);
}

/// Ensure that a pointer instance with its size is situated inside an allocated buffer.
/// Params:
/// 	ptr = Pointer of instance.
/// 	sizeof = Size of the instance in memory.
/// 	buffer = Base pointer of the memory buffer.
/// 	bufsize = Size of the bufer memory allocation.
/// Returns: True is pointer instance breaches outside allocated memory buffer.
align(true)
bool adbg_bits_boundchk(void *ptr, size_t sizeof, void *buffer, size_t bufsize) {
	// ptr + sizeof might overflow
	return ptr < buffer || ptr >= buffer + bufsize || ptr + sizeof > buffer + bufsize;
}
@system unittest {
	template P(size_t n) { enum P = cast(void*)n; }
	// Typical usage, check if pointer instance and size within buffer
	assert(adbg_bits_ptrbounds(P!20, uint.sizeof, P!10, 30) == false);
	// Within bounds
	assert(adbg_bits_ptrbounds(P!0,  4, P!0, 20) == false);
	assert(adbg_bits_ptrbounds(P!1,  4, P!0, 20) == false);
	assert(adbg_bits_ptrbounds(P!10, 4, P!0, 20) == false);
	assert(adbg_bits_ptrbounds(P!11, 4, P!0, 20) == false);
	assert(adbg_bits_ptrbounds(P!16, 4, P!0, 20) == false);
	// Outside bounds
	assert(adbg_bits_ptrbounds(P!0,  4, P!100, 20));
	assert(adbg_bits_ptrbounds(P!19, 4, P!0, 20));
	assert(adbg_bits_ptrbounds(P!20, 4, P!0, 20));
	assert(adbg_bits_ptrbounds(P!30, 4, P!0, 20));
	assert(adbg_bits_ptrbounds(P!40, 4, P!0, 20));
	assert(adbg_bits_ptrbounds(P!(-1), 4, P!0, 20));
	assert(adbg_bits_ptrbounds(P!0, 100, P!0, 20));
}

alias adbg_bits_ptrbounds = adbg_bits_boundchk;