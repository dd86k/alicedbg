/**
 * Bit manipulation utility module.
 *
 * This includes bit swapping functions, and some extras (such as the
 * BIT template to help selecting bits).
 *
 * Most useful being the fswap variants, which depending on the requested
 * endian (compared to the target's), return a function for bulk processing.
 *
 * License: BSD 3-clause
 */
module adbg.utils.bit;

import adbg.platform;

extern (C):

/// Create a 1-bit bitmask with a bit position (0-based, 1 << a).
template BIT(int n) { enum { BIT = 1 << n } }

/// Turn a 4-character string into a 4-byte number
/// Params: s = 4-character string
template char4i32(char[4] s) {
	version (BigEndian)
		enum { char4i32 = (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | (s[3]) }
	else
		enum { char4i32 = (s[3] << 24) | (s[2] << 16) | (s[1] << 8) | (s[0]) }
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

private ushort adbg_util_nop16(ushort v) { return v; }
private uint adbg_util_nop32(uint v) { return v; }
private ulong adbg_util_nop64(ulong v) { return v; }

/// Byte-swap an 16-bit value.
/// Params: v = 16-bit value
/// Returns: Byte-swapped value
/// Notes:
/// LDC and GDC transform this into a ROL instruction.
/// If x86 inline assembly is available, DMD uses the ROL instruction.
ushort adbg_util_bswap16(ushort v) pure nothrow @nogc {
	static if (IN_ASM == InlineAsm.DMD_x86) {
		asm pure nothrow @nogc {
			lea EDI, v;
			rol word ptr [EDI], 8;
		}
		return v;
	} else static if (IN_ASM == InlineAsm.DMD_x86_64) {
		asm pure nothrow @nogc {
			lea RDI, v;
			rol word ptr [RDI], 8;
		}
		return v;
	} else
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
	static if (IN_ASM == InlineAsm.DMD_x86 || IN_ASM == InlineAsm.DMD_x86_64) {
		asm pure nothrow @nogc {
			mov EAX, v;
			bswap EAX;
			mov v, EAX;
		}
		return v;
	} else {
		v = (v >> 16) | (v << 16);
		return ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8);
	}
}

/// Byte-swap an 64-bit value.
/// Params: v = 64-bit value
/// Returns: Byte-swapped value
/// Notes:
/// Shamelessly taken from https://stackoverflow.com/a/19560621
/// Only LDC is able to pick this up as BSWAP.
/// If x86 inline assembly is available, DMD uses the BSWAP instruction.
ulong adbg_util_bswap64(ulong v) pure nothrow @nogc {
	static if (IN_ASM == InlineAsm.DMD_x86) {
		asm pure nothrow @nogc {
			lea EDI, v;
			mov EAX, [EDI];
			mov EDX, [EDI+4];
			bswap EAX;
			bswap EDX;
			mov [EDI+4], EAX;
			mov [EDI], EDX;
		}
		return v;
	} else static if (IN_ASM == InlineAsm.DMD_x86_64) {
		asm pure nothrow @nogc {
			mov RAX, v;
			bswap RAX;
			mov v, RAX;
		}
		return v;
	} else {
		v = (v >> 32) | (v << 32);
		v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
		return ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
	}
}

unittest {
	assert(adbg_util_bswap16(0xAABB) == 0xBBAA);
	assert(adbg_util_bswap32(0xAABBCCDD) == 0xDDCCBBAA);
	assert(adbg_util_bswap64(0xAABBCCDD_11223344) == 0x44332211_DDCCBBAA);
	version (LittleEndian) {
		fswap16 lsb16 = adbg_util_fswap16(0);
		fswap32 lsb32 = adbg_util_fswap32(0);
		fswap64 lsb64 = adbg_util_fswap64(0);
		fswap16 msb16 = adbg_util_fswap16(1);
		fswap32 msb32 = adbg_util_fswap32(1);
		fswap64 msb64 = adbg_util_fswap64(1);
		// LSB matches
		assert(lsb16(0xAABB) == 0xAABB);
		assert(lsb32(0xAABBCCDD) == 0xAABBCCDD);
		assert(lsb64(0xAABBCCDD_11223344) == 0xAABBCCDD_11223344);
		// MSB does not match
		assert(msb16(0xAABB) == 0xBBAA);
		assert(msb32(0xAABBCCDD) == 0xDDCCBBAA);
		assert(msb64(0xAABBCCDD_11223344) == 0x44332211_DDCCBBAA);
	} else {
		fswap16 lsb16 = adbg_util_fswap16(0);
		fswap32 lsb32 = adbg_util_fswap32(0);
		fswap64 lsb64 = adbg_util_fswap64(0);
		fswap16 msb16 = adbg_util_fswap16(1);
		fswap32 msb32 = adbg_util_fswap32(1);
		fswap64 msb64 = adbg_util_fswap64(1);
		// LSB does not match
		assert(lsb16(0xAABB) == 0xBBAA);
		assert(lsb32(0xAABBCCDD) == 0xDDCCBBAA);
		assert(lsb64(0xAABBCCDD_11223344) == 0x44332211_DDCCBBAA);
		// MSB matches
		assert(msb16(0xAABB) == 0xAABB);
		assert(msb32(0xAABBCCDD) == 0xAABBCCDD);
		assert(msb64(0xAABBCCDD_11223344) == 0xAABBCCDD_11223344);
	}
}