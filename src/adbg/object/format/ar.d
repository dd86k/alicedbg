/// UNIX library archive format.
///
/// This only supports the System V (aka GNU) variant.
///
/// Sources:
/// - gdb/include/aout/ar.h
/// - Microsoft Portable Executable and Common Object File Format Specification
/// - Microsoft Corporation, Revision 6.0 - February 1999
/// - Microsoft Corporation, Revision 8.3 - February 2013
/// - Microsoft Corporation, Revision 11 - February 2013
/// - winnt.h (10.0.22621.0)
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.format.ar;

import adbg.error;
import adbg.object.server;
import adbg.utils.bit;
import core.stdc.stdlib : atoi;
import core.stdc.string : memcpy;

// NOTE: MSVC linker can only process libraries under 4 GiB in size.

// NOTE: Format detection (taken and updated from LLVM@llvm/lib/Object/Archive.cpp)
//       Below is the pattern that is used to figure out the archive format
//       GNU archive format
//         First member : "/"  (May exist, if it exists, points to the symbol table)
//         Second member: "//" (Ditto)
//         Note: The string table is used if the filename exceeds 15 characters.
//       BSD archive format
//         First member: "__.SYMDEF" or "__.SYMDEF_64" (Darwin) or "__.SYMDEF SORTED" (symbol table)
//         There is no string table, if the filename exceeds 15 characters or has a
//         embedded space, the filename has #1/<size>, The size represents the size
//         of the filename that needs to be read after the archive header.
//       COFF archive format
//         First member : "/"
//         Second member: "/"  (Provides a directory of symbols)
//         Third member : "//" (May exist, if it exists, contains the string table)
//         Note: Microsoft PE/COFF Spec 8.3 says that the third member is present
//         even if the string table is empty. However, lib.exe does not in fact
//         seem to create the third member if there's no member whose filename
//         exceeds 15 characters. So the third member is optional.

// NOTE: Variants
//       GNU archive format
//         (optional) "/"
//            Acts as a main index for all other members in the archive
//            These members mostly contain object data (COFF or ELF these days)
//            Data:
//            u32:big    Number of offsets
//            u32...:big Absolute file offsets
//         (optional) "//"

// NOTE: Member headers are observed, at least on MS variants, to be 2-byte aligned-up.

/// COFF library archive magic.
enum AR_MAGIC = CHAR64!"!<arch>\n";
/// Thin COFF library archive magic. Used in GNU binutils and Elfutils.
enum AR_THIN_MAGIC = CHAR64!"!<thin>\n";
/// 
private enum AR_EOL = CHAR16!"`\n";

private immutable char[16] AR_LINKER_MEMBER    = "/               ";
private immutable char[16] AR_LONGNAMES_MEMBER = "//              ";
private immutable char[16] AR_HYBRIDMAP_MEMBER = "/<HYBRIDMAP>/   ";

/// 
struct ar_file_header {
	/// Magic containing "!<arch>\n" or similar
	char[8] Magic;
}

/// 
struct ar_member_header {
	/// Name of archive member, with a slash (/) appended
	/// to terminate the name. If the first character is a slash,
	/// the name has a special interpretation, as described
	/// below.
	///
	/// With name "Example/", the field gives the name of the archive
	/// member directly.
	///
	/// With name "/", the archive member is one of the two linker
	/// members. Both of the linker members have this name.
	///
	/// With name "//", the archive member is the longname member,
	/// which consists of a series of null-terminated ASCII strings.
	/// The longnames member is the third archive member, and must
	/// always be present even if the contents are empty.
	///
	/// With a name like "/n", the name of the archive member is located
	/// at offset n within the longnames member. The number n is the
	/// decimal representation of the offset. For example: "/26" indicates
	/// that the name of the archive member is located 26 bytes beyond the
	/// beginning of longnames member contents.
	char[16] Name;
	/// Date and time the archive member was created:
	/// ASCII decimal representation of the number of
	/// seconds since 1/1/1970 UCT.
	char[12] Date;
	/// ASCII decimal representation of the user ID.
	char[6] UserID;
	/// ASCII decimal representation of the group ID.
	char[6] GroupID;
	/// ASCII octal representation of the member’s file mode.
	char[8] Mode;
	/// ASCII decimal representation of the total size of the
	/// archive member, not including the size of the header.
	char[10] Size;
	union {
		/// The two bytes in the C string: "`\n" (0x60 0x0a).
		char[2] End;
		ushort EndMarker;
	}
}

struct ar_member_data {
	void *data;
	int size;
}

/// When first name is "/"
struct mscoff_first_linker_header {
	/// 
	uint SymbolCount;
	/// Offsets in big-endian
	uint[1] Offsets;
	// String table after SymbolCount * uint.sizeof
}

/// When second name is "/"
struct mscoff_second_linker_header {
	uint MemberCount;
	uint[1] Offsets;
	// uint SymbolCount; // Follows Offset table
	// ushort[*] Indices;
	// String Table after Indices
}

int adbg_object_ar_load(adbg_object_t *o) {
	o.format = AdbgObject.archive;
	return 0;
}

ar_member_header* adbg_object_ar_first_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	// First entry starts right after signature
	o.i.ar.current = ar_file_header.sizeof;
	
	// Return it
	return cast(ar_member_header*)(o.buffer + ar_file_header.sizeof);
}

/// Convert a number from a fixed character buffer to a scalar integer.
/// Params:
///   p = Character buffer pointer. Can be null-terminated.
///   s = Size of character buffer. Or the maximum string length input.
/// Returns: Integer value.
int atoint(const(char)* p, int s) {
	if (p == null || s <= 0)
		return 0;
	// If first non-space character met is '-', apply negation
	int v; char c = void;
	for (int i; i < s && (c = p[i]) != 0; ++i) {
		if (c < '0' || c > '9')
			continue;
		v = (10 * v) + (c - '0');
	}
	return v;
}
unittest {
	assert(atoint("0", 10) == 0);
	assert(atoint("1", 10) == 1);
	assert(atoint("2", 10) == 2);
	assert(atoint("86", 10) == 86);
	assert(atoint("123", 10) == 123);
	assert(atoint("4000", 10) == 4000);
	assert(atoint("68088", 10) == 68088);
	assert(atoint("4000", 2) == 40);
}

// Get the next instance of the header
ar_member_header* adbg_object_ar_next_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	// Jump to next header location using the current member size
	ar_member_header *member = cast(ar_member_header*)(o.buffer + o.i.ar.current);
	int size = cast(int)ar_member_header.sizeof + atoint(member.Size.ptr, member.Size.sizeof);
	size_t newloc = adbg_alignup(o.i.ar.current + size, 2);
	
	// At minimum, get member header
	if (adbg_object_outboundl(o, newloc, ar_member_header.sizeof)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	// Evaluate new member header with its new size
	member = cast(ar_member_header*)(o.buffer + newloc);
	if (member.EndMarker != AR_EOL) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	size = cast(int)ar_member_header.sizeof + atoint(member.Size.ptr, member.Size.sizeof);
	if (adbg_object_outboundl(o, newloc, ar_member_header.sizeof + size)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	// All good, set as current, and return member
	o.i.ar.current = newloc;
	return member;
}

// 
ar_member_data adbg_object_ar_data(adbg_object_t *o, ar_member_header *member) {
	ar_member_data m = void;
	
	if (o == null || member == null) {
		adbg_oops(AdbgError.invalidArgument);
		m.data = null; m.size = 0;
		return m;
	}
	
	m.data = cast(void*)member + ar_member_header.sizeof;
	m.size = atoint(member.Size.ptr, member.Size.sizeof);
	return m;
}

/*const(char)* adbg_object_ar_symbol(adbg_object_t *o, ar_member_header *member, uint index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	//TODO: Redo/Clean using offsets
	// NOTE: Hard to enforce length checks here
	
	//ar_member_header *member = cast(ar_member_header*)(o.buffer + lochead);
	uint *items = cast(uint*)(member + 1);
	uint  count = adbg_bswap32(*items++);
	version (Trace) trace("count=%d", count);
	if (index >= count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	uint locsym = adbg_bswap32(items[index]);
	//int size = atoint(member.Size.ptr, member.Size.sizeof);
	if (adbg_object_outbound(o, locsym)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	return o.bufferc + locsym;
}*/

// No-op for now, planned function
void adbg_object_ar_free(adbg_object_t *o, ar_member_header *member) {
}
