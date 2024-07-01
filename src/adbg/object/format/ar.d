/// UNIX library archive format.
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
import core.stdc.stdlib;

// NOTE: Possible object formats included
//       - ELF relocatable objects (POSIX)
//       - COFF objects (Windows)

// NOTE: MSVC linker can only process libraries under 4 GiB in size.

// NOTE: Format detection (taken and updated from llvm/lib/Object/Archive.cpp)
//       Below is the pattern that is used to figure out the archive format
//       GNU / System V archive format
//         First member : "/"  (May exist, if it exists, points to the symbol table)
//         Second member: "//" (Ditto)
//         "/" acts as a main index for all other members in the archive.
//         These members mostly contain object data (COFF or ELF)
//         u32:    Number of offsets
//         u32...: Absolute file offsets
//         Note: The string table is used if the filename exceeds 15 characters.
//       BSD archive format
//         First member: "__.SYMDEF", "__.SYMDEF_64" (Darwin), or "__.SYMDEF SORTED" (symbol table)
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

// NOTE: Member headers are observed, at least on MS variants, to be 2-byte aligned-up.

/// COFF library archive magic.
enum AR_MAGIC = CHAR64!"!<arch>\n";

// Thin COFF library archive magic. Used in GNU binutils and Elfutils.
//enum AR_THIN_MAGIC = CHAR64!"!<thin>\n";

// IBM's big library archive format
//  https://www.ibm.com/docs/en/aix/7.2?topic=formats-ar-file-format-big
//enum AR_BIG_MAGIC = CHAR64!"<bigaf>\n";

// IBM's small library archive format
//  https://www.ibm.com/docs/en/aix/7.2?topic=formats-ar-file-format-small
//enum AR_SMALL_MAGIC = CHAR64!"<aiaff>\n";

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

private enum ARFormat {
	unknown,
	gnu,
	bsd,
	microsoft,
}

private struct internal_ar_t {
	long offset; // current file offset of current header
	ar_member_header current; // current member
	ar_member_header symbol;  // symbol member
	void *symbol_buffer;
	int symbol_size;
}

private enum STATUS_SYMBOL_LOADED = 1 << 16;

int adbg_object_ar_load(adbg_object_t *o) {
	o.internal = malloc(internal_ar_t.sizeof);
	if (o.internal == null) 
		return adbg_oops(AdbgError.crt);
		
	o.format = AdbgObject.archive;
	return 0;
}

void adbg_object_ar_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
	//internal_ar_t *internal = cast(internal_ar_t*)o.internal;
	
	free(o.internal);
}

/// Convert a number from a fixed character buffer to a scalar integer.
/// Params:
///   p = Character buffer pointer. Can be null-terminated.
///   s = Size of character buffer. Or the maximum string length input.
/// Returns: Integer value.
private
int atoint(const(char)* p, size_t s) {
	if (p == null || s <= 0)
		return 0;
	int v; char c = void;
	for (size_t i; i < s && (c = p[i]) != 0; ++i) {
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
	assert(atoint("4000", 2) == 40); // Test buffer size
	assert(atoint("2147483647", 10) == int.max);
}

ar_member_header* adbg_object_ar_first_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_ar_t *internal = cast(internal_ar_t*)o.internal;
	
	// First entry starts right after signature
	internal.offset = ar_file_header.sizeof;
	
	// Read first member
	if (adbg_object_read_at(o, ar_file_header.sizeof, &internal.current, ar_member_header.sizeof))
		return null;
	
	// 
	if (internal.current.EndMarker != AR_EOL) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	return &internal.current;
}

// Get the next instance of the header
ar_member_header* adbg_object_ar_next_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_ar_t *internal = cast(internal_ar_t*)o.internal;
	
	int size = adbg_object_ar_membersize(&internal.current);
	if (size < 0) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	// Jump to next header location using the current member size
	// The alignment is needed at least for MS variants
	long newloc = adbg_alignup64(internal.offset + ar_member_header.sizeof + size, 2);
	
	// Read header
	if (adbg_object_read_at(o, newloc, &internal.current, ar_member_header.sizeof))
		return null;
	
	// 
	if (internal.current.EndMarker != AR_EOL) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	// All good, set as current, and return member
	internal.offset = newloc;
	return &internal.current;
}

int adbg_object_ar_membersize(ar_member_header *member) {
	if (member == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	return atoint(member.Size.ptr, member.Size.sizeof);
}

ar_member_data* adbg_object_ar_member_data(adbg_object_t *o, ar_member_header *member) {
	if (o == null || member == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_ar_t *internal = cast(internal_ar_t*)o.internal;
	
	int size = adbg_object_ar_membersize(member);
	if (size < 0) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	void *buffer = malloc(ar_member_data.sizeof + size);
	if (buffer == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	ar_member_data *data = cast(ar_member_data*)buffer;
	data.size = size;
	data.data = buffer + ar_member_data.sizeof;
	
	long dataloc = internal.offset + size;
	if (adbg_object_read_at(o, dataloc, data.data, size)) {
		free(buffer);
		return null;
	}
	
	return data;
}

void adbg_object_ar_member_data_close(ar_member_data *data) {
	if (data) free(data);
}

//TODO: adbg_object_ar_symbol
//      This will require going through all object files and get their symbols
//      So, waiting on being able to load objects in-memory

/*
const(char)* adbg_object_ar_symbol(adbg_object_t *o, size_t index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_ar_t *internal = cast(internal_ar_t*)o.internal;
	
	// Symbol member not loaded
	if ((o.status & STATUS_SYMBOL_LOADED) == 0) {
		version (Trace) trace("Loading first member");
		
		if (adbg_object_read_at(o, ar_file_header.sizeof, &internal.symbol, ar_member_header.sizeof))
			return null;
		
		internal.symbol_size = adbg_object_ar_membersize(&internal.symbol);
		if (internal.symbol_size < 0)
			return null;
		if (internal.symbol_size <= uint.sizeof) {
			adbg_oops(AdbgError.assertion);
			return null;
		}
		
		internal.symbol_buffer = malloc(internal.symbol_size);
		if (internal.symbol_buffer == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		
		if (adbg_object_read_at(o, ar_file_header.sizeof + ar_member_header.sizeof,
			internal.symbol_buffer, internal.symbol_size))
			return null;
		
		o.status |= STATUS_SYMBOL_LOADED;
	}
	
	uint count = adbg_bswap32(*cast(uint*)internal.symbol_buffer);
	
	if (index >= count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	uint *offsets = cast(uint*)(internal.symbol_buffer + uint.sizeof);
	
	uint *offset = offsets + index;
	
	if (adbg_bits_ptrbounds(offset, uint.sizeof, offsets, internal.symbol_size)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	// Offset to member headers
	uint aoffset = adbg_bswap32(*offset);
	
	version (Trace) trace("aoffset=%#x", aoffset);
	
	return null;
}
*/
