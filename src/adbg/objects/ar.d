/// UNIX library archive format.
///
/// Sources:
/// - Microsoft Portable Executable and Common Object File Format Specification
/// - Microsoft Corporation, Revision 6.0 - February 1999
/// - Microsoft Corporation, Revision 8.3 - February 2013
/// - Microsoft Corporation, Revision 11 - February 2013
/// - Windows SDK: winnt.h (10.0.22621.0)
/// - GDB (gdb/include/aout/ar.h)
/// - LLVM (llvm/lib/Object/Archive.cpp)
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.objects.ar;

import adbg.error;
import adbg.objectserver;
import adbg.utils.bit;
import core.stdc.stdlib;
import core.stdc.string : strncmp;
import core.stdc.ctype : isdigit;

extern (C):

enum ArVersion {
	unknown	= 0,
	gnu	= 1,
	bsd	= 2,
	coff	= 3,
}

// NOTE: Possible object formats included
//       - ELF relocatable objects (POSIX)
//       - COFF objects (Windows)

// NOTE: MSVC linker can only process libraries under 4 GiB in size.

// NOTE: Format detection (taken and updated from llvm/lib/Object/Archive.cpp)
//       GNU and System V (SVR4) archive format
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

/// Linker member
private immutable char[16] AR_MEMBER_LINKER     = "/               ";
/// Long name table
private immutable char[16] AR_MEMBER_LONGNAMES  = "//              ";

// Traditional 64-bit GNU archive member
private immutable char[16] AR_MEMBER_SYM64      = "/SYM64/         ";

// BSD
private immutable char[16] AR_MEMBER_SYMDEF     = "__.SYMDEF       ";
// BSD/Darwin
private immutable char[16] AR_MEMBER_SYMDEF64   = "__.SYMDEF_64    ";
// BSD
private immutable char[16] AR_MEMBER_SYMDEF_SORTED = "__.SYMDEF SORTED";

// I forgot where this one comes from
private immutable char[16] AR_MEMBER_HYBRIDMAP  = "/<HYBRIDMAP>/   ";
// Note from LLVM:
// "System libraries from the Windows SDK for Windows 11 contain this symbol.
// It looks like a CFG guard: we just skip it for now."
private immutable char[16] AR_MEMBER_XFGHASHMAP = "/<XFGHASHMAP>/  ";
// Note from LLVM:
// "Some libraries (e.g., arm64rt.lib) from the Windows WDK
// (version 10.0.22000.0) contain this undocumented special member."
private immutable char[16] AR_MEMBER_ECSYMBOLS  = "/<ECSYMBOLS>/   ";

/// 
struct ar_file_header_t {
	/// Magic containing "!<arch>\n" or similar
	char[8] Magic;
}

/// 
struct ar_member_header_t {
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
	/// archive member, excluding the size of this header.
	char[10] Size;
	union {
		/// The two bytes in the C string: "`\n" (0x60 0x0a).
		char[2] End;
		ushort EndMarker;
	}
}

struct ar_member_data_t {
	void *pointer;
	int size;
}

/// When first name is "/"
struct mscoff_first_linker_header_t {
	/// 
	uint SymbolCount;
	/// Offsets in big-endian
	uint[1] Offsets;
	// String table after SymbolCount * uint.sizeof
}

/// When second name is "/"
struct mscoff_second_linker_header_t {
	uint MemberCount;
	uint[1] Offsets;
	// uint SymbolCount; // Follows Offset table
	// ushort[*] Indices;
	// String Table after Indices
}

private struct internal_ar_t {
	ArVersion kind;
	
	// used for iterating
	long offset; // current file offset of current header
	ar_member_header_t current; // current member
}

private enum STATUS_SYMBOL_LOADED = 1 << 16;

int adbg_object_ar_load(adbg_object_t *o) {
	o.internal = malloc(internal_ar_t.sizeof);
	if (o.internal == null) 
		return adbg_oops(AdbgError.crt);
	
	// Since UNIX archives can still be used as regular archives,
	// we need to find out which kind of archive (gnu/bsd/msvc)
	// we're dealing, and that it is formatted correctly.
	/*
	ar_member_header_t *header0 = adbg_object_ar_first_member(o);
	if (header0 == null) {
		free(o.internal);
		return adbg_error_code();
	}
	
	// "/"
	if (strncmp(header0.Name.ptr, AR_MEMBER_LINKER.ptr, AR_MEMBER_LINKER.length) == 0) {
		
	} else if (strncmp(header0.Name.ptr, AR_MEMBER_SYMDEF.ptr, AR_MEMBER_LINKER.length) == 0) {
		
	}
	*/
	
	adbg_object_postload(o, AdbgObject.archive, &adbg_object_ar_unload);
	return 0;
}

void adbg_object_ar_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
	//internal_ar_t *internal = cast(internal_ar_t*)o.internal;
	
	free(o.internal);
}

/// Convert a number from a fixed character buffer to an unsigned integer.
/// Params:
///   p = Character buffer pointer. Can be null-terminated.
///   s = Size of character buffer. Or the maximum string length input.
/// Returns: 32-bit Unsigned integer value.
private
uint atouint(const(char)* p, size_t s) {
	if (p == null || s <= 0)
		return 0;
	int v; char c = void;
	for (size_t i; i < s && (c = p[i]) != 0; ++i) {
		if (c < '0' || c > '9') // Failsafe/error
			return 0;
		v = (10 * v) + (c - '0');
	}
	return v;
}
extern (D) unittest {
	enum L = 10;
	// valid
	assert(atouint("0", L) == 0);
	assert(atouint("1", L) == 1);
	assert(atouint("2", L) == 2);
	assert(atouint("86", L) == 86);
	assert(atouint("123", L) == 123);
	assert(atouint("4000", L) == 4000);
	assert(atouint("68088", L) == 68088);
	assert(atouint("4000", 2) == 40); // Test max size
	assert(atouint("2147483647", L) == int.max);
	assert(atouint("4294967295", L) == uint.max);
	// invalid
	assert(atouint("0", L) == 0);
	assert(atouint("a", L) == 0);
	assert(atouint("-1", L) == 0);
}

ar_member_header_t* adbg_object_ar_first_member(adbg_object_t *o) {
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
	internal.offset = ar_file_header_t.sizeof;
	
	// Read first member and validate it
	if (adbg_object_read_at(o, ar_file_header_t.sizeof, &internal.current, ar_member_header_t.sizeof))
		return null;
	if (internal.current.EndMarker != AR_EOL) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	
	return &internal.current;
}

// Get the next instance of the header
ar_member_header_t* adbg_object_ar_next_member(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_ar_t *internal = cast(internal_ar_t*)o.internal;
	
	uint size = adbg_object_ar_membersize(&internal.current);
	if (size <= 0) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	// Jump to next header location using the current member size
	// The alignment is needed at least for MS variants
	long newloc = adbg_alignup64(internal.offset + ar_member_header_t.sizeof + size, 2);
	
	// Read header
	if (adbg_object_read_at(o, newloc, &internal.current, ar_member_header_t.sizeof))
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

uint adbg_object_ar_membersize(ar_member_header_t *member) {
	if (member == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	return atouint(member.Size.ptr, member.Size.sizeof);
}

// TODO: adbg_object_ar_member_name
//       Names like "/75" should be entry index 76 in "//"

/// Get the resolved name of a member into a user-provided buffer.
/// 
/// The buffer will contain a null-terminated string.
/// Params:
///   buffer = Pointer to a narrow-character buffer.
///   bufsize = Size of the buffer, in characters.
///   o = Object instance.
///   member = Archive member, given by `adbg_object_ar_first_member` or `adbg_object_ar_next_member`.
/// Returns: The number of characters written, excluding the null-terminator, or -1 on error.
ptrdiff_t adbg_object_ar_member_name(char *buffer, size_t bufsize, adbg_object_t *o, ar_member_header_t *member) {
	if (buffer == null || bufsize == 0 || o == null || member == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	
	size_t allowedsz = bufsize - 1; // for null
	
	if (member.Name[0] == '/') { // special / long-name
		// TODO: Check object format
		// TODO: Check ar kind
		// coff:
		// member.Name[1] == ' ' (or '\0'?) -> table
		// member.Name[1] == '/' -> long-name table
		// isdigit( member.Name[1] ) -> long-name else special
		adbg_oops(AdbgError.unimplemented);
		return -1;
	}
	
	// Otherwise it's in the name as "example.obj/".
	// Copy until either buffer run out or '/' is met.
	ptrdiff_t i;
	for (; i < ar_member_header_t.Name.sizeof && i < allowedsz; ++i) {
		if (member.Name[i] == '/')
			break;
		buffer[i] = member.Name[i];
	}
	buffer[i] = 0;
	return i;
}

ar_member_data_t* adbg_object_ar_member_data(adbg_object_t *o, ar_member_header_t *member) {
	if (o == null || member == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_ar_t *internal = cast(internal_ar_t*)o.internal;
	
	uint size = adbg_object_ar_membersize(member);
	if (size <= 0) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	void *buffer = malloc(ar_member_data_t.sizeof + size);
	if (buffer == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	ar_member_data_t *data = cast(ar_member_data_t*)buffer;
	data.size    = size;
	data.pointer = buffer + ar_member_data_t.sizeof;
	
	long dataloc = internal.offset + size;
	if (adbg_object_read_at(o, dataloc, data.pointer, size)) {
		free(buffer);
		return null;
	}
	
	return data;
}

void adbg_object_ar_member_data_close(ar_member_data_t *data) {
	if (data) free(data);
}
