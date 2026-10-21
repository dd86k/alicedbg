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
import core.stdc.string : memcmp;

extern (C):

// Used internally
enum ArVersion {
	unknown	= 0,
	gnu	= 1,
	bsd	= 2,
	coff	= 3,
}

// NOTE: Possible object formats included
//       - ELF relocatable objects (Typically POSIX platforms)
//       - COFF objects (Windows)
//       It's also used in some other applications, like packaging (APT),
//       so be careful!

// NOTE: MSVC linker can only process libraries under 4 GiB in size.

// NOTE: Format detection (taken and updated from llvm/lib/Object/Archive.cpp)
//       GNU and System V (SVR4) archive format
//         First member : "/"  (May exist, if it exists, points to the symbol table)
//         Second member: "//" (Ditto)
//         Third member : "//" (optional, string table, terminated by "/\n")
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
//         Third member : "//" (optional, string table, terminated by "\0")
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
// Maybe ARM64EC related?
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
	
	// "//" member data location, cached on first long-name lookup
	long strtab_offset;
	uint strtab_size;
	bool strtab_searched;
	
	// "/" or "/SYM64/" member data location, cached on first symbol lookup
	long symtab_offset;
	uint symtab_size;
	bool symtab_searched;
	bool symtab_wide;
}

int adbg_object_ar_load(adbg_object_t *o) {
	int e = adbg_object_impl_setup(o, AdbgObject.archive,
		internal_ar_t.sizeof,
		null);
	if (e) return e;
	
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
	
	return 0;
}
version (none)
void adbg_object_ar_unload(adbg_object_t *o) {
	
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
		if (c == ' ') // Header fields are space-padded
			break;
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
	assert(atouint("1684      ", L) == 1684);
	assert(atouint("2147483647", L) == int.max);
	assert(atouint("4294967295", L) == uint.max);
	// invalid
	assert(atouint("0", L) == 0);
	assert(atouint("a", L) == 0);
	assert(atouint("-1", L) == 0);
}

ar_member_header_t* adbg_object_ar_first_member(adbg_object_t *o) {
	internal_ar_t *ar = cast(internal_ar_t*)adbg_object_impl_get_buffer(o);
	if (ar == null) return null;
	
	// First entry starts right after signature
	ar.offset = ar_file_header_t.sizeof;
	
	// Read first member and validate it
	if (adbg_object_read_at(o, ar_file_header_t.sizeof, &ar.current, ar_member_header_t.sizeof))
		return null;
	if (ar.current.EndMarker != AR_EOL) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	
	return &ar.current;
}

// Get the next instance of the header
ar_member_header_t* adbg_object_ar_next_member(adbg_object_t *o) {
	internal_ar_t *ar = cast(internal_ar_t*)adbg_object_impl_get_buffer(o);
	if (ar == null) return null;
	
	uint size = adbg_object_ar_membersize(&ar.current);
	if (size <= 0) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	// Jump to next header location using the current member size
	// The alignment is needed at least for MS variants
	long newloc = adbg_alignup64(ar.offset + ar_member_header_t.sizeof + size, 2);
	
	// Read header
	if (adbg_object_read_at(o, newloc, &ar.current, ar_member_header_t.sizeof))
		return null;
	
	// 
	if (ar.current.EndMarker != AR_EOL) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	// All good, set as current, and return member
	ar.offset = newloc;
	return &ar.current;
}

uint adbg_object_ar_membersize(ar_member_header_t *member) {
	if (member == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	return atouint(member.Size.ptr, member.Size.sizeof);
}

// Cached tables are trusted afterwards, so reject sizes that run past EOF
private
bool ar_member_fits(adbg_object_t *o, long dataloc, uint size) {
	long filesize = adbg_object_filesize(o);
	return filesize >= 0 && dataloc + size <= filesize;
}

// Locate the "//" member. It always precedes regular members, so stop at the
// first one to avoid walking archives that have no string table.
private
int adbg_object_ar_find_strtab(adbg_object_t *o, internal_ar_t *ar) {
	if (ar.strtab_searched)
		return ar.strtab_size ? 0 : adbg_oops(AdbgError.objectMalformed);
	ar.strtab_searched = true;
	
	ar_member_header_t header = void;
	long loc = ar_file_header_t.sizeof;
	for (;;) {
		if (adbg_object_read_at(o, loc, &header, ar_member_header_t.sizeof))
			return adbg_error_code();
		if (header.EndMarker != AR_EOL || header.Name[0] != '/')
			return adbg_oops(AdbgError.objectMalformed);
		
		uint size = adbg_object_ar_membersize(&header);
		if (header.Name == AR_MEMBER_LONGNAMES) {
			if (size == 0 || ar_member_fits(o, loc + ar_member_header_t.sizeof, size) == false)
				return adbg_oops(AdbgError.objectMalformed);
			ar.strtab_offset = loc + ar_member_header_t.sizeof;
			ar.strtab_size   = size;
			return 0;
		}
		
		loc = adbg_alignup64(loc + ar_member_header_t.sizeof + size, 2);
	}
}

/// Get the resolved name of a member into a user-provided buffer.
/// 
/// The buffer will contain a null-terminated string. Special members
/// ("/", "//", "/SYM64/", etc.) are returned as-is.
/// Params:
///   buffer = Pointer to a narrow-character buffer.
///   bufsize = Size of the buffer, in characters.
///   o = Object instance.
///   member = Current archive member, given by `adbg_object_ar_first_member` or `adbg_object_ar_next_member`.
/// Returns: The number of characters written, excluding the null-terminator, or -1 on error.
ptrdiff_t adbg_object_ar_member_name(char *buffer, size_t bufsize, adbg_object_t *o, ar_member_header_t *member) {
	if (buffer == null || bufsize == 0 || o == null || member == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	internal_ar_t *ar = cast(internal_ar_t*)adbg_object_impl_get_buffer(o);
	if (ar == null) return -1;
	
	size_t allowedsz = bufsize - 1; // for null
	ptrdiff_t i;
	
	// GNU/COFF long name: "/<offset>" into the "//" member, where entries
	// end with "/\n" (GNU) or "\0" (COFF).
	if (member.Name[0] == '/' && member.Name[1] >= '0' && member.Name[1] <= '9') {
		if (adbg_object_ar_find_strtab(o, ar))
			return -1;
		uint noffset = atouint(member.Name.ptr + 1, member.Name.sizeof - 1);
		if (noffset >= ar.strtab_size) {
			adbg_oops(AdbgError.objectMalformed);
			return -1;
		}
		size_t rdsize = ar.strtab_size - noffset;
		if (rdsize > allowedsz) rdsize = allowedsz;
		if (rdsize && adbg_object_read_at(o, ar.strtab_offset + noffset, buffer, rdsize))
			return -1;
		for (; i < rdsize && buffer[i] != 0 && buffer[i] != '\n'; ++i) {}
		if (i && buffer[i - 1] == '/' && i < rdsize && buffer[i] == '\n')
			--i;
		buffer[i] = 0;
		return i;
	}
	
	// BSD long name: "#1/<length>", name follows the header.
	if (member.Name[0..3] == "#1/") {
		uint nlen = atouint(member.Name.ptr + 3, member.Name.sizeof - 3);
		if (nlen == 0 || nlen > adbg_object_ar_membersize(member)) {
			adbg_oops(AdbgError.objectMalformed);
			return -1;
		}
		size_t rdsize = nlen > allowedsz ? allowedsz : nlen;
		if (rdsize && adbg_object_read_at(o, ar.offset + ar_member_header_t.sizeof, buffer, rdsize))
			return -1;
		for (; i < rdsize && buffer[i] != 0; ++i) {} // may be null-padded
		buffer[i] = 0;
		return i;
	}
	
	// Short names are space-padded, GNU/COFF append a '/' terminator.
	// Special members keep their slashes.
	bool special = member.Name[0] == '/';
	for (; i < ar_member_header_t.Name.sizeof && i < allowedsz; ++i) {
		char c = member.Name[i];
		if (c == ' ' || (c == '/' && special == false))
			break;
		buffer[i] = c;
	}
	buffer[i] = 0;
	return i;
}

/// Check if the member is an archive table (symbol index, string table, etc.)
/// rather than a stored file.
/// Params:
///   o = Object instance.
///   member = Current archive member, needed to read BSD long names.
/// Returns: True if special.
bool adbg_object_ar_member_is_special(adbg_object_t *o, ar_member_header_t *member) {
	if (member == null)
		return false;
	
	// "/<offset>" is a GNU/COFF long file name, other "/" names are tables
	if (member.Name[0] == '/')
		return member.Name[1] < '0' || member.Name[1] > '9';
	
	if (member.Name == AR_MEMBER_SYMDEF || member.Name == AR_MEMBER_SYMDEF64 ||
		member.Name == AR_MEMBER_SYMDEF_SORTED)
		return true;
	
	// Darwin stores its symbol tables as BSD long names
	if (member.Name[0..3] == "#1/") {
		char[24] name = void;
		ptrdiff_t len = adbg_object_ar_member_name(name.ptr, name.sizeof, o, member);
		if (len < 0)
			return false;
		const(char)[] s = name[0..len];
		return s == "__.SYMDEF" || s == "__.SYMDEF_64" ||
			s == "__.SYMDEF SORTED" || s == "__.SYMDEF_64 SORTED";
	}
	
	return false;
}

ar_member_data_t* adbg_object_ar_member_data(adbg_object_t *o, ar_member_header_t *member) {
	internal_ar_t *ar = cast(internal_ar_t*)adbg_object_impl_get_buffer(o);
	if (ar == null) return null;
	
	uint size = adbg_object_ar_membersize(member);
	long dataloc = ar.offset + ar_member_header_t.sizeof;
	
	// BSD long names are stored inline, before the data
	if (member.Name[0..3] == "#1/") {
		uint nlen = atouint(member.Name.ptr + 3, member.Name.sizeof - 3);
		if (nlen > size) {
			adbg_oops(AdbgError.objectMalformed);
			return null;
		}
		dataloc += nlen;
		size    -= nlen;
	}
	if (size == 0) {
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
	if (adbg_object_read_at(o, dataloc, data.pointer, size)) {
		free(buffer);
		return null;
	}
	
	return data;
}

void adbg_object_ar_member_data_close(ar_member_data_t *data) {
	if (data) free(data);
}

// Read-ahead buffer so walking the index costs a handful of reads
private struct ar_window_t {
	long pos;
	size_t len;
	ubyte[512] data;
}

/// Iterator over the archive symbol index.
struct ar_symbol_iter_t {
	adbg_object_t *object;
	ulong count;
	ulong index;
	long offsets;	// file offset of the member offset array
	long strings;	// file offset of the next name
	long end;	// end of the symbol index member data
	bool wide;
	ar_member_symbol_t current;
	ar_window_t offwin;
	ar_window_t strwin;
}

/// 
struct ar_member_symbol_t {
	/// File offset of the member header defining this symbol, see `adbg_object_ar_member_at`.
	long member_offset;
	/// Name length, can exceed the buffer size given to `adbg_object_ar_symbol_next`.
	size_t name_length;
}

private
ubyte* ar_window_get(adbg_object_t *o, ar_window_t *w, long loc, size_t size, long end) {
	if (loc >= w.pos && loc + size <= w.pos + w.len)
		return w.data.ptr + (loc - w.pos);
	if (loc + size > end) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	size_t rdsize = cast(size_t)(end - loc);
	if (rdsize > w.data.sizeof) rdsize = w.data.sizeof;
	if (adbg_object_read_at(o, loc, w.data.ptr, rdsize))
		return null;
	w.pos = loc;
	w.len = rdsize;
	return w.data.ptr;
}

// The GNU "/" (or "/SYM64/") and the first COFF linker member share a layout:
// a big-endian count, as many big-endian member offsets, then null-terminated
// names. The second COFF linker member is ignored since the first suffices.
private
int adbg_object_ar_find_symtab(adbg_object_t *o, internal_ar_t *ar) {
	if (ar.symtab_searched)
		return ar.symtab_size ? 0 : adbg_oops(AdbgError.objectItemNotFound);
	ar.symtab_searched = true;
	
	ar_member_header_t header = void;
	long loc = ar_file_header_t.sizeof;
	if (adbg_object_read_at(o, loc, &header, ar_member_header_t.sizeof))
		return adbg_error_code();
	if (header.EndMarker != AR_EOL)
		return adbg_oops(AdbgError.objectMalformed);
	
	bool wide = header.Name == AR_MEMBER_SYM64;
	if (header.Name != AR_MEMBER_LINKER && wide == false)
		return adbg_oops(AdbgError.objectItemNotFound); // incl. BSD __.SYMDEF
	
	uint size = adbg_object_ar_membersize(&header);
	if (size < (wide ? ulong.sizeof : uint.sizeof) ||
		ar_member_fits(o, loc + ar_member_header_t.sizeof, size) == false)
		return adbg_oops(AdbgError.objectMalformed);
	
	ar.symtab_offset = loc + ar_member_header_t.sizeof;
	ar.symtab_size   = size;
	ar.symtab_wide   = wide;
	return 0;
}

/// Open an iterator over the archive symbol index.
///
/// Entries are read on demand.
/// Params: o = Object instance.
/// Returns: Iterator, or null on error.
ar_symbol_iter_t* adbg_object_ar_symbol_open(adbg_object_t *o) {
	internal_ar_t *ar = cast(internal_ar_t*)adbg_object_impl_get_buffer(o);
	if (ar == null) return null;
	if (adbg_object_ar_find_symtab(o, ar))
		return null;
	
	ulong count = void;
	size_t width = ar.symtab_wide ? ulong.sizeof : uint.sizeof;
	if (ar.symtab_wide) {
		if (adbg_object_read_at(o, ar.symtab_offset, &count, ulong.sizeof))
			return null;
		version (LittleEndian) count = adbg_bswap64(count);
	} else {
		uint count32 = void;
		if (adbg_object_read_at(o, ar.symtab_offset, &count32, uint.sizeof))
			return null;
		version (LittleEndian) count32 = adbg_bswap32(count32);
		count = count32;
	}
	if (count > (ar.symtab_size - width) / width) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	
	ar_symbol_iter_t *it = cast(ar_symbol_iter_t*)calloc(1, ar_symbol_iter_t.sizeof);
	if (it == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	it.object  = o;
	it.count   = count;
	it.wide    = ar.symtab_wide;
	it.offsets = ar.symtab_offset + width;
	it.strings = it.offsets + (count * width);
	it.end     = ar.symtab_offset + ar.symtab_size;
	return it;
}

/// Get the next symbol from the index.
///
/// The name is null-terminated and truncated to fit the buffer.
/// Params:
///   it = Iterator.
///   buffer = Name buffer.
///   bufsize = Size of the name buffer, in characters.
/// Returns: Symbol entry, or null at the end of the index or on error.
ar_member_symbol_t* adbg_object_ar_symbol_next(ar_symbol_iter_t *it, char *buffer, size_t bufsize) {
	if (it == null || buffer == null || bufsize == 0) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (it.index >= it.count)
		return null;
	
	adbg_object_t *o = it.object;
	size_t width = it.wide ? ulong.sizeof : uint.sizeof;
	ubyte *p = ar_window_get(o, &it.offwin, it.offsets + (it.index * width), width, it.strings);
	if (p == null)
		return null;
	version (LittleEndian)
		it.current.member_offset = it.wide ?
			cast(long)adbg_bswap64(*cast(ulong*)p) : adbg_bswap32(*cast(uint*)p);
	else
		it.current.member_offset = it.wide ? cast(long)*cast(ulong*)p : *cast(uint*)p;
	
	size_t allowedsz = bufsize - 1; // for null
	size_t len;
	for (;;) {
		char *c = cast(char*)ar_window_get(o, &it.strwin, it.strings + len, 1, it.end);
		if (c == null)
			return null;
		if (*c == 0)
			break;
		if (len < allowedsz)
			buffer[len] = *c;
		++len;
	}
	buffer[len < allowedsz ? len : allowedsz] = 0;
	
	it.strings += len + 1;
	it.current.name_length = len;
	++it.index;
	return &it.current;
}

void adbg_object_ar_symbol_close(ar_symbol_iter_t *it) {
	if (it) free(it);
}

/// Read the member header at a file offset, typically from a symbol entry.
///
/// This becomes the current member, so member iteration continues from it.
/// Params:
///   o = Object instance.
///   offset = File offset of the member header.
/// Returns: Member header, or null on error.
ar_member_header_t* adbg_object_ar_member_at(adbg_object_t *o, long offset) {
	internal_ar_t *ar = cast(internal_ar_t*)adbg_object_impl_get_buffer(o);
	if (ar == null) return null;
	
	if (offset < ar_file_header_t.sizeof) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	ar_member_header_t header = void;
	if (adbg_object_read_at(o, offset, &header, ar_member_header_t.sizeof))
		return null;
	if (header.EndMarker != AR_EOL) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	
	ar.current = header;
	ar.offset  = offset;
	return &ar.current;
}
