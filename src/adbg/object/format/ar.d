/// COFF Library archive format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.object.format.ar;

import adbg.utils.bit;

// Sources:
// - gdb/include/aout/ar.h
// - Microsoft Portable Executable and Common Object File Format Specification
//   Microsoft Corporation, Revision 6.0 - February 1999
//   Microsoft Corporation, Revision 8.3 - February 2013

// Format:
//   Signature
//   Header + 1st Linker Member + Data
//   Header + 2nd Linker Member + Data
//   Header + Longnames Member + Data
//   Header + obj n + Data

/// COFF archive magic.
enum AR_MAGIC = CHAR64!"!<arch>\n";
/// Thin COFF archive magic.
enum AR_THIN_MAGIC = CHAR64!"!<thin>\n";

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
	/// The two bytes in the C string: "`\n" (0x60 0x0a).
	char[2] End;
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

//
// MSCOFF import
//

/// 
struct mscoff_import_header {
	/// Must be IMAGE_FILE_MACHINE_UNKNOWN.
	ushort Sig1;
	/// Must be 0xFFFF.
	ushort Sig2;
	ushort Version;
	ushort Machine;
	uint TimeStamp;
	uint Size;
	ushort Ordinal;
	union {
		ulong Reserved;
	}
}