/// Microsoft COFF archive format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.format.mscoff;

import adbg.utils.bit;

// Format:
//   Signature
//   Header + 1st Linker Member + Data
//   Header + 2nd Linker Member + Data
//   Header + Longnames Member + Data
//   Header + obj n + Data

/// COFF archive magic.
enum MSCOFF_MAGIC = CHAR64!"!<arch>\n";

struct mscoff_member_header {
	/// Magic containing "!<arch>\n"
	char[8] Magic;
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
	/// The two bytes in the C string "\\n".
	char[2] End;
}

// 
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