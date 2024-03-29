/// New Executable format, introduced in Windows 1.0.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.format.ne;

import adbg.object.server;
import adbg.machines : AdbgMachine;
import adbg.error;
import adbg.utils.bit;
import adbg.include.c.stdlib : calloc, free;

// Got lazy mid-way

extern (C):

/// NE magic
enum NE_MAGIC = CHAR16!"NE";

// Header flags
enum : ushort {
	/// Shared automatic data segment
	NE_HFLAG_SINGLEDATA = 0x0001,
	/// Instanced automatic data segment
	NE_HFLAG_MULTIPLEDATA = 0x0002,
	/// Errors detected at link time, module will not load.
	NE_HFLAG_LINKERERROR = 0x2000,
	/// Library module.
	///
	/// The SS:SP information is invalid, CS:IP points
	/// to an initialization procedure that is called
	/// with AX equal to the module handle. This
	/// initialization procedure must perform a far
	/// return to the caller, with AX not equal to
	/// zero to indicate success, or AX equal to zero
	/// to indicate failure to initialize. DS is set
	/// to the library's data segment if the
	/// SINGLEDATA flag is set. Otherwise, DS is set
	/// to the caller's data segment.
	///
	/// A program or DLL can only contain dynamic
	/// links to executable files that have this
	/// library module flag set. One program cannot
	/// dynamic-link to another program.
	NE_HFLAG_LIBMODULE = 0x8000,
}
// Types
enum : ushort {
	/// Windows
	NE_TYPE_WINDOWS = 0x0002,
}
// Segment flags
enum : ushort {
	/// Segment-type mask.
	NE_SFLAG_TYPE_MASK = 0x0007, // 0b111
	/// Code-segment type.
	NE_SFLAG_TYPE_CODE = 0x0000,
	/// Data-segment type.
	NE_SFLAG_TYPE_DATA = 0x0001,
	/// Segment is not fixed.
	NE_SFLAG_MOVABLE = 0x0010,
	/// Segment will be preloaded; read-only if
	/// this is a data segment.
	NE_SFLAG_PRELOAD = 0x0040,
	/// Set if segment has relocation records.
	NE_SFLAG_RELOCINFO = 0x0040,
	/// Discard priority mask.
	NE_SFLAG_DISCARD = 0xf000,
}
// Relocation flags
enum : ubyte {
	/// Source mask
	NE_RFLAG_SOURCE_MASK = 0xf,
	NE_RFLAG_SOURCE_LOBYTE = 0x0,
	NE_RFLAG_SOURCE_SEGMENT = 0x2,
	NE_RFLAG_SOURCE_FAR_ADDR = 0x3,
	NE_RFLAG_SOURCE_OFFSET = 0x5,
	
	/// Target mask
	NE_RFLAG_TARGET_MASK = 0x3,
	NE_RFLAG_TARGET_INTERNALREF = 0x0,
	NE_RFLAG_TARGET_IMPORTORDINAL = 0x1,
	NE_RFLAG_TARGET_IMPORTNAME = 0x2,
	NE_RFLAG_TARGET_OSFIXUP = 0x3,
	
	NE_RFLAG_ADDITIVE = 0x4
}

// NOTE: Names from winnt.h:_IMAGE_OS2_HEADER
/// NE header
struct ne_header {
	/// Signature word.
	ushort ne_magic;
	/// Version number of the linker.
	ubyte ne_ver;
	/// Revision number of the linker.
	ubyte ne_rev;
	/// Entry Table file offset, relative to the beginning of
	/// the segmented EXE header.
	ushort ne_enttab;
	/// Number of bytes in the entry table.
	ushort ne_cbenttab;
	/// 32-bit CRC of entire contents of file.
	/// These words are taken as zero during the calculation.
	uint ne_crc;
	/// Flag word.
	ushort ne_flags;
	/// Segment number of automatic data segment.
	///
	/// This value is set to zero if SINGLEDATA and
	/// MULTIPLEDATA flag bits are clear, NOAUTODATA is
	/// indicated in the flags word.
	///
	/// A Segment number is an index into the module's segment
	/// table. The first entry in the segment table is segment
	/// number 1.
	ushort ne_autodata;
	/// Initial size, in bytes, of dynamic heap added to the
	/// data segment. This value is zero if no initial local
	/// heap is allocated.
	ushort ne_heap;
	/// Initial size, in bytes, of stack added to the data
	/// segment. This value is zero to indicate no initial
	/// stack allocation, or when SS is not equal to DS.
	ushort ne_stack;
	/// Segment number:offset of CS:IP.
	uint ne_csip;
	/// Segment number:offset of SS:SP.
	///
	/// If SS equals the automatic data segment and SP equals
	/// zero, the stack pointer is set to the top of the
	/// automatic data segment just below the additional heap
	/// area.
	//
	// +--------------------------+
	// | additional dynamic heap  |
	// +--------------------------+ <- SP
	// |    additional stack      |
	// +--------------------------+
	// | loaded auto data segment |
	// +--------------------------+ <- DS, SS
	uint ne_sssp;
	/// Number of entries in the Segment Table.
	ushort ne_cseg;
	/// Number of entries in the Module Reference Table.
	ushort ne_cmod;
	/// Number of bytes in the Non-Resident Name Table.
	ushort ne_cbnrestab;
	/// Segment Table file offset, relative to the beginning
	/// of the segmented EXE header.
	ushort ne_segtab;
	/// Resource Table file offset, relative to the beginning
	/// of the segmented EXE header.
	ushort ne_rsrctab;
	/// Resident Name Table file offset, relative to the
	/// beginning of the segmented EXE header.
	ushort ne_restab;
	/// Module Reference Table file offset, relative to the
	/// beginning of the segmented EXE header.
	ushort ne_modtab;
	/// Imported Names Table file offset, relative to the
	/// beginning of the segmented EXE header.
	ushort ne_imptab;
	/// Non-Resident Name Table offset, relative to the
	/// beginning of the file.
	uint ne_nrestab;
	/// Number of movable entries in the Entry Table.
	ushort ne_cmovent;
	/// Logical sector alignment shift count, log(base 2) of
	/// the segment sector size (default 9).
	ushort ne_align;
	/// Number of resource entries.
	ushort ne_cres;
	/// Executable type, used by loader.
	ubyte ne_exetyp;
	
	// NOTE: The old document stopped here with ubyte[8] reserved.
	//       winnt.h continue with these
	
	/// Other .EXE flags
	ubyte ne_flagsothers;
	/// Offset to retturn thunks
	ushort ne_pretthunks;
	/// Offset to segment ref. bytes
	ushort ne_psegrefbytes;
	/// Minimum code swap area size
	ushort ne_swaparea;
	/// Expected Windows version number
	ushort ne_expver;
}

/// NE segment, after header
struct ne_segment {
	/// Logical-sector offset (n byte) to the contents of the segment
	/// data, relative to the beginning of the file. Zero means no
	/// file data.
	ushort Offset;
	/// Length of the segment in the file, in bytes. Zero means 64K.
	ushort Length;
	/// Flag word.
	ushort Flags;
	/// Minimum allocation size of the segment, in bytes. Total size
	/// of the segment. Zero means 64K.
	ushort Minimum;
}

/// NE segment header in segment
struct ne_segment_data {
	ushort RelocationCount;
	ne_segment_reloc[1] Relocations;
}

struct ne_segment_reloc {
	ubyte Type;
	ubyte Flags;
	ushort Offset;
}

/// NE resource entry found in blocks
struct ne_resource_entry {
	/// File offset to the contents of the resource data,
	/// relative to beginning of file. The offset is in terms
	/// of the alignment shift count value specified at
	/// beginning of the resource table.
	ushort Offset;
	/// Length of the resource in the file (in bytes).
	ushort Length;
	/// Flag word.
	ushort Flags;
	/// Resource ID. This is an integer type if the high-order
	/// bit is set (8000h), otherwise it is the offset to the
	/// resource string, the offset is relative to the
	/// beginning of the resource table.
	ushort ResourceID;
	// DD Reserved... huh? Didn't you just say 8 bytes?
}

/// NE resource block, found in resource tables
struct ne_resource_block {
	/// Type ID. This is an integer type if the high-order bit is
	/// set (8000h); otherwise, it is an offset to the type string,
	/// the offset is relative to the beginning of the resource
	/// table. A zero type ID marks the end of the resource type
	/// information blocks.
	ushort Id;
	/// Number of resources for this type.
	ushort Count;
	uint Reserved;
	/// A table of resources for this type follows. The following is
	/// the format of each resource (8 bytes each):
	ne_resource_entry[1] Entries;
}

/// NE resource, after segments
struct ne_resource {
	/// Alignment shift count for resource data.
	ushort Alignment;
	ne_resource_block[1] Blocks;
}
/// After resource blocks
struct ne_resource_string {
	/// Length of the type or name string that follows. A zero value
        /// indicates the end of the resource type and name string, also
        /// the end of the resource table.
	ubyte Length;
	/// ASCII text of the type or name string.
	/// Note that these strings are NOT null terminated and
	/// are case sensitive.
	char[1] Text;
}

struct ne_resident {
	ubyte Length;
	char[1] Text;
	ushort Ordinal;
}

int adbg_object_ne_load(adbg_object_t *o) {
	
	o.format = AdbgObject.ne;
	
	o.i.ne.header = cast(ne_header*)o.i.mz.newbase;
	
	with (o.i.ne.header)
	if (o.p.reversed) {
		ne_enttab	= adbg_bswap16(ne_enttab);
		ne_cbenttab	= adbg_bswap16(ne_cbenttab);
		ne_crc	= adbg_bswap32(ne_crc);
		ne_flags	= adbg_bswap16(ne_flags);
		ne_autodata	= adbg_bswap16(ne_autodata);
		ne_heap	= adbg_bswap16(ne_heap);
		ne_stack	= adbg_bswap16(ne_stack);
		ne_csip	= adbg_bswap32(ne_csip);
		ne_sssp	= adbg_bswap32(ne_sssp);
		ne_cseg	= adbg_bswap16(ne_cseg);
		ne_cmod	= adbg_bswap16(ne_cmod);
		ne_cbnrestab	= adbg_bswap16(ne_cbnrestab);
		ne_segtab	= adbg_bswap16(ne_segtab);
		ne_rsrctab	= adbg_bswap16(ne_rsrctab);
		ne_restab	= adbg_bswap16(ne_restab);
		ne_modtab	= adbg_bswap16(ne_modtab);
		ne_imptab	= adbg_bswap16(ne_imptab);
		ne_nrestab	= adbg_bswap32(ne_nrestab);
		ne_cmovent	= adbg_bswap16(ne_cmovent);
		ne_align	= adbg_bswap16(ne_align);
		ne_cres	= adbg_bswap16(ne_cres);
		ne_pretthunks	= adbg_bswap16(ne_pretthunks);
		ne_psegrefbytes	= adbg_bswap16(ne_psegrefbytes);
		ne_swaparea	= adbg_bswap16(ne_swaparea);
		ne_expver	= adbg_bswap16(ne_expver);
	}
	
	return 0;
}

const(char)* adbg_object_ne_type(ubyte type) {
	switch (type) {
	case NE_TYPE_WINDOWS: return "Windows";
	default: return "Unknown";
	}
}