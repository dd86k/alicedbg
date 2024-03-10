/// Linear Executable object format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.object.format.lx;

// NOTE: LX is mainly 16-bit only and LE mixed 16/32-bit

import adbg.error;
import adbg.object.server : adbg_object_t, AdbgObject;
import adbg.object.machines;
import adbg.utils.bit;

extern (C):

/// LX magic for OS/2 binaries.
enum LX_MAGIC = CHAR16!"LX";
/// LE magic for Windows binaries.
enum LE_MAGIC = CHAR16!"LE";

enum : ushort {
	/// 80286 or better
	LX_CPU_80286	= 0x0001,
	/// 80386 or better
	LX_CPU_80386	= 0x0002,
	/// 80486 or better
	LX_CPU_80486	= 0x0003,
	
	/// OS/2
	LX_OS_OS2	= 0x0001,
	/// Windows
	LX_OS_WIN	= 0x0002,
	/// DOS 4.x
	LX_OS_DOS4	= 0x0003,
	/// Windows 386
	LX_OS_WINS386	= 0x0004,
}
enum : uint {
	/// Per-Process Library Initialization
	LX_FLAG_PROCLIBINIT	= 0x00000004,
	/// Internal fixups for the module have been applied.
	LX_FLAG_INTFIXUPS	= 0x00000010,
	/// External fixups for the module have been applied.
	LX_FLAG_EXTFIXUPS	= 0x00000020,
	/// Incompatible with PM windowing.
	LX_FLAG_INCOMPATPMWIN	= 0x00000100,
	/// Compatible with PM windowing.
	LX_FLAG_COMPATPMWIN	= 0x00000200,
	/// Uses PM windowing API.
	LX_FLAG_USESPMWIN	= 0x00000300, // Mask
	/// Module is not loadable.
	LX_FLAG_MODUNLOADABLE	= 0x00002000,
	/// Per-process Library Termination.
	LX_FLAG_PROCLIBTERM	= 0x40000000,
	
	/// Module type mask.
	LX_FLAG_MODTYPE_MASK	= 0x00038000,
	/// Program module.
	LX_FLAG_MODTYPE_PROG	= 0x00000000,
	/// Library module.
	LX_FLAG_MODTYPE_LIB	= 0x00008000,
	/// Protected Memory Library module.
	LX_FLAG_MODTYPE_PROTLIB	= 0x00018000,
	/// Physical Device Driver module.
	LX_FLAG_MODTYPE_PHYSDEV	= 0x00020000,
	/// Virtual Device Driver module (static).
	LX_FLAG_MODTYPE_VIRTDEV	= 0x00028000,
	/// Virtual Device Driver module (dynamic).
	LX_FLAG_MODTYPE_VXDDYN	= 0x00038000,
}

private enum E32RESBYTES3 = 196 - 176; // lx_header.sizeof

// winnt.h:_IMAGE_VXD_HEADER
/// LX/LE header
struct lx_header { // NOTE: Names are taken from spec except for its "e32_exe" name
	/// Header magic. "LX" or "LE"
	ushort magic;
	/// Byte Ordering.
	///
	/// 0 for little-endian, 1 for big-endian.
	ubyte border;
	/// Word Ordering.
	///
	/// 0 for little-endian, 1 for big-endian.
	ubyte worder;
	/// Linear EXE Format Level.
	///
	/// The  Linear EXE Format Level is set  to  0  for  the
	/// initial version  of  the 32-bit linear  EXE  format.
	/// Each  incompatible  change to the  linear EXE format
	/// must increment this value.  This  allows the  system
	/// to recognized future EXE file versions  so  that  an
	/// appropriate  error message  may  be displayed  if an
	/// attempt is made to load them.
	uint level;
	/// Module CPU Type.
	///
	/// 1=i286 and later, 2=i386 and later, 3=i486 and later
	ushort cpu;
	/// Module OS Type.
	ushort os;
	/// Version of the linear EXE module.
	uint ver;
	/// Flag bits for the module.
	uint mflags;
	/// Number of pages in module.
	uint mpages;
	/// The Object number to which the Entry Address is relative.
	uint startobj;
	/// Entry Address of module.
	uint eip;
	/// Starting stack address of module.
	uint stackobj;
	/// The size of one page for this system.
	uint esp;
	/// Module page size.
	uint pagesize;
	union {
		/// Size of last page. (LE)
		uint lastpage;
		/// The shift left bits for page offsets. (LX)
		uint pageshift;
	}
	/// Total size of the fixup information in bytes.
	uint fixupsize;
	/// Checksum for fixup information.
	uint fixupsum;
	/// Size of memory resident tables.
	uint ldrsize;
	/// Checksum for loader section.
	uint ldrsum;
	/// Object Table offset.
	uint objtab;
	/// Object Table Count.
	uint objcnt;
	/// Object Page Table offset.
	uint objmap;
	/// Object Iterated Pages offset.
	uint itermap;
	/// Resource Table offset.
	uint rsrctab;
	/// Number of entries in Resource Table.
	uint rsrccnt;
	/// Resident Name Table offset.
	uint restab;
	/// Entry Table offset.
	uint enttab;
	/// Module Format Directives Table offset.
	uint dirtab;
	/// Number of Module Format Directives in the Table.
	uint dircnt;
	/// Fixup Page Table offset.
	uint fpagetab;
	/// Fixup Record Table Offset
	uint frectab;
	/// Import Module Name Table offset.
	uint impmod;
	/// The number of entries in the Import Module Name Table.
	uint impmodcnt;
	/// Import Procedure Name Table offset.
	uint impproc;
	/// Per-Page Checksum Table offset.
	uint pagesum;
	/// Data Pages Offset.
	uint datapage;
	/// Number of Preload pages for this module.
	uint preload;
	/// Non-Resident Name Table offset.
	uint nrestab;
	/// Number of bytes in the Non-resident name table.
	uint cbnrestab;
	/// Non-Resident Name Table Checksum.
	uint nressum;
	/// The Auto Data Segment Object number.
	uint autodata;
	/// Debug Information offset.
	uint debuginfo;
	/// Debug Information length;
	uint debuglen;
	/// Instance pages in preload section.
	uint instpreload;
	/// Instance pages in demand section.
	uint instdemand;
	/// Heap size added to the Auto DS Object.
	uint heapsize;
	
	// NOTE: winnt.h defines
	//       - BYTE   e32_res3[12];
	//       - DWORD  e32_winresoff;
	//       - DWORD  e32_winreslen;
	//       - WORD   e32_devid;
	//       - WORD   e32_ddkver;
	
	/// Size of requested stack.
	uint stacksize;
	union {
		/// Pad structure to 196 bytes
		ubyte[E32RESBYTES3] res;
		struct { // LE specifics
			ubyte[8] res1;
			uint winresoff;	/// Windows VxD version info resource offset
			uint winreslen;	/// Windows VxD version info resource lenght
			ushort device_id;	/// Windows VxD device ID
			ushort ddk_version;	/// Windows VxD DDK version (usually 0x030A)
		}
	}
}

struct lx_record {
	uint size;	/// Object virtual size
	uint addr;	/// Base virtual address
	uint flags;
	uint mapidx;	/// Page map index
	uint mapsize;	/// Count of entries in page map
	uint reserved;
}

// Record flags
enum {
	LX_OBJ_READABLE        = 0x0001,
	LX_OBJ_WRITEABLE       = 0x0002,
	LX_OBJ_EXECUTABLE      = 0x0004,
	LX_OBJ_RESOURCE        = 0x0008,
	LX_OBJ_DISCARDABLE     = 0x0010,
	LX_OBJ_SHARABLE        = 0x0020,
	LX_OBJ_HAS_PRELOAD     = 0x0040,
	LX_OBJ_HAS_INVALID     = 0x0080,
	LX_OBJ_PERM_SWAPPABLE  = 0x0100,  /* LE */
	LX_OBJ_HAS_ZERO_FILL   = 0x0100,  /* LX */
	LX_OBJ_PERM_RESIDENT   = 0x0200,
	LX_OBJ_PERM_CONTIGUOUS = 0x0300,  /* LX */
	LX_OBJ_PERM_LOCKABLE   = 0x0400,
	LX_OBJ_ALIAS_REQUIRED  = 0x1000,
	LX_OBJ_BIG             = 0x2000,
	LX_OBJ_CONFORMING      = 0x4000,
	LX_OBJ_IOPL            = 0x8000,
}

struct lx_le_map_entry {  /* LE */
	ubyte[3] page_num;    /* 24-bit page number in .exe file */
	ubyte    flags;
}

struct lx_lx_map_entry { /* LX */
	/// Offset from Preload page start
	/// shifted by page_shift in hdr
	uint   page_offset;
	/// Size of entry in bytes.
	ushort data_size;
	ushort flags;
}

union lx_map_entry {
	lx_le_map_entry    le;
	lx_lx_map_entry    lx;
}

// Page entries
enum {
	PAGE_VALID      = 0,
	PAGE_ITERATED   = 1,
	PAGE_INVALID    = 2,
	PAGE_ZEROED     = 3,
	PAGE_RANGE      = 4,
}

struct lx_flat_bundle_prefix {
    ubyte  b32_cnt;
    ubyte  b32_type;
    ushort b32_obj;
}

struct flat_null_prefix {
    ubyte b32_cnt;
    ubyte b32_type;
}

/* values for the b32_type field */
alias bundle_types = int;
enum {
    FLT_BNDL_EMPTY  = 0,
    FLT_BNDL_ENTRY16,
    FLT_BNDL_GATE16,
    FLT_BNDL_ENTRY32,
    FLT_BNDL_ENTRYFWD
}

struct lx_flat_bundle_entry32 {
    ubyte e32_flags;      /* flag bits are same as in OS/2 1.x */
    uint  e32_offset;
}

struct lx_flat_bundle_gate16 {
    ubyte  e32_flags;      /* flag bits are same as in OS/2 1.x */
    ushort offset;
    ushort callgate;
}

/*
 * other, unused bundle types are:
 */

struct lx_flat_bundle_entry16 {
    ubyte  e32_flags;      /* flag bits are same as in OS/2 1.x */
    ushort e32_offset;
}

struct lx_flat_bundle_entryfwd {
    ubyte  e32_flags;      /* flag bits are same as in OS/2 1.x */
    ushort modord;
    uint   value;
}

struct lx_flat_res_table {
    ushort type_id;
    ushort name_id;
    uint   res_size;
    ushort object;
    uint   offset;
}

/* fixup record source flags */
enum {
	LX_OSF_SOURCE_MASK             = 0x0F,
	LX_OSF_SOURCE_BYTE             = 0x00,
	LX_OSF_SOURCE_UNDEFINED        = 0x01,
	LX_OSF_SOURCE_SEG              = 0x02,
	LX_OSF_SOURCE_PTR_32           = 0x03,
	LX_OSF_SOURCE_OFF_16           = 0x05,
	LX_OSF_SOURCE_PTR_48           = 0x06,
	LX_OSF_SOURCE_OFF_32           = 0x07,
	LX_OSF_SOURCE_OFF_32_REL       = 0x08,
	LX_OSF_SFLAG_FIXUP_TO_ALIAS    = 0x10,
	LX_OSF_SFLAG_LIST              = 0x20,
}

/* fixup record target flags */
enum {
	LX_OSF_TARGET_MASK             = 0x03,
	LX_OSF_TARGET_INTERNAL         = 0x00,
	LX_OSF_TARGET_EXT_ORD          = 0x01,
	LX_OSF_TARGET_EXT_NAME         = 0x02,
	LX_OSF_TARGET_INT_VIA_ENTRY    = 0x03,
	LX_OSF_TFLAG_ADDITIVE_VAL      = 0x04,
	LX_OSF_TFLAG_INT_CHAIN         = 0x08,
	LX_OSF_TFLAG_OFF_32BIT         = 0x10,
	LX_OSF_TFLAG_ADD_32BIT         = 0x20,
	LX_OSF_TFLAG_OBJ_MOD_16BIT     = 0x40,
	LX_OSF_TFLAG_ORDINAL_8BIT      = 0x80,
}

int adbg_object_lx_load(adbg_object_t *o) {
	
	o.format = AdbgObject.lx;
	o.i.lx.header = cast(lx_header*)o.i.mz.newbase;
	
	//TODO: Deal with word order
	
	return 0;
}

const(char)* adbg_object_lx_cputype_string(ushort cpu) {
	switch (cpu) {
	case LX_CPU_80286:	return "80286";
	case LX_CPU_80386:	return "80386";
	case LX_CPU_80486:	return "80486";
	default:	return "Unknown";
	}
}

const(char)* adbg_object_lx_ostype_string(ushort os) {
	switch (os) {
	case LX_OS_OS2:	return "OS/2";
	case LX_OS_WIN:	return "Windows";
	case LX_OS_DOS4:	return "DOS 4.x";
	case LX_OS_WINS386:	return "Windows 386";
	default:	return "Unknown";
	}
}

const(char)* adbg_object_lx_modtype_string(uint flags) {
	switch (flags & LX_FLAG_MODTYPE_MASK) { // 17:15
	case LX_FLAG_MODTYPE_PROG:	return "Program";
	case LX_FLAG_MODTYPE_LIB:	return "Library";
	case LX_FLAG_MODTYPE_PROTLIB:	return "Protected Memory Library";
	case LX_FLAG_MODTYPE_PHYSDEV:	return "Physical Device Driver";
	case LX_FLAG_MODTYPE_VIRTDEV:	return "Static Virtual Device Driver";
	case LX_FLAG_MODTYPE_VXDDYN:	return "Dynamic Virtual Device Driver (VxD)";
	default:	return "Unkown";
	}
}
