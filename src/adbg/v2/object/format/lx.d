/// Linear Executable object format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.format.lx;

import adbg.error;
import adbg.v2.object.server : adbg_object_t, AdbgObject;
import adbg.v2.object.machines;
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
	/// Virtual Device Driver module.
	LX_FLAG_MODTYPE_VIRTDEV	= 0x00028000,
}

private enum E32RESBYTES3 = 196 - 176; // lx_header.sizeof
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
	/// The shift left bits for page offsets.
	uint pageshift;
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
	/// Size of requested stack.
	uint stacksize;
	/// Pad structure to 196 bytes
	ubyte[E32RESBYTES3] res3;
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
	case LX_FLAG_MODTYPE_VIRTDEV:	return "Virtual Device Driver";
	default:	return "Unkown";
	}
}
