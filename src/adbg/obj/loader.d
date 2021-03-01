/**
 * Object/image loader.
 *
 * The goal of the object/image loader is being able to obtain information
 * from obj/pdb/image files such as:
 * - Object Type;
 * - Machine architecture;
 * - Symbols;
 * - Debugging information (types, etc.);
 * - And a few extras for dumping purposes.
 *
 * Currently, the entire file is loaded in memory out of keeping the
 * implementation simple. Future could see MMI/O usage, or a pure "disk" mode.
 *
 * License: BSD-3-Clause
 */
module adbg.obj.loader;

import core.stdc.stdio;
import adbg.error;
import adbg.disasm.disasm : AdbgDisasmPlatform, adbg_disasm_msb;
import adbg.obj.pe;

extern (C):

/*enum {	// adbg_obj_load flags
	/// Leave file in memory, used by dumper
	LOADER_MEM = 0x1000,
}*/

/*private enum {	// obj_info_t internal flags
	/// ISA is MSB
	LOADER_INTERNAL_MSB	= 0x0000_0001,
	/// Section info is loaded
	/// Internal buffer is allocated
	LOADER_INTERNAL_BUF_ALLOC	= 0x4000_0000,
	/// Structure is loaded included header
	LOADER_INTERNAL_OBJ_LOADED	= 0x8000_0000
}*/

/// Executable or object format
enum AdbgObjType {
	/// Mysterious file format
	Unknown,
	/// Mark Zbikowski format
	MZ,
	/// New Executable format
	NE,
	/// Linked Executable/LX format
	LE,
	/// Portable Executable format
	PE,
	/// Executable and Linkable Format
	ELF,
	/// Mach Object format
	MachO,
	/// Microsoft Program Database format
	PDB,
	/// Microsoft Debug format
	DBG,
}

/// Symbol entry
struct obj_symbol_t {
	size_t address;
	char *name;
	uint length;
}

/// Executable file information and headers
// NOTE: Could be renamed to obj_meta_t, but oh well
struct obj_info_t { align(1):
	//
	// File
	//

	union {
		void   *b;	/// (Internal)
		char   *bc8;	/// (Internal)
		ubyte  *bi8;	/// (Internal)
		ushort *bi16;	/// (Internal)
		uint   *bi32;	/// (Internal)
		ulong  *bi64;	/// (Internal)
	}
	/// File handle, used internally.
	FILE *handle;
	/// File size.
	uint size;

	//
	// Object data
	//

	/// File type, populated by the respective loading function.
	AdbgObjType type;
	/// Image's platform translated value for disasm
	AdbgDisasmPlatform platform;
	/// A copy of the original loading flags
	int oflags;

	union {
		PE_META pe;	/// PE32 data
	}

	//
	// Symbols handling
	//

	obj_symbol_t *symbols;	/// Symbols pointer (for internal use)
	uint symbols_count;	/// Number of symbols available

	//
	// Internals
	//

}

/// Open object from file path.
///
/// This uses fopen and adbg_obj_load to load a file from a file path.
///
/// Params:
/// 	info = Object info structure
/// 	path = File path
/// 	flags = Configuration flags
/// Returns: OS error code or a FileError on error
int adbg_obj_open(obj_info_t *info, const(char*) path, int flags) {
	info.handle = fopen(path, "rb");

	if (info.handle == null)
		return 1;

	return adbg_obj_load(info, info.handle, flags);
}

/// Load object from file handle.
///
/// This populates the obj_info_t structure provided to this function.
/// Flags are used to indicate what to load. The function is responsible of
/// allocating data depending on the requested information. The headers
/// are always loaded.
///
/// NOTICE: For the moment being, the LOADER_FILE_MEM is default. No other
/// modes have been implemented.
///
/// If you see an executable image larger than 2 GiB, do let me know.
/// Params:
/// 	file = Opened FILE
/// 	info = obj_info_t structure
/// 	flags = Load options
/// Returns: OS error code or a FileError on error
int adbg_obj_load(obj_info_t *info, FILE *file, int flags) {
	import core.stdc.config : c_long;
	import core.stdc.stdlib : malloc;

	if (file == null)
		return adbg_error(AdbgError.nullArgument);

	info.handle = file;
	info.oflags = flags;

	// File size

	if (fseek(info.handle, 0, SEEK_END))
		return adbg_error_system;
	
	info.size = cast(uint)ftell(info.handle);
	
	if (info.size == 0xFFFF_FFFF) // -1
		return adbg_error_system;
	if (fseek(info.handle, 0, SEEK_SET))
		return adbg_error_system;

	// Allocate and read

	info.b = malloc(info.size);
	
	if (info.b == null)
		return adbg_error_system;
	if (fread(info.b, info.size, 1, info.handle) == 0)
		return adbg_error_system;

	// Auto-detection

	file_sig_t sig = void; // for conveniance

	int e = void;
	switch (*info.bi16) {
	case SIG_MZ:
		uint hdrloc = *(info.bi32 + 15); // 0x3c / 4
		if (hdrloc == 0)
			return adbg_error_system;
		if (hdrloc >= info.size - 4)
			return adbg_error_system;
		sig.u32 = *cast(uint*)(info.b + hdrloc);
		switch (sig.u16[0]) {
		case SIG_PE:
			if (sig.u16[1]) // "PE\0\0"
				return adbg_error(AdbgError.unsupportedObjFormat);
			e = adbg_obj_pe_load(info, hdrloc, flags);
			break;
		default: // MZ
			return adbg_error(AdbgError.unsupportedObjFormat);
		}
		break;
	default:
		return adbg_error(AdbgError.unsupportedObjFormat);
	}

	return e;
}

//TODO: adbg_obj_unload
/*int adbg_obj_unload(obj_info_t *info) {
	
	return 0;
}*/

//TODO: adbg_obj_symbol_at_address
/*char* adbg_obj_symbol_at_address(obj_info_t *info, size_t address) {
	
	return null;
}*/

//TODO: int adbg_obj_src_line(source_t *?)
//      Return line of source code

private:

version (LittleEndian) {
	enum ushort SIG_MZ	= 0x5A4D; // "MZ"
	enum ushort SIG_PE	= 0x4550; // "PE"
	enum ushort SIG_ELF_L	= 0x4C45; // "EL", low 2-byte
	enum ushort SIG_ELF_H	= 0x7F46; // "F\x7F", high 2-byte
} else {
	enum ushort SIG_MZ	= 0x4D5A; // "MZ"
	enum ushort SIG_PE	= 0x5045; // "PE"
	enum ushort SIG_ELF_L	= 0x454C; // "EL", low 2-byte
	enum ushort SIG_ELF_H	= 0x467F; // "F\x7F", high 2-byte
}

struct file_sig_t { align(1):
	union {
		uint u32;
		char[4] c8;
		ushort[2] u16;
	}
}