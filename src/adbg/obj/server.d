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
module adbg.obj.server;

import core.stdc.stdio;
import core.stdc.config : c_long;
import adbg.error;
import adbg.disasm.disasm : AdbgDisasmPlatform, adbg_disasm_msb;
import adbg.obj.pe, adbg.obj.elf;
import adbg.utils.bit;

extern (C):

/// Executable or object format
enum AdbgObjFormat {
	/// Mysterious file format
	unknown,
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

struct adbg_object_impl_t {
//	const(char)* function(adbg_object_t*) machine;
	ubyte* function(adbg_object_t*, char* name) section;
//	object_symbol_t* function(object_t*, size_t addr) symbol;
//	object_line_t* function(object_t*, size_t addr) line;
}

/// PE meta for internal use
private struct pe_t {
	// Header
	PE_HEADER *hdr;
	union {
		PE_OPTIONAL_HEADER *opthdr;
		PE_OPTIONAL_HEADER64 *opthdr64;
		PE_OPTIONAL_HEADERROM *opthdrrom;
	}
	// Directories
	union {
		PE_IMAGE_DATA_DIRECTORY *dir;
		PE_DIRECTORY_ENTRY *dirs;
	}
	// Data
	PE_EXPORT_DESCRIPTOR *exports;
	PE_IMPORT_DESCRIPTOR *imports;
	PE_DEBUG_DIRECTORY *debugdir;
	union {
		PE_LOAD_CONFIG_DIR32 *loaddir32;
		PE_LOAD_CONFIG_DIR64 *loaddir64;
	}
	PE_SECTION_ENTRY *sections;
	// Internal
	uint offset; /// PE header file offset
}
/// ELF meta for internal use
private struct elf_t {
	union {
		Elf32_Ehdr *hdr32;
		Elf64_Ehdr *hdr64;
	}
}

struct adbg_object_t {
	//
	// File
	//
	
	union {
		void   *buf;	/// (Internal)
		char   *bufc8;	/// (Internal)
		ubyte  *bufi8;	/// (Internal)
		ushort *bufi16;	/// (Internal)
		uint   *bufi32;	/// (Internal)
		ulong  *bufi64;	/// (Internal)
	}
	/// File handle, used internally.
	FILE *file;
	/// File size.
	c_long fsize;
	
	//
	// Object data
	//
	
	/// Object translated platform target
	AdbgDisasmPlatform platform;
	/// Object format
	AdbgObjFormat format;
	
	//
	// Implementation-defined metadata
	//
	
	adbg_object_impl_t impl; /// Internal
	union {
		pe_t pe; /// PE32 meta
		elf_t elf; /// ELF meta
	}
	
//	bool is64;
}

/// Open 
int adbg_obj_open_path(adbg_object_t *obj, const(char) *path) {
	obj.file = fopen(path, "rb");

	if (obj.file == null)
		return adbg_error_system;

	return adbg_obj_open_file(obj, obj.file);
}

int adbg_obj_open_file(adbg_object_t *obj, FILE *file) {
	import core.stdc.stdlib : malloc;
	import core.stdc.string : memset;

	if (obj == null || file == null)
		return adbg_error(AdbgError.invalidArgument);

	obj.file = file;

	// File size

	if (fseek(obj.file, 0, SEEK_END))
		return adbg_error_system;
	
	obj.fsize = ftell(obj.file);
	
	if (obj.fsize < 0) // -1
		return adbg_error_system;
	if (fseek(obj.file, 0, SEEK_SET))
		return adbg_error_system;

	// Allocate

	obj.buf = malloc(obj.fsize);
	
	if (obj.buf == null)
		return adbg_error_system;
	
	// Read
	
	if (fread(obj.buf, obj.fsize, 1, obj.file) == 0)
		return adbg_error_system;
	
	// Set meta to zero (failsafe future impl.)
	
	memset(&obj.impl, 0, adbg_object_impl_t.sizeof + pe_t.sizeof);

	// Auto-detection

	file_sig_t sig = void; // for conveniance
	
	switch (obj.bufi32[0]) {
	case CHAR32!"ELF\0":
		assert(0, "todo");
	default:
	}
	
	switch (obj.bufi16[0]) {
	case CHAR16!"MZ":
		obj.pe.offset = obj.bufi32[15]; // 0x3c / 4
		
		if (obj.pe.offset < 0x40)
			return adbg_error(AdbgError.unknownObjFormat);
		if (obj.pe.offset >= obj.fsize - 4)
			return adbg_error(AdbgError.unknownObjFormat);
		
		sig.u32 = *cast(uint*)(obj.buf + obj.pe.offset);
		
		switch (sig.u16[0]) {
		case CHAR16!"PE":
			if (sig.u16[1]) // "PE\0\0"
				return adbg_error(AdbgError.unknownObjFormat);
			return adbg_obj_pe_preload(obj);
		default: //TODO: MZ
		}
		break;
	default:
	}
	
	return adbg_error(AdbgError.unknownObjFormat);
}

//TODO: Select module/PID/debuggee

//TODO: adbg_obj_unload
/*int adbg_obj_unload(obj_info_t *info) {
	
	return 0;
}*/

private:

struct file_sig_t { align(1):
	union {
		uint u32;
		char[4] c8;
		ushort[2] u16;
	}
}
