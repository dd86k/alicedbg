/**
 * Object server.
 *
 * The goal of the object/image loader is being able to obtain information
 * from obj/pdb/image files such as:
 * - Object Type;
 * - Machine architecture;
 * - Symbols;
 * - Debugging information (types, etc.);
 * - And a few extras for dumping purposes.
 *
 * Files are first loaded entirely in memory. Then internal pointers are set
 * depending on the format.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.obj.server;

import core.stdc.stdio;
import core.stdc.config : c_long;
import adbg.error;
import adbg.disasm.disasm : AdbgPlatform;
import adbg.obj.mz, adbg.obj.pe, adbg.obj.elf;
import adbg.utils.bit : CHAR16, CHAR32;

//TODO: adbg_obj_is64bit
//TODO: adbg_obj_ismsb

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

/// (Internal) Function pointers the implementation needs to fill.
struct adbg_object_impl_t {
//	extern (C) const(char)* function(adbg_object_t*) machine;
	/// Get data pointer from section name
	extern (C) ubyte* function(adbg_object_t*, char* name) section;
//	extern (C) object_symbol_t* function(object_t*, size_t addr) symbol;
//	extern (C) object_line_t* function(object_t*, size_t addr) line;
}

/// (Internal) MZ meta structure
private struct mz_t {
	mz_hdr *hdr;
	mz_reloc *relocs;
}
/// (Internal) PE meta structure
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
/// (Internal) ELF meta structure
private struct elf_t {
	union {
		Elf32_Ehdr *hdr32;
		Elf64_Ehdr *hdr64;
	}
	union {
		Elf32_Phdr *phdr32;
		Elf64_Phdr *phdr64;
	}
	union {
		Elf32_Shdr *shdr32;
		Elf64_Shdr *shdr64;
	}
}

private enum IMPL_SIZE = adbg_object_impl_t.sizeof;
private enum META_SIZE = pe_t.sizeof;

/// Represents an object file or module.
struct adbg_object_t {
	//
	// Object data
	//
	
	/// Object translated platform target
	AdbgPlatform platform;
	/// Object format
	AdbgObjFormat format;
	
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
	// Implementation-defined metadata
	//
	
	adbg_object_impl_t impl; /// Internal
	union {
		mz_t mz;	/// MZ meta
		pe_t pe;	/// PE32 meta
		elf_t elf;	/// ELF meta
	}
}

/// Load an object file using its path.
/// Params:
/// 	obj = Object structure
/// 	path = File path
/// Returns: Status code
int adbg_obj_open_path(adbg_object_t *obj, const(char) *path) {
	obj.file = fopen(path, "rb");
	
	if (obj.file == null)
		return adbg_oops(AdbgError.os);
	
	return adbg_obj_open_file(obj, obj.file);
}

/// Load an objet file using a FILE structure.
/// Params:
/// 	obj = Object structure
/// 	file = FILE structure
/// Returns: Status code
int adbg_obj_open_file(adbg_object_t *obj, FILE *file) {
	import core.stdc.stdlib : malloc;
	import core.stdc.string : memset;
	
	if (obj == null || file == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	obj.file = file;
	
	// File size
	
	if (fseek(obj.file, 0, SEEK_END))
		return adbg_oops(AdbgError.os);
	
	obj.fsize = ftell(obj.file);
	
	if (obj.fsize < 0) // -1
		return adbg_oops(AdbgError.os);
	if (fseek(obj.file, 0, SEEK_SET))
		return adbg_oops(AdbgError.os);
	
	// Allocate
	
	obj.buf = malloc(obj.fsize);
	
	if (obj.buf == null)
		return adbg_oops(AdbgError.os);
	
	// Read
	
	if (fread(obj.buf, obj.fsize, 1, obj.file) == 0)
		return adbg_oops(AdbgError.os);
	
	// Set meta to zero (failsafe for future implementations)
	
	memset(&obj.impl, 0, IMPL_SIZE + META_SIZE);
	
	// Auto-detection
	
	file_sig_t sig = void; // for conveniance
	
	switch (obj.bufi32[0]) {
	case CHAR32!"\x7FELF":
		return adbg_obj_elf_preload(obj);
	default:
	}
	
	switch (obj.bufi16[0]) {
	case CHAR16!"MZ":
		if (obj.fsize < mz_hdr.sizeof)
			return adbg_oops(AdbgError.unknownObjFormat);
		
		obj.pe.offset = obj.bufi32[15]; // 0x3c / 4
		
		if (obj.pe.offset)
		if (obj.pe.offset >= obj.fsize - PE_HEADER.sizeof)
			return adbg_oops(AdbgError.unknownObjFormat);
		
		sig.u32 = *cast(uint*)(obj.buf + obj.pe.offset);
		
		switch (sig.u16[0]) {
		case CHAR16!"PE":
			if (sig.u16[1]) // "PE\0\0"
				return adbg_oops(AdbgError.unknownObjFormat);
			return adbg_obj_pe_preload(obj);
		case CHAR16!"LE", CHAR16!"LX", CHAR16!"NE":
			return adbg_oops(AdbgError.unsupportedObjFormat);
		default: // Assume MZ
			return adbg_obj_mz_preload(obj);
		}
	default:
		return adbg_oops(AdbgError.unknownObjFormat);
	}
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
