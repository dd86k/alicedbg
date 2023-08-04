/// Object server.
///
/// The goal of the object/image loader is being able to obtain information
/// from obj/pdb/image files such as:
/// - Object Type;
/// - Machine architecture;
/// - Symbols;
/// - Debugging information (types, etc.);
/// - And a few extras for dumping purposes.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.server;

import adbg.include.c.stdio;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import adbg.error;
import adbg.utils.bit;
import adbg.v2.object.formats;
import adbg.v2.disassembler.core : AdbgDasmPlatform;

extern (C):

/// Executable or object format.
enum AdbgObject {
	/// Raw binary file, or unknown object format.
	raw,
	/// Mark Zbikowski format.
	mz,
	/// New Executable format.
	ne,
	/// Linked Executable/LX format.
	le,
	/// Portable Executable format.
	pe,
	/// Executable and Linkable Format.
	elf,
	/// Mach Object format.
	macho,
	// Microsoft Program Database format.
	//pdb,
	// Microsoft Debug format.
	//dbg,
	// 
	//codeview
	// 
	//dwarf
}

enum AdbgObjectLoadOption {
	partial = 1,
}

/// Represents a file object image.
///
/// All fields are used internally and should not be used directly.
struct adbg_object_t {
	/// File handle to object.
	FILE *handle;
	/// File size.
	ulong file_size;
	
	union {
		void   *buffer;	/// Buffer to file object.
		ubyte  *buffer8;	/// Ditto
		ushort *buffer16;	/// Ditto
		uint   *buffer32;	/// Ditto
		ulong  *buffer64;	/// Ditto
	}
	/// Allocated buffer size.
	size_t buffer_size;
	/// Option: Partial loading.
	/// Warning: Rest of object must be loaded automatically before using other services.
	bool partial;
	/// 
	bool reserved;
	
	/// Loaded object type.
	AdbgObject type;

	package
	union adbg_object_internals_t {
		// Main header. All object files have some form of header.
		void *header;
		
		struct mz_t {
			mz_header *header;
			mz_relocation *relocs;
		}
		mz_t mz;
		
		struct pe_t {
			// Headers
			PE_HEADER *header;
			PE_OPTIONAL_HEADER *opt_header;
			// Directories
			PE_IMAGE_DATA_DIRECTORY *directory;
			// Data
			PE_SECTION_ENTRY *sections;
			PE_EXPORT_DESCRIPTOR *exports;
			PE_IMPORT_DESCRIPTOR *imports;
			PE_DEBUG_DIRECTORY *debug_directory;
			union {
				PE_LOAD_CONFIG_DIR32 *load_config32;
				PE_LOAD_CONFIG_DIR64 *load_config64;
			}
		}
		pe_t pe;
		
		struct macho_t {
			union {
				macho_header *header;
				macho_fatmach_header *fat_header;
			}
			macho_fat_arch *fat_arch;
			bool is64;
			bool fat;
			bool reversed;
			bool reserved;
		}
		macho_t macho;
		
		struct elf32_t {
			Elf32_Ehdr *e_header;
			Elf32_Phdr *p_header;
			Elf32_Shdr *s_header;
		}
		elf32_t elf32;
		
		struct elf64_t {
			Elf64_Ehdr *e_header;
			Elf64_Phdr *p_header;
			Elf64_Shdr *s_header;
		}
		elf64_t elf64;
	}
	/// Internal object definitions.
	adbg_object_internals_t i;
}

int adbg_object_open(adbg_object_t *obj, const(char) *path, ...) {
	if (obj == null)
		return adbg_oops(AdbgError.nullArgument);
	
	obj.handle = fopen(path, "rb");
	if (obj.handle == null)
		return adbg_oops(AdbgError.crt);
	
	va_list list = void;
	va_start(list, path);
	
	return adbg_object_loadv(obj, list);
}

void adbg_object_close(adbg_object_t *obj) {
	if (obj == null)
		return;
	if (obj.handle)
		fclose(obj.handle);
	if (obj.buffer && obj.buffer_size)
		free(obj.buffer);
}

private
int adbg_object_loadv(adbg_object_t *obj, va_list args) {
	import core.stdc.string : memset;
	
	if (obj == null || obj.handle == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	// options
	obj.partial = false;
L_ARG:
	switch (va_arg!int(args)) {
	case 0: break;
	case AdbgObjectLoadOption.partial:
		obj.partial = true;
		goto L_ARG;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	// Get file size
	if (fseek(obj.handle, 0, SEEK_END))
		return adbg_oops(AdbgError.crt);
	
	obj.file_size = ftell(obj.handle);
	
	if (obj.file_size < 0) // -1
		return adbg_oops(AdbgError.crt);
	if (fseek(obj.handle, 0, SEEK_SET))
		return adbg_oops(AdbgError.crt);
	
	// Allocate
	enum PARTIAL_SIZE = 4096;
	obj.buffer_size = obj.partial ? PARTIAL_SIZE : cast(size_t)obj.file_size;
	obj.buffer = malloc(obj.buffer_size);
	if (obj.buffer == null)
		return adbg_oops(AdbgError.crt);
	
	// Read
	if (fread(obj.buffer, obj.file_size, 1, obj.handle) == 0)
		return adbg_oops(AdbgError.crt);
	
	// zero internal stuff
	obj.i = obj.i.init;
	// Set first header
	// Also used in auto-detection
	obj.i.header = obj.buffer;
	
	// Auto-detection
	//TODO: Consider moving auto-detection as separate function?
	switch (*obj.buffer32) {
	case MAGIC_ELF:
		return adbg_object_elf_load(obj);
	case MACHO_MAGIC:	// 32-bit LE
	case MACHO_MAGIC_64:	// 64-bit LE
	case MACHO_CIGAM:	// 32-bit BE
	case MACHO_CIGAM_64:	// 64-bit BE
	case MACHO_FAT_MAGIC:	// Fat LE
	case MACHO_FAT_CIGAM:	// Fat BE
		return adbg_object_macho_load(obj);
	default:
	}
	
	switch (*obj.buffer16) {
	case MAGIC_MZ:
		if (obj.file_size < mz_header.sizeof)
			return adbg_oops(AdbgError.unknownObjFormat);
		
		uint offset = obj.i.mz.header.e_lfanew;
		
		if (offset == 0)
			return adbg_object_mz_load(obj);
		if (offset >= obj.file_size - PE_HEADER.sizeof)
			return adbg_oops(AdbgError.assertion);
		
		uint sig = *cast(uint*)(obj.buffer + offset);
		
		if (sig == MAGIC_PE32)
			return adbg_object_pe_load(obj);
		
		switch (cast(ushort)sig) {
		case CHAR16!"LE", CHAR16!"LX", CHAR16!"NE":
			return adbg_oops(AdbgError.unsupportedObjFormat);
		default: // Assume MZ?
			return adbg_object_mz_load(obj);
		}
	default:
		return adbg_oops(AdbgError.unknownObjFormat);
	}
}

//TODO: adbg_object_load_continue if partial was used
//TODO: Switch to object server's machine definition when done
//      AdbgMachine adbg_object_machine(adbg_object_t *obj)

/// Get machine type for disassembler from object.
///
/// Useful for dumping object disassembly.
/// Params: obj = Object.
/// Returns: Machine type.
AdbgDasmPlatform adbg_object_platform(adbg_object_t *obj) {
	if (obj == null || obj.handle == null)
		return AdbgDasmPlatform.native;
	
	switch (obj.type) with (AdbgObject) {
	case pe:
		switch (obj.i.pe.header.Machine) {
		case PE_MACHINE_AMD64:	return AdbgDasmPlatform.x86_64;
		case PE_MACHINE_I386:	return AdbgDasmPlatform.x86_32;
		default:
		}
		break;
	case macho:
		// NOTE: both fat and header matches
		switch (obj.i.macho.header.cputype) {
		case MACHO_CPUTYPE_X86_64:	return AdbgDasmPlatform.x86_64;
		case MACHO_CPUTYPE_I386:	return AdbgDasmPlatform.x86_32;
		default:
		}
		break;
	case elf:
		switch (obj.i.elf32.e_header.e_machine) {
		case ELF_EM_X86_64:	return AdbgDasmPlatform.x86_64;
		case ELF_EM_386:	return AdbgDasmPlatform.x86_32;
		default:
		}
		break;
	default:
	}
	
	return AdbgDasmPlatform.native;
}