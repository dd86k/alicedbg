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
import adbg.v2.object.machines : AdbgMachine;

extern (C):

//TODO: Function to check and/or fetch stuff from object
//      Check bounds at minimum
//TODO: Object type and format enums
//      Either:
//      - extent formats to include everyting else, have functions to say type (_is_dump)
//      - keep format and add a "type/purpose" enum (exec/dump/symbols/etc.)
//      - do type as first-class and format second
//TODO: Consider loading only 4K for detection

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
	FILE *file_handle;
	/// File size.
	ulong file_size;
	
	union {
		void   *buffer;	/// Buffer to file object.
		char   *bufferc;	/// Ditto
		wchar  *bufferw;	/// Ditto
		dchar  *bufferd;	/// Ditto
		ubyte  *buffer8;	/// Ditto
		ushort *buffer16;	/// Ditto
		uint   *buffer32;	/// Ditto
		ulong  *buffer64;	/// Ditto
	}
	/// Allocated buffer size.
	size_t buffer_size;
	
	/// Loaded object format.
	AdbgObject format;
	
	package
	struct adbg_object_properties_t {
		/// Target endianness is reversed and therefore fields needs
		/// to be byte-swapped.
		bool reversed;
		// Target object has code that can be run on this platform.
		// Examples: x86 on x86-64 or Arm A32 on Arm A64 via WoW64
		//TODO: bool platform_native;
	}
	adbg_object_properties_t p;
	
	package
	struct adbg_object_options_t {
		/// Option: Partial loading.
		/// Warning: Rest of object must be loaded automatically before
		/// using other services.
		bool partial;
	}
	adbg_object_options_t o;
	
	// Pointers to machine-dependant structures
	//TODO: Move stuff like "reversed_"/"is64"/etc. fields into properties
	package
	union adbg_object_internals_t {
		// Main header. All object files have some form of header.
		void *header;
		
		struct mz_t {
			mz_hdr *header;
			mz_reloc *relocs;
			
			bool *reversed_relocs;
		}
		mz_t mz;
		
		struct pe_t {
			// Headers
			PE_HEADER *header;
			union {
				PE_OPTIONAL_HEADER *opt_header;
				PE_OPTIONAL_HEADER64 *opt_header64;
				PE_OPTIONAL_HEADERROM *opt_headerrom;
			}
			// Directories
			PE_IMAGE_DATA_DIRECTORY *directory;
			PE_EXPORT_DESCRIPTOR *directory_exports;
			PE_IMPORT_DESCRIPTOR *directory_imports;
			PE_DEBUG_DIRECTORY *directory_debug;
			union {
				PE_LOAD_CONFIG_DIR32 *load_config32;
				PE_LOAD_CONFIG_DIR64 *load_config64;
			}
			// Data
			PE_SECTION_ENTRY *sections;
			
			bool *reversed_sections;
			bool *reversed_dir_exports;
			bool *reversed_dir_imports;
			bool *reversed_dir_debug;
		}
		pe_t pe;
		
		struct macho_t {
			union {
				macho_header *header;
				macho_fatmach_header *fat_header;
			}
			macho_fat_arch *fat_arch;
			macho_load_command *commands;
			bool is64;
			bool fat;
			
			bool *reversed_fat_arch;
			bool *reversed_commands;
		}
		macho_t macho;
		
		struct elf32_t {
			Elf32_Ehdr *ehdr;
			Elf32_Phdr *phdr;
			Elf32_Shdr *shdr;
			
			bool reversed_ehdr;
			bool *reversed_phdr;
			bool *reversed_shdr;
		}
		elf32_t elf32;
		
		struct elf64_t {
			Elf64_Ehdr *ehdr;
			Elf64_Phdr *phdr;
			Elf64_Shdr *shdr;
			
			bool reversed_ehdr;
			bool *reversed_phdr;
			bool *reversed_shdr;
		}
		elf64_t elf64;
	}
	/// Internal object definitions.
	adbg_object_internals_t i;
}

// Internal: Check if pointer is outside of file
package
bool adbg_object_poutside(adbg_object_t *o, void *ptr) {
	return ptr >= o.buffer + o.file_size;
}

int adbg_object_open(adbg_object_t *o, const(char) *path, ...) {
	if (o == null)
		return adbg_oops(AdbgError.nullArgument);
	
	o.file_handle = fopen(path, "rb");
	if (o.file_handle == null)
		return adbg_oops(AdbgError.crt);
	
	va_list list = void;
	va_start(list, path);
	
	return adbg_object_loadv(o, list);
}

void adbg_object_close(adbg_object_t *o) {
	if (o == null)
		return;
	switch (o.format) with (AdbgObject) {
	case mz:
		with (o.i.mz) if (reversed_relocs) free(reversed_relocs);
		break;
	case pe:
		with (o.i.pe) {
			if (reversed_sections) free(reversed_sections);
			if (reversed_dir_exports) free(reversed_dir_exports);
			if (reversed_dir_imports) free(reversed_dir_imports);
			if (reversed_dir_debug) free(reversed_dir_debug);
		}
		break;
	case macho:
		with (o.i.macho) {
		if (reversed_fat_arch) free(reversed_fat_arch);
		if (reversed_commands) free(reversed_commands);
		}
		break;
	case elf:
		import adbg.v2.object.format.elf :
			ELF_EI_CLASS, ELF_CLASS_32, ELF_CLASS_64;
		switch (o.i.elf32.ehdr.e_ident[ELF_EI_CLASS]) {
		case ELF_CLASS_32:
			with (o.i.elf32) {
				if (reversed_phdr) free(reversed_phdr);
				if (reversed_shdr) free(reversed_shdr);
			}
			break;
		case ELF_CLASS_64:
			with (o.i.elf64) {
				if (reversed_phdr) free(reversed_phdr);
				if (reversed_shdr) free(reversed_shdr);
			}
			break;
		default:
		}
		break;
	default:
	}
	if (o.file_handle)
		fclose(o.file_handle);
	if (o.buffer && o.buffer_size)
		free(o.buffer);
}

private
int adbg_object_loadv(adbg_object_t *o, va_list args) {
	import core.stdc.string : memset;
	
	if (o == null || o.file_handle == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	memset(&o.o, 0, o.o.sizeof); // Init options
	memset(&o.p, 0, o.p.sizeof); // Init object properties
	memset(&o.i, 0, o.i.sizeof); // Init object internal structures
	
	// options
L_ARG:
	switch (va_arg!int(args)) {
	case 0: break;
	case AdbgObjectLoadOption.partial:
		o.o.partial = true;
		goto L_ARG;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	// Get file size
	if (fseek(o.file_handle, 0, SEEK_END))
		return adbg_oops(AdbgError.crt);
	
	o.file_size = ftell(o.file_handle);
	
	if (o.file_size < 0) // -1
		return adbg_oops(AdbgError.crt);
	if (fseek(o.file_handle, 0, SEEK_SET))
		return adbg_oops(AdbgError.crt);
	
	// Allocate
	enum PARTIAL_SIZE = 4096;
	o.buffer_size = o.o.partial ? PARTIAL_SIZE : cast(size_t)o.file_size;
	o.buffer = malloc(o.buffer_size);
	if (o.buffer == null)
		return adbg_oops(AdbgError.crt);
	
	// Read
	if (fread(o.buffer, cast(size_t)o.file_size, 1, o.file_handle) == 0)
		return adbg_oops(AdbgError.crt);
	
	// Set first header
	// Also used in auto-detection
	o.i.header = o.buffer;
	
	// Auto-detection
	//TODO: Consider moving auto-detection as separate function?
	//      Especially if debugger can return process' base address for image headers
	switch (*o.buffer32) {
	case MAGIC_ELF:	// "\x7fELF" is text and MAGIC is automatically swapped on target
		return adbg_object_elf_load(o);
	case MACHO_MAGIC:	// 32-bit
	case MACHO_MAGIC_64:	// 64-bit
	case MACHO_CIGAM:	// 32-bit reversed
	case MACHO_CIGAM_64:	// 64-bit reversed
	case MACHO_FAT_MAGIC:	// Fat
	case MACHO_FAT_CIGAM:	// Fat reversed
		return adbg_object_macho_load(o);
	default:
	}
	
	switch (*o.buffer16) {
	case MAGIC_MZ:
		if (o.file_size < mz_hdr.sizeof)
			return adbg_oops(AdbgError.unknownObjFormat);
		
		uint offset = o.i.mz.header.e_lfanew;
		if (offset == 0)
			return adbg_object_mz_load(o);
		if (offset >= o.file_size - PE_HEADER.sizeof)
			return adbg_oops(AdbgError.assertion);
		
		uint sig = *cast(uint*)(o.buffer + offset);
		if (sig == MAGIC_PE32) // text
			return adbg_object_pe_load(o);
		
		switch (cast(ushort)sig) {
		case CHAR16!"LE", CHAR16!"LX", CHAR16!"NE":
			return adbg_oops(AdbgError.unsupportedObjFormat);
		default: // Assume MZ?
			return adbg_object_mz_load(o);
		}
	case MAGIC_ZM:
		if (o.file_size < mz_hdr.sizeof)
			return adbg_oops(AdbgError.unknownObjFormat);
		
		o.p.reversed = true;
		with (o.i.mz.header) e_lfanew = adbg_bswap32(e_lfanew);
		goto case MAGIC_MZ;
	default:
		return adbg_oops(AdbgError.unknownObjFormat);
	}
}

//TODO: adbg_object_load_continue if partial was used
//      set new buffer_size, partial=false

AdbgMachine adbg_object_machine(adbg_object_t *o) {
	if (o == null)
		return AdbgMachine.native;
	
	switch (o.format) with (AdbgObject) {
	case mz:	return AdbgMachine.i8086;
	case pe:	return adbg_object_pe_machine(o.i.pe.header.Machine);
	// NOTE: Both fat and header matches the header structure
	case macho:	return adbg_object_macho_machine(o.i.macho.header.cputype);
	case elf:	return adbg_object_elf_machine(o.i.elf32.ehdr.e_machine);
	default:	return AdbgMachine.unknown;
	}
}

/// Get the short name of the loaded object format.
/// Params: o = Object instance.
/// Returns: Object format name.
const(char)* adbg_object_short_name(adbg_object_t *o) {
	if (o == null)
		goto L_UNKNOWN;
	switch (o.format) with (AdbgObject) {
	case mz:	return "mz";
	case ne:	return "ne";
	case le:	return "le";
	case pe:	return "pe32";
	case macho:	return "macho";
	case elf:	return "elf";
	default:
	}
L_UNKNOWN:
	return "unknown";
}

/// Get the name of the loaded object format.
/// Params: o = Object instance.
/// Returns: Object format name.
const(char)* adbg_object_name(adbg_object_t *o) {
	if (o == null)
		goto L_UNKNOWN;
	switch (o.format) with (AdbgObject) {
	case mz:	return "Mark Zbikowski";
	case ne:	return "New Executable";
	case le:	return "Linked Executable";
	case pe:	return "Portable Executable";
	case macho:	return "Mach-O";
	case elf:	return "Executable and Linkable Format";
	default:
	}
L_UNKNOWN:
	return "Unknown";
}