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
/// License: BSD-3-Clause-Clear
module adbg.object.server;

import adbg.include.c.stdio;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import adbg.error;
import adbg.utils.bit;
import adbg.utils.math;
import adbg.object.formats;
import adbg.machines : AdbgMachine, adbg_machine_name;
import adbg.debugger.process : adbg_process_t;
import adbg.debugger.memory : adbg_memory_map_t, adbg_memory_read;
import core.stdc.string;

extern (C):

// NOTE: Function names
//       At best, prefer adbg_object_OBJECT_xyz where OBJECT is the type
//       (e.g., pe, elf, etc.) to make things consistent. This is why
//       auxiliary names are simply "adbg_object_offset", for example.

//TODO: (Important) Redo I/O handling
//      To reduce memory usage (will require better internal APIs):
//      - Load 4 KiB chunk in memory for header(s)
//      - Allocate and load data on-demand (e.g., section headers, etc.)
//      - Require each object implementation have its own closing function.
//      This is a big endeavour because of the reliance on the internal buffer pointers.
//      Naturally, more internal pointers will need to be created, and only accessible
//      using the newer API.

//TODO: const(ubyte)* adbg_obj_section_i(obj, index);
//TODO: const(ubyte)* adbg_object_get_section_by_type(obj, type);
//TODO: const(char)* adbg_object_get_debug_path(obj);
//TODO: Function to attach debug or coredump object to executable
//      int adbg_object_load_debug(obj, path);
//TODO: Consider structure definition, using a template
//      Uses:
//      - For swapping, uses less code than inlining it
//      - For displaying and using field offsets
//TODO: adbg_object_t: Consider grouping all properties into one
//      Instead of multiple structures, it might be
//      better to group all the options/properties/internals
//      into one structure (e.g., "struct info_t" member .info)

/// Executable or object file format.
enum AdbgObject {
	/// Raw binary file, or unknown object format.
	raw,
	/// Ditto
	unknown = raw,
	/// Mark Zbikowski format. (.exe)
	mz,
	/// New Executable format. (.exe)
	ne,
	/// Linked Executable/LX format. (.exe)
	lx,
	/// Portable Executable format. (.exe)
	pe,
	/// Executable and Linkable Format.
	elf,
	/// Mach Object format.
	macho,
	/// Microsoft Program Database format 2.0. (.pdb)
	pdb20,
	/// Microsoft Program Database format 7.0. (.pdb)
	pdb70,
	/// Windows memory dump format. (.dmp)
	dmp,
	/// Windows Minidump format. (.mdmp)
	mdmp,
	/// OMF object or library. (.obj, .lib)
	omf,
	/// COFF Library archive. (.lib)
	archive,
	/// COFF object. (.obj)
	coff,
	/// MSCOFF object. (.obj)
	mscoff,
}

// 
/*enum AdbgObjectKind {
	unknown,
	executable,
}*/

// NOTE: This enum is a little weird but should be used as an I/O strategy
/// Object origin. (or "load mode")
///
/// How was the object loaded or hooked.
private
enum AdbgObjectOrigin {
	/// Object is unloaded, or the loading method is unknown.
	unknown,
	/// Object was loaded from disk.
	disk,
	/// Object was loaded from the debugger into memory.
	process,
	//TODO: user buffer (memory)
}

package
enum AdbgObjectInternalFlags {
	/// Object has its fields swapped because of its target endianness.
	reversed	= 0x1,
	/// 
	notnative	= 0x2,
}

struct adbg_section_t {
	void *header;
	size_t header_size;
	void *data;
	size_t data_size;
}

/// Represents a file object image.
///
/// All fields are used internally and should not be used directly.
struct adbg_object_t {
	/// Object's loading origin.
	AdbgObjectOrigin origin;
	union {
		struct {
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
			
			/// File handle to object.
			FILE *file_handle;
			/// File size.
			ulong file_size;
	
			/// Allocated buffer size.
			size_t buffer_size;
		}
		struct {
			adbg_process_t *process;
		}
	}
	
	/// Loaded object format.
	AdbgObject format;
	
	// Object properties.
	package
	struct adbg_object_properties_t {
		/// Target endianness is reversed and therefore fields needs
		/// to be byte-swapped.
		bool reversed;
		// Target object has code that can be run on this platform.
		// Examples: x86 on x86-64 or Arm A32 on Arm A64 via WoW64
		//TODO: bool platform_native;
		
		// Temp field to avoid free'ing non-allocated memory
		bool noalloc;
		
		// 
		size_t debug_offset;
	}
	adbg_object_properties_t p;
	
	// Pointers to machine-dependant structures
	//TODO: Move stuff like "reversed_"/"is64"/etc. fields into properties
	package
	union adbg_object_internals_t {
		// Main header. All object files have some form of header.
		void *header;
		
		struct mz_t {
			union {
				mz_hdr *header;
				mz_hdr_ext *header_ext;
			}
			mz_reloc *relocs;
			void *newbase;
			bool *reversed_relocs;
		}
		mz_t mz;
		
		struct ne_t {
			ne_header *header;
		}
		ne_t ne;
		
		struct lx_t {
			lx_header *header;
		}
		lx_t lx;
		
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
			bool *reversed_dir_export_entries;
			bool *reversed_dir_imports;
			bool *reversed_dir_debug;
			
			bool reversed_dir_exports;
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
		
		struct ar_t {
			size_t current;
		}
		ar_t ar;
		
		struct pdb20_t {
			pdb20_file_header *header;
		}
		pdb20_t pdb20;
		
		struct pdb70_t {
			pdb70_file_header *header;
			ubyte *fpm;	/// Points to used FPM block
			void *dir;	/// Directory buffer (Stream 0)
			
			// Stream 0 meta
			uint strcnt;	/// Stream count
			uint *strsize;	/// Stream size (Points to Stream[0].size)
			uint *stroff;	/// Block IDs (Points to Stream[0].block[0])
			
			// Lookup table made from Stream 0
			pdb70_stream *strmap;	/// Stream mapping
		}
		pdb70_t pdb70;
		
		struct mdmp_t {
			mdump_header *header;
		}
		mdmp_t mdmp;
		
		struct dmp_t {
			dmp_header *header;
			dmp64_header *header64;
		}
		dmp_t dmp;
		
		struct omf_t {
			omf_lib_header *header;
			int pgsize;
			int firstentry;
		}
		omf_t omf;
		
		struct coff_t {
			coff_header *header;
			ushort sig;
		}
		coff_t coff;
		
		union mscoff_t {
			mscoff_import_header      *import_header;
			mscoff_anon_header        *anon_header;
			mscoff_anon_header_v2     *anon_v2_header;
			mscoff_anon_header_bigobj *anon_big_header;
		}
		mscoff_t mscoff;
	}
	/// Internal object definitions.
	adbg_object_internals_t i;
}

/// Check if pointer is outside the object bounds.
/// Params:
/// 	o = Object instance.
/// 	p = Pointer.
/// Returns: True if outside bounds.
bool adbg_object_outboundp(adbg_object_t *o, void *p) {
	version (Trace) trace("p=%zx", cast(size_t)p);
	return p < o.buffer || p >= o.buffer + o.file_size;
}
/// Check if pointer with length is outside the object bounds.
/// Params:
/// 	o = Object instance.
/// 	p = Pointer.
/// 	size = Data size.
/// Returns: True if outside bounds.
bool adbg_object_outboundpl(adbg_object_t *o, void *p, size_t size) {
	version (Trace) trace("p=%zx length=%zu", cast(size_t)p, size);
	return p < o.buffer || p + size >= o.buffer + o.file_size;
}

/// Check if offset is within file boundaries
/// Params:
/// 	o = Object instance.
/// 	off = File offset.
/// Returns: True if in bounds.
bool adbg_object_outbound(adbg_object_t *o, ulong off) {
	version (Trace) trace("offset=%llx", off);
	if (o == null) return true;
	return off >= o.file_size;
}

/// Check if offset with size is within file boundaries
/// Params:
/// 	o = Object instance.
/// 	off = File offset.
/// 	size = Data size.
/// Returns: True if in bounds.
bool adbg_object_outboundl(adbg_object_t *o, ulong off, size_t size) {
	version (Trace) trace("offset=%llx length=%zu", off, size);
	if (o == null) return true;
	return off + size > o.file_size;
}

/// Get pointer from offset.
/// Params:
/// 	o = Object instance.
/// 	p = Destination pointer.
/// 	offset = File offset.
/// Returns: True if outside bounds.
bool adbg_object_offset(adbg_object_t *o, void** p, ulong offset) {
	version (Trace) trace("p=%zx offset=%llx", cast(size_t)p, offset);
	if (p == null) return true;
	if (adbg_object_outbound(o, offset)) return true;
	*p = o.buffer + offset;
	return false;
}

/// Get pointer from offset with size.
/// Params:
/// 	o = Object instance.
/// 	p = Destination pointer.
/// 	offset = File offset.
/// 	size = Data size.
/// Returns: True if outside bounds.
bool adbg_object_offsetl(adbg_object_t *o, void** p, ulong offset, size_t size) {
	version (Trace) trace("p=%zx offset=%llx length=%zu", cast(size_t)p, offset, size);
	if (p == null) return true;
	if (adbg_object_outboundl(o, offset, size)) return true;
	*p = o.buffer + offset;
	return false;
}
unittest {
	adbg_object_t o = void;
	o.buffer = cast(void*)0x10;
	o.file_size = 10_000;
	void *p;
	assert(adbg_object_offsetl(&o, &p, 0x10, 100) == false);
	assert(cast(size_t)p == 0x20);
}

/// Template helper to get pointer from offset with length automatically.
/// Params:
/// 	o = Object instance.
/// 	dst = Destination pointer.
/// 	offset = File offset.
/// Returns: True if outside bounds.
bool adbg_object_offsett(T)(adbg_object_t *o, T* dst, ulong offset) {
	if (dst == null) return true;
	if (adbg_object_outboundl(o, offset, T.sizeof)) return true;
	static if (T.sizeof <= ulong.sizeof)
		*dst = *cast(T*)(o.buffer + offset);
	else
		static assert(0, "adbg_object_offsett memcpy TODO");
	return false;
}

/// Object server options.
enum AdbgObjectLoadOption {
	reserved = 1,
}

/// Load an object from disk into memory.
///
/// This function allocates memory.
/// Params:
///   path = File path.
///   ... = Options. Terminated with 0.
/// Returns: Object instance, or null on error.
export
adbg_object_t* adbg_object_open_file(const(char) *path, ...) {
	version (Trace) trace("path=%s", path);
	
	adbg_object_t *o = cast(adbg_object_t*)malloc(adbg_object_t.sizeof);
	if (o == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	o.file_handle = fopen(path, "rb");
	if (o.file_handle == null) {
		free(o);
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	va_list list = void;
	va_start(list, path);
	
	if (adbg_object_loadv(o, list)) {
		adbg_object_close(o);
		return null;
	}
	
	return o;
}

/*adbg_object_t* adbg_object_open_process(adbg_process_t *proc) {
	adbg_oops(AdbgError.unimplemented);
	return null;
}*/

/// Close object instance.
export
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
			if (reversed_dir_export_entries) free(reversed_dir_export_entries);
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
		import adbg.object.format.elf :
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
	case pdb70:
		with (o.i.pdb70) if (dir) free(dir);
		with (o.i.pdb70) if (strmap) free(strmap);
		break;
	default:
	}
	if (o.file_handle)
		fclose(o.file_handle);
	if (o.buffer && o.buffer_size)
		free(o.buffer);
	if (o.p.noalloc == false) // check is temporary
		free(o);
}

//TODO: adbg_object_write (disk source being copy-on-write to memory)

// Read raw data from object.
// Params:
// 	o = Object instance.
// 	buffer = Buffer pointer.
// 	rsize = Size to read.
// Returns: Error code.
/+int adbg_object_read(adbg_object_t *o, ulong location, void *buffer, size_t rsize) {
	if (rsize == 0)
		return 0;
	if (o == null || buffer == null) {
		adbg_oops(AdbgError.nullArgument);
		return -1;
	}
	
	import adbg.debugger.memory : adbg_memory_read;
	import core.stdc.string : memcpy;
	
	switch (o.origin) with (AdbgObjectOrigin) {
	case disk:
		if (location + rsize >= o.buffer_size)
			return adbg_oops(AdbgError.objectOutsideAccess);
		if (memcpy(buffer, o.buffer + location, rsize))
			return adbg_oops(AdbgError.crt);
		return 0;
	case process:
		return adbg_memory_read(
			o.process, cast(size_t)location, buffer, cast(uint)rsize);
	default:
	}
	
	return adbg_oops(AdbgError.unimplemented);
}+/

// Object detection and loading
private
int adbg_object_loadv(adbg_object_t *o, va_list args) {
	import core.stdc.string : memset;
	
	if (o == null || o.file_handle == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	memset(&o.p, 0, o.p.sizeof); // Init object properties
	memset(&o.i, 0, o.i.sizeof); // Init object internal structures
	
	// options
L_ARG:	switch (va_arg!int(args)) {
	case 0: break;
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
	version (Trace) trace("filesize=%llu", o.file_size);
	
	// Allocate
	o.buffer_size = cast(size_t)o.file_size;
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
	
	// Magic detection over 8 Bytes
	if (o.file_size > PDB_DEFAULT_PAGESIZE) {
		if (memcmp(o.buffer, PDB20_MAGIC.ptr, PDB20_MAGIC.length) == 0)
			return adbg_object_pdb20_load(o);
		if (memcmp(o.buffer, PDB70_MAGIC.ptr, PDB70_MAGIC.length) == 0)
			return adbg_object_pdb70_load(o);
	}
	
	// 64-bit signature detection
	switch (*o.buffer64) {
	case AR_MAGIC:
		return adbg_object_ar_load(o);
	case PAGEDUMP32_MAGIC, PAGEDUMP64_MAGIC:
		return adbg_object_dmp_load(o);
	default:
	}
	
	// 32-bit signature detection
	switch (*o.buffer32) {
	case ELF_MAGIC:	// ELF
		return adbg_object_elf_load(o);
	case MACHO_MAGIC:	// Mach-O 32-bit
	case MACHO_MAGIC64:	// Mach-O 64-bit
	case MACHO_CIGAM:	// Mach-O 32-bit reversed
	case MACHO_CIGAM64:	// Mach-O 64-bit reversed
	case MACHO_FATMAGIC:	// Mach-O Fat
	case MACHO_FATCIGAM:	// Mach-O Fat reversed
		return adbg_object_macho_load(o);
	case MDMP_MAGIC:
		return adbg_object_mdmp_load(o);
	default:
	}
	
	// 16-bit signature detection
	switch (*o.buffer16) {
	// Anonymous MSCOFF
	case 0:
		if (o.file_size < mscoff_anon_header_bigobj.sizeof)
			return adbg_oops(AdbgError.objectUnknownFormat);
		if (o.i.mscoff.import_header.Sig2 != 0xffff)
			return adbg_oops(AdbgError.objectUnknownFormat);
		
		return adbg_object_mscoff_load(o);
	case MAGIC_MZ:
		if (o.file_size < mz_hdr.sizeof)
			return adbg_oops(AdbgError.objectUnknownFormat);
		
		version (Trace) trace("e_lfarlc=%#x", o.i.mz.header.e_lfarlc);
		
		// If e_lfarlc (relocation table) starts lower than e_lfanew,
		// then assume old MZ.
		// NOTE: e_lfarlc can point to 0x40.
		if (o.i.mz.header.e_lfarlc < 0x40)
			return adbg_object_mz_load(o);
		
		// If e_lfanew points within MZ extended header
		if (o.i.mz.header_ext.e_lfanew <= mz_hdr_ext.sizeof)
			return adbg_object_mz_load(o);
		
		// If e_lfanew points outside file
		if (o.i.mz.header_ext.e_lfanew >= o.file_size)
			return adbg_object_mz_load(o);
		
		// NOTE: ReactOS checks if NtHeaderOffset is not higher than 256 MiB
		//       At this point, it could be malformed.
		//       Have you seen a 256M DOS executable?
		if (o.i.mz.header_ext.e_lfanew >= MiB!256)
			return adbg_object_mz_load(o);
		
		// Set where new header is located, used by sub-loaders
		o.i.mz.newbase = o.buffer + o.i.mz.header_ext.e_lfanew;
		
		// 32-bit signature check
		uint sig = *cast(uint*)o.i.mz.newbase;
		switch (sig) {
		case MAGIC_PE32:
			return adbg_object_pe_load(o);
		default:
		}
		
		// 16-bit signature check
		switch (cast(ushort)sig) {
		case NE_MAGIC:
			return adbg_object_ne_load(o);
		case LX_MAGIC, LE_MAGIC:
			return adbg_object_lx_load(o);
		default:
		}
		
		// If nothing matches, assume MZ
		return adbg_object_mz_load(o);
	// Old MZ magic or swapped
	case MAGIC_ZM:
		if (o.file_size < mz_hdr.sizeof)
			return adbg_oops(AdbgError.objectUnknownFormat);
		
		goto case MAGIC_MZ;
	// COFF magics
	case COFF_MAGIC_I386:
	case COFF_MAGIC_I386_AIX:
	case COFF_MAGIC_AMD64:
	case COFF_MAGIC_IA64:
	case COFF_MAGIC_Z80:
	case COFF_MAGIC_TMS470:
	case COFF_MAGIC_TMS320C5400:
	case COFF_MAGIC_TMS320C6000:
	case COFF_MAGIC_TMS320C5500:
	case COFF_MAGIC_TMS320C2800:
	case COFF_MAGIC_MSP430:
	case COFF_MAGIC_TMS320C5500P:
	case COFF_MAGIC_MIPSEL:
		return adbg_object_coff_load(o, *o.buffer16);
	default:
	}
	
	// 8-bit signature detection
	switch (*o.buffer8) {
	case OMFRecord.LIBRARY: // OMF library header entry
	case OMFRecord.THEADR: // First OMF object entry of THEADR
	case OMFRecord.LHEADR: // First OMF object entry of LHEADR
		return adbg_object_omf_load(o, *o.buffer8);
	default:
	}
	
	return adbg_oops(AdbgError.objectUnknownFormat);
}

export
void* adbg_object_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	// NOTE: Cleared on allocation until image is loaded
	return o.i.header;
}

adbg_section_t* adbg_object_section_n(adbg_object_t *o, const(char)* name, uint flags = 0) {
	if (o == null || name == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}

	// First, first the section header by name
	void *headerp = void; size_t header_size = void;
	void *datap = void;   size_t data_size = void;
	switch (o.format) with (AdbgObject) {
	//case pe:
	//	break;
	case elf:
		switch (o.i.elf32.ehdr.e_ident[ELF_EI_CLASS]) {
		case ELF_CLASS_32:
			Elf32_Shdr *shdr32 = adbg_object_elf_shdr32_n(o, name);
			if (shdr32 == null)
				return null;
			headerp = shdr32;
			header_size = Elf32_Shdr.sizeof;
			datap = o.buffer + shdr32.sh_offset;
			data_size = shdr32.sh_size;
			break;
		case ELF_CLASS_64:
			Elf64_Shdr *shdr64 = adbg_object_elf_shdr64_n(o, name);
			if (shdr64 == null)
				return null;
			headerp = shdr64;
			header_size = Elf64_Shdr.sizeof;
			datap = o.buffer + shdr64.sh_offset;
			data_size = cast(size_t)shdr64.sh_size;
			break;
		default:
			goto Lunavail;
		}
		break;
	default:
	Lunavail:
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// Is section within bounds?
	if (adbg_object_outboundpl(o, datap, data_size)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	// TODO: Turn into vararg helper tool
	//       mcalloc(pointer, size, pointer, size, null);
	// Then, allocate the memory to hold the header and data
	adbg_section_t *section = cast(adbg_section_t*)malloc(
		adbg_section_t.sizeof + header_size + data_size);
	if (section == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	section.header      = cast(void*)section + adbg_section_t.sizeof;
	section.header_size = header_size;
	section.data        = cast(void*)section + adbg_section_t.sizeof + header_size;
	section.data_size   = data_size;
	// Copy section header and section data
	memcpy(section.header, headerp, header_size);
	memcpy(section.data,   datap,   data_size);

	return section;
}

//adbg_section_t* adbg_object_section_i(adbg_object_t *o, size_t index, uint flags = 0) {	
//}

void adbg_object_section_free(adbg_object_t *o, adbg_section_t *section) {
	if (section == null)
		return;
	free(section);
}

/// Returns the first machine type the object supports.
/// Params: o = Object instance.
/// Returns: Machine value.
AdbgMachine adbg_object_machine(adbg_object_t *o) {
	if (o == null)
		return AdbgMachine.native;
	
	switch (o.format) with (AdbgObject) {
	case mz:	return AdbgMachine.i8086;
	case ne: // NOTE: Can have a mix of 8086/i286/i386 instructions, take the highest
		if (o.i.ne.header.ne_flags & NE_HFLAG_INTI386)
			return AdbgMachine.i386;
		if (o.i.ne.header.ne_flags & (NE_HFLAG_INT8086 | NE_HFLAG_INTI286))
			return AdbgMachine.i8086;
		break;
	case lx:
		switch (o.i.lx.header.cpu) {
		case LX_CPU_80286: return AdbgMachine.i8086;
		case LX_CPU_80386:
		case LX_CPU_80486: return AdbgMachine.i386;
		default:
		}
		break;
	case pe:	return adbg_object_pe_machine(o.i.pe.header.Machine);
	case macho: // NOTE: Both Mach-O headers (regular/fat) match in layout for cputype
		return adbg_object_macho_machine(o.i.macho.header.cputype);
	case elf:
		with (o.i.elf32.ehdr)
		return adbg_object_elf_machine(e_machine, e_ident[ELF_EI_CLASS]);
	case coff:
		switch (o.i.coff.sig) {
		case COFF_MAGIC_I386:
		case COFF_MAGIC_I386_AIX:	return AdbgMachine.i386;
		case COFF_MAGIC_AMD64:	return AdbgMachine.amd64;
		case COFF_MAGIC_IA64:	return AdbgMachine.ia64;
		case COFF_MAGIC_Z80:	return AdbgMachine.z80;
		/*case COFF_MAGIC_TMS470:	return AdbgMachine.;
		/*case COFF_MAGIC_TMS320C5400:	return AdbgMachine.;
		case COFF_MAGIC_TMS320C6000:	return AdbgMachine.;
		case COFF_MAGIC_TMS320C5500:	return AdbgMachine.;
		case COFF_MAGIC_TMS320C2800:	return AdbgMachine.;
		case COFF_MAGIC_MSP430:	return AdbgMachine.;
		case COFF_MAGIC_TMS320C5500P:	return AdbgMachine.;*/
		case COFF_MAGIC_MIPSEL:	return AdbgMachine.mipsle;
		default:
		}
		break;
	default:
	}
	return AdbgMachine.unknown;
}
const(char)* adbg_object_machine_string(adbg_object_t *o) {
	AdbgMachine mach = adbg_object_machine(o);
	return mach ? adbg_machine_name(mach) : `Unknown`;
}

/// Get the short name of the loaded object format.
/// Params: o = Object instance.
/// Returns: Object format name.
const(char)* adbg_object_format_shortname(adbg_object_t *o) {
	if (o == null)
		goto Lunknown;
	final switch (o.format) with (AdbgObject) {
	case mz:	return "mz";
	case ne:	return "ne";
	case lx:	return o.i.lx.header.magic == LX_MAGIC ? "lx" : "le";
	case pe:	return "pe32";
	case macho:	return "macho";
	case elf:	return "elf";
	case pdb20:	return "pdb20";
	case pdb70:	return "pdb70";
	case mdmp:	return "mdmp";
	case dmp:	return "dmp";
	case omf:	return "omf";
	case archive:	return "archive";
	case coff:	return "coff";
	case mscoff:	return "mscoff";
	Lunknown:
	case unknown:	return "unknown";
	}
}

/// Get the full name of the loaded object format.
/// Params: o = Object instance.
/// Returns: Object format name.
const(char)* adbg_object_format_name(adbg_object_t *o) {
	if (o == null)
		goto Lunknown;
	final switch (o.format) with (AdbgObject) {
	case mz:	return `Mark Zbikowski`;
	case ne:	return `New Executable`;
	case lx:	return `Linked Executable`;
	case pe:	return `Portable Executable`;
	case macho:	return `Mach-O`;
	case elf:	return `Executable and Linkable Format`;
	case pdb20:	return `Program Database 2.0`;
	case pdb70:	return `Program Database 7.0`;
	case mdmp:	return `Windows Minidump`;
	case dmp:	return `Windows Memory Dump`;
	case omf:	return `Relocatable Object Module Format`;
	case archive:	return `Library Archive`;
	case coff:	return `Common Object File Format`;
	case mscoff:	return `Microsoft Common Object File Format`;
	Lunknown:
	case unknown:	return "Unknown";
	}
}

/*enum AdbgObjectKind {
	unknown,
	executable,
	sharedObject,
}

AdbgObjectKind adbg_object_format_kind(adbg_object_t *o)*/

const(char)* adbg_object_format_kind_string(adbg_object_t *o) {
	if (o == null)
		goto Lunknown;
	switch (o.format) with (AdbgObject) {
	case mz:
		return o.i.mz.header.e_ovno ? `Overlayed Executable` : `Executable`;
	case ne:
		return o.i.ne.header.ne_flags & NE_HFLAG_LIBMODULE ? `Library Module` : `Executable`;
	case lx:
		return adbg_object_lx_modtype_string(o.i.lx.header.mflags);
	case pe:
		return o.i.pe.header.Characteristics & PE_CHARACTERISTIC_DLL ? `Dynamically Linked Library` : `Executable`;
	case macho:
		if (o.i.macho.fat) return `Fat Executable`;
		return adbg_object_macho_filetype_string(o.i.macho.header.filetype);
	case elf:
		return o.i.elf32.ehdr.e_type == ELF_ET_DYN ? `Shared Object` : `Executable`;
	case pdb20, pdb70:
		return `Debug Database`;
	case mdmp, dmp:
		return `Memory Dump`;
	case archive:
		return `Library`;
	case omf:
		return o.i.omf.firstentry ? `Library` : `Object`;
	case coff, mscoff:
		return `Object`;
	default: Lunknown:
		return `Unknown`;
	}
}