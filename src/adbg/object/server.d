/// Object server.
///
/// The goal of the object/image loader is being able to obtain information
/// from object files such as:
/// - Object Type;
/// - Machine architecture;
/// - Symbols;
/// - Debugging information (types, etc.);
/// - And a few extras for dumping purposes.
///
/// Implementating these services from scratch gives a few benefits:
/// - Control, all information from objects is available.
/// - Flexbility, the operating system might limited in options for symbol discovery.
/// - Fallbacks, such as selecting at least one source for symbols.
///
/// The way this is structured is simple: This module provides a generic object API
/// and implements basic I/O for submodules to use.
/// 
/// The submodules that implementing specific object formats manage their own internal
/// memory buffers.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.server;

import adbg.debugger.memory : adbg_memory_read;
import adbg.debugger.process : adbg_process_t;
import adbg.error;
import adbg.machines : AdbgMachine, adbg_machine_name;
import adbg.utils.math;	// For MiB template
import adbg.object.formats;
import adbg.include.c.stdio;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import adbg.os.file;
import core.stdc.string;

extern (C):

// NOTE: Function names
//       At best, prefer adbg_object_OBJECT_xyz where OBJECT is the type
//       (e.g., pe, elf, etc.) to make things consistent. This is why
//       auxiliary names are simply "adbg_object_offset", for example.

//TODO: Consider structure definition, using a template
//      Uses:
//      - For swapping, uses less code than inlining it
//      - For displaying and using field offsets

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
	/// 
	userbuffer,
}

package
enum AdbgObjectInternalFlags {
	//TODO: Rename to swapped since this is a little confusing
	/// Object has its fields swapped because of its target endianness.
	swapped	= 0x1,
	/// Old alias for swapped.
	reversed = swapped,
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
	// NOTE: It's important that none of the modules rely on a total size,
	//       like a file size, since the origin can be of any kind (e.g., a process).
	//       However, it must be seekable.
	deprecated union {
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
	}
	package union {
		struct {
			OSFILE *file;
		}
		struct {
			adbg_process_t *process;
			size_t location;
		}
	}
	
	/// Object's loading origin.
	AdbgObjectOrigin origin;
	/// Loaded object format.
	AdbgObject format;
	
	// NOTE: Sub modules are free to use upper 16 bits
	/// Internal status flags. (e.g., swapping required)
	int status;
	
	// NOTE: This can be turned into a static buffer.
	/// Managed by the object handler.
	void *internal;
	
	//TODO: Deprecate *all* of this
	
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
	deprecated
	adbg_object_properties_t p;
	
	// Pointers to machine-dependant structures
	//TODO: Move stuff like "reversed_"/"is64"/etc. fields into properties
	package
	union adbg_object_internals_t {
		// Main header. All object files have some form of header.
		void *header;
		
		struct macho_t {
			union {
				macho_header_t *header;
				macho_fat_header_t *fat_header;
			}
			macho_fat_arch_entry_t *fat_arch;
			macho_load_command_t *commands;
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
	deprecated
	adbg_object_internals_t i;
}

//TODO: adbg_object_needswap
//      Check origin (==disk) and swap field, return true if fields need to be swapped

/// Check if pointer is outside the object bounds.
/// Params:
/// 	o = Object instance.
/// 	p = Pointer.
/// Returns: True if outside bounds.
deprecated
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
deprecated
bool adbg_object_outboundpl(adbg_object_t *o, void *p, size_t size) {
	version (Trace) trace("p=%zx length=%zu", cast(size_t)p, size);
	return p < o.buffer || p + size >= o.buffer + o.file_size;
}

/// Check if offset is within file boundaries
/// Params:
/// 	o = Object instance.
/// 	off = File offset.
/// Returns: True if in bounds.
deprecated
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
deprecated
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
deprecated
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
deprecated
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
deprecated
bool adbg_object_offsett(T)(adbg_object_t *o, T* dst, ulong offset) {
	if (dst == null) return true;
	if (adbg_object_outboundl(o, offset, T.sizeof)) return true;
	static if (T.sizeof <= ulong.sizeof)
		*dst = *cast(T*)(o.buffer + offset);
	else
		static assert(0, "adbg_object_offsett memcpy TODO");
	return false;
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
	
	//TODO: To remove
	o.file_handle = fopen(path, "rb");
	if (o.file_handle == null) {
		free(o);
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	o.file = osfopen(path, OSFileOFlags.read);
	if (o.file == null) {
		free(o);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	o.origin = AdbgObjectOrigin.disk;
	
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
/// Params: o = Object instance.
export
void adbg_object_close(adbg_object_t *o) {
	if (o == null)
		return;
	switch (o.format) with (AdbgObject) {
	case mz:	adbg_object_mz_unload(o); break;
	case ne:	adbg_object_ne_unload(o); break;
	case lx:	adbg_object_lx_unload(o); break;
	case pe:	adbg_object_pe_unload(o); break;
	case macho:	adbg_object_macho_unload(o); break;
	case elf:	adbg_object_elf_unload(o); break;
	case pdb70:
		//TODO: Remove junk
		with (o.i.pdb70) if (dir) free(dir);
		with (o.i.pdb70) if (strmap) free(strmap);
		break;
	default:
	}
	if (o.file)
		osfclose(o.file);
	if (o.file_handle)
		fclose(o.file_handle);
	if (o.buffer && o.buffer_size)
		free(o.buffer);
	free(o);
}

int adbg_object_read(adbg_object_t *o, void *buffer, size_t rdsize, int flags = 0) {
	version (Trace) trace("buffer=%p rdsize=%zu", buffer, rdsize);
	
	if (o == null || buffer == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (rdsize == 0)
		return 0;
	
	version (Trace) trace("origin=%d", o.origin);
	switch (o.origin) with (AdbgObjectOrigin) {
	case disk:
		int target = cast(int)rdsize;
		int r = osfread(o.file, buffer, target);
		version (Trace) trace("osfread=%d", r);
		if (r < 0)
			return adbg_oops(AdbgError.os);
		if (r < target)
			return adbg_oops(AdbgError.partialRead);
		return 0;
	case process:
		return adbg_memory_read(o.process, o.location, buffer, cast(uint)rdsize);
	//case userbuffer:
		//if (location + rsize >= o.buffer_size)
		//	return adbg_oops(AdbgError.objectOutsideAccess);
		//if (memcpy(buffer, o.buffer + location, rsize))
		//	return adbg_oops(AdbgError.crt);
	default:
	}
	
	return adbg_oops(AdbgError.unimplemented);
}

//TODO: adbg_object_read_at: Add flag to allocate memory. Or make a new function (new signature)
/// Read raw data from object at absolute position.
/// Params:
/// 	o = Object instance.
/// 	location = Absolute file offset.
/// 	buffer = Buffer pointer.
/// 	rdsize = Size to read.
/// 	flags = Additional settings.
/// Returns: Zero on success; Otherwise error code.
int adbg_object_read_at(adbg_object_t *o, long location, void *buffer, size_t rdsize, int flags = 0) {
	version (Trace) trace("location=%lld buffer=%p rdsize=%zu", location, buffer, rdsize);
	
	if (o == null || buffer == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	if (rdsize == 0)
		return 0;
	
	switch (o.origin) with (AdbgObjectOrigin) {
	case disk:
		if (osfseek(o.file, location, OSFileSeek.start) < 0)
			return adbg_oops(AdbgError.os);
		break;
	case process:
		o.location = cast(size_t)location;
		break;
	default:
		return adbg_oops(AdbgError.unimplemented);
	}
	
	return adbg_object_read(o, buffer, rdsize);
}

/// 
private
union SIGNATURE {
	ubyte[64] buffer;
	ulong u64;
	uint u32;
	ushort u16;
	ubyte u8;
	mz_header_t mzheader;
}

// Object detection and loading
private
int adbg_object_loadv(adbg_object_t *o, va_list args) {
	if (o == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	o.status = 0;
	memset(&o.p, 0, o.p.sizeof); // Init object properties
	memset(&o.i, 0, o.i.sizeof); // Init object internal structures
	
	// options
	/*
L_ARG:	switch (va_arg!int(args)) {
	case 0: break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	*/
	
	// SECTION: OLD STRATEGY
	
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
	
	// SECTION: OLD STRATEGY
	
	// SECTION: NEW STRATEGY
	
	// Load minimum for signature detection
	// Also tests seeking in case this is a streamed input
	SIGNATURE sig = void;
	int ssz = osfread(o.file, &sig, SIGNATURE.sizeof); /// signature size
	version (Trace) trace("ssz=%d", ssz);
	if (ssz < 0)
		return adbg_oops(AdbgError.os);
	if (ssz < 32) // File is empty or too small to mean anything
		return adbg_oops(AdbgError.objectTooSmall);
	if (osfseek(o.file, 0, OSFileSeek.start) < 0) // Reset offset, test seek
		return adbg_oops(AdbgError.os);
	
	// !SECTION: NEW STRATEGY
	
	// Magic detection over 8 Bytes
	if (memcmp(sig.buffer.ptr, PDB20_MAGIC.ptr, PDB20_MAGIC.length) == 0)
		return adbg_object_pdb20_load(o);
	if (memcmp(sig.buffer.ptr, PDB70_MAGIC.ptr, PDB70_MAGIC.length) == 0)
		return adbg_object_pdb70_load(o);
	
	// 64-bit signature detection
	version (Trace) trace("u64=%#x", sig.u64);
	switch (sig.u64) {
	case AR_MAGIC:
		return adbg_object_ar_load(o);
	case PAGEDUMP32_MAGIC, PAGEDUMP64_MAGIC:
		return adbg_object_dmp_load(o);
	default:
	}
	
	// 32-bit signature detection
	version (Trace) trace("u32=%#x", sig.u32);
	switch (sig.u32) {
	case ELF_MAGIC:	// ELF
		return adbg_object_elf_load(o);
	case MACHO_MAGIC:	// Mach-O 32-bit
	case MACHO_MAGIC64:	// Mach-O 64-bit
	case MACHO_CIGAM:	// Mach-O 32-bit reversed
	case MACHO_CIGAM64:	// Mach-O 64-bit reversed
	case MACHO_FATMAGIC:	// Mach-O Fat
	case MACHO_FATCIGAM:	// Mach-O Fat reversed
		return adbg_object_macho_load(o, sig.u32);
	case MDMP_MAGIC:
		return adbg_object_mdmp_load(o);
	default:
	}
	
	// 16-bit signature detection
	version (Trace) trace("u16=%#x", sig.u16);
	switch (sig.u16) {
	// Anonymous MSCOFF
	case 0:
		if (o.file_size < mscoff_anon_header_bigobj.sizeof)
			return adbg_oops(AdbgError.objectUnknownFormat);
		if (o.i.mscoff.import_header.Sig2 != 0xffff)
			return adbg_oops(AdbgError.objectUnknownFormat);
		return adbg_object_mscoff_load(o);
	case MAGIC_MZ:
		version (Trace) trace("e_lfarlc=%#x", sig.mzheader.e_lfarlc);
		
		// If e_lfarlc (relocation table) starts lower than e_lfanew,
		// then assume old MZ.
		// NOTE: e_lfarlc can point to 0x40.
		if (sig.mzheader.e_lfarlc < 0x40)
			return adbg_object_mz_load(o);
		
		// If e_lfanew points within (extended) MZ header
		if (sig.mzheader.e_lfanew <= mz_header_t.sizeof)
			return adbg_object_mz_load(o);
		
		// ReactOS checks if NtHeaderOffset is not higher than 256 MiB
		//TODO: Consider if malformed.
		if (sig.mzheader.e_lfanew >= MiB!256)
			return adbg_object_mz_load(o);
		
		uint newsig = void;
		if (adbg_object_read_at(o, sig.mzheader.e_lfanew, &newsig, uint.sizeof))
			return adbg_errno();
		
		version (Trace) trace("newsig=%#x", newsig);
		
		// 32-bit signature check
		switch (newsig) {
		case MAGIC_PE32:
			return adbg_object_pe_load(o, sig.mzheader.e_lfanew);
		default:
		}
		
		// 16-bit signature check
		switch (cast(ushort)newsig) {
		case NE_MAGIC:
			return adbg_object_ne_load(o, sig.mzheader.e_lfanew);
		case LX_MAGIC, LE_MAGIC:
			return adbg_object_lx_load(o, sig.mzheader.e_lfanew);
		default:
		}
		
		// If nothing matches, assume MZ
		return adbg_object_mz_load(o);
	// Old MZ magic or swapped
	case MAGIC_ZM:
		//TODO: pre-checked if only the signature is swapped
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
		return adbg_object_coff_load(o, sig.u16);
	default:
	}
	
	// 8-bit signature detection
	version (Trace) trace("u8=%#x", sig.u8);
	switch (sig.u8) {
	case OMFRecord.LIBRARY: // OMF library header entry
	case OMFRecord.THEADR: // First OMF object entry of THEADR
	case OMFRecord.LHEADR: // First OMF object entry of LHEADR
		return adbg_object_omf_load(o, sig.u8);
	default:
	}
	
	return adbg_oops(AdbgError.objectUnknownFormat);
}

//TODO: Flags: Contains (default: exact), case insensitive, executable only, etc.
adbg_section_t* adbg_object_search_section_by_name(adbg_object_t *o, const(char) *name, int flags = 0) {
	if (o == null || name == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	// Search every section for its name
	void *section_header;
	size_t section_header_size;
	long section_offset;
	size_t section_size;
	switch (o.format) with (AdbgObject) {
	case pe:
		size_t i;
		for (pe_section_entry_t *s = void; (s = adbg_object_pe_section(o, i)) != null; ++i) {
			//TODO: Section name function (in case of long section names)
			if (strncmp(name, s.Name.ptr, s.Name.sizeof) == 0) {
				section_header = s;
				section_header_size = pe_section_entry_t.sizeof;
				section_offset = s.PointerToRawData;
				section_size = s.SizeOfRawData;
				break;
			}
		}
		break;
	case macho:
		int macho64 = adbg_object_macho_is_64bit(o);
		size_t ci;
		MACHO_FOR: for (macho_load_command_t *c = void; (c = adbg_object_macho_load_command(o, ci)) != null; ++ci) {
			size_t si;
			for (void *s = void; (s = adbg_object_macho_segment_section(o, c, si)) != null; ++si) {
				if (macho64) {
					macho_section64_t *s64 = cast(macho_section64_t*)s;
					
					if (strncmp(name, s64.sectname.ptr, s64.sectname.sizeof) == 0) {
						section_header = s64;
						section_header_size = macho_section64_t.sizeof;
						section_offset = s64.offset;
						section_size = s64.size;
						break MACHO_FOR;
					}
				} else { // 32-bit
					macho_section_t *s32 = cast(macho_section_t*)s;
				
					if (strncmp(name, s32.sectname.ptr, s32.sectname.sizeof) == 0) {
						section_header = s32;
						section_header_size = macho_section_t.sizeof;
						section_offset = s32.offset;
						section_size = s32.size;
						break MACHO_FOR;
					}
				}
			}
		}
		break;
	case elf:
		size_t i;
		switch (adbg_object_elf_class(o)) {
		case ELF_CLASS_32:
			for (Elf32_Shdr *s = void; (s = adbg_object_elf_shdr32(o, i)) != null; ++i) {
				const(char) *sname = adbg_object_elf_shdr32_name(o, s);
				if (sname == null)
					continue;
				if (strcmp(name, sname) == 0) {
					section_header = s;
					section_header_size = Elf32_Shdr.sizeof;
					section_offset = s.sh_offset;
					section_size = s.sh_size;
					break;
				}
			}
			break;
		case ELF_CLASS_64:
			for (Elf64_Shdr *s = void; (s = adbg_object_elf_shdr64(o, i)) != null; ++i) {
				const(char) *sname = adbg_object_elf_shdr64_name(o, s);
				if (sname == null)
					continue;
				if (strcmp(name, sname) == 0) {
					section_header = s;
					section_header_size = Elf32_Shdr.sizeof;
					section_offset = s.sh_offset;
					section_size = s.sh_size;
					break;
				}
			}
			break;
		default:
			return null;
		}
		break;
	default:
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// No section found
	if (section_header == null) {
		adbg_oops(AdbgError.unfindable);
		return null;
	}
	
	// Everything needs to be set. OK to do since this is internal information.
	assert(section_header);
	assert(section_header_size);
	assert(section_offset);
	assert(section_size);
	
	// Allocate the buffer to hold the section header and data
	size_t totalsize = adbg_section_t.sizeof + section_header_size + section_size;
	void *section_buffer = malloc(totalsize);
	if (section_buffer == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Copy everything into the new buffer
	adbg_section_t *section = cast(adbg_section_t*)section_buffer;
	section.header_size = section_header_size;
	section.data_size = section_size;
	
	// Header starts after section metadata
	section.header = section_buffer + adbg_section_t.sizeof;
	memcpy(section.header, section_header, section_header_size);
	
	// Data starts after section header data
	section.data = section_buffer + adbg_section_t.sizeof + section_header_size;
	if (adbg_object_read_at(o, section_offset, section.data, section_size)) {
		free(section_buffer);
		return null; // function sets error
	}
	
	// Return buffer pointer
	return section;
}

deprecated
export
void* adbg_object_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	// NOTE: Cleared on allocation until image is loaded
	return o.i.header;
}

deprecated
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

void adbg_object_section_close(adbg_object_t *o, adbg_section_t *section) {
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
	case ne:	return adbg_object_ne_machine(o);
	case lx:	return adbg_object_lx_machine(o);
	case pe:	return adbg_object_pe_machine(o);
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

/// Get the short name of the loaded object type.
/// Params: o = Object instance.
/// Returns: Object type name.
export
const(char)* adbg_object_type_shortname(adbg_object_t *o) {
	if (o == null)
		goto Lunknown;
	//TODO: Consider merging pdb20 and pdb70 to only "pdb"
	//TODO: Consider dropping "le" to stick only with "lx"
	final switch (o.format) with (AdbgObject) {
	case mz:	return "mz";
	case ne:	return "ne";
	case lx:	return adbg_object_lx_header_shortname(o);
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

/// Get the full name of the loaded object type.
/// Params: o = Object instance.
/// Returns: Object type name.
export
const(char)* adbg_object_type_name(adbg_object_t *o) {
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

// Printing purposes only
const(char)* adbg_object_kind_string(adbg_object_t *o) {
	if (o == null)
		return null;
	switch (o.format) with (AdbgObject) {
	case mz:	return adbg_object_mz_kind_string(o);
	case ne:	return adbg_object_ne_kind_string(o);
	case lx:	return adbg_object_lx_kind_string(o);
	case pe:	return adbg_object_pe_kind_string(o);
	case macho:	return adbg_object_macho_kind_string(o);
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
	default:
	}
	return null;
}