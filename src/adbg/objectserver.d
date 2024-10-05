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
module adbg.objectserver;

import adbg.process.memory : adbg_memory_read;
import adbg.process.base : adbg_process_t;
import adbg.error;
import adbg.machines : AdbgMachine, adbg_machine_name;
import adbg.utils.math;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import adbg.os.file;
import adbg.objects;
import core.stdc.string;

extern (C):

// NOTE: For object submodule implementations.
//
//       Function names
//         At best, prefer adbg_object_OBJECT_xyz where OBJECT is the type
//         (e.g., pe, elf, etc.) to make things consistent. This is why
//         auxiliary names are simply "adbg_object_offset", for example.
//
//       Performance
//         Keeping crucial information, like the sectiontable, in memory,
//         can greatly accelerate a lot of the operations, including section
//         searches, but should only be allocated on-demand. Headers, program
//         headers, and sections usually should be read when loading a new
//         object instance.

// TODO: Clean the section search functions
// TODO: Consider structure definition, using a template
//       Uses:
//       - For swapping, uses less code than inlining it
//       - For displaying and using field offsets
// TODO: adbg_object_endiannes
//       Why? Machine module do not include endianness.
//       And would be beneficial when host has incompatible endianness.
// TODO: adbg_object_open_process(int pid, ...)
// TODO: adbg_object_open_buffer(void *buffer, size_t size, ...)
// TODO: adbg_object_origin_string(adbg_object_t *o)
//       Return string of how object was loaded, mainly for tracing purposes
// TODO: adbg_object_load_debug(adbg_object_t *o)
//       Attach debug object instance to this one. Likely to be used internally for stuff
//       like getting symbols off memory addresses.
//       PE32:
//         - Load PDB from debug entry (PDB absolute or try relative same folder)
//       ELF:
//         - DWARF (".debug_info" and others)
//         - Compact C type Format (CTF, ".ctf"): https://github.com/lovasko/libctf
//         - BPF Type Format (BTF)
//       Mach-O:
//         - uuid_command points to dSYM file

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

/// Object origin. Used in adbg_object_read.
private
enum AdbgObjectOrigin {
	/// Object is unloaded, or the loading method is unknown.
	unknown,
	/// Object was loaded from disk.
	disk,
	/// Object was loaded from the debugger into memory.
	process,
	/// TODO: Object is a whole buffer provided externally.
	userbuffer,
	/// TODO: Object is memory-mapped.
	mmap,
}

package
enum AdbgObjectInternalFlags {
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
	package union {
		struct {
			OSFILE *file;
		}
		struct {
			adbg_process_t *process;
			size_t location;
		}
		struct {
			void *user_buffer;
			size_t user_size;
		}
	}
	
	/// Object's loading origin.
	AdbgObjectOrigin origin;
	/// Loaded object format.
	AdbgObject format;
	
	/// Internal status flags. (e.g., swapping required)
	int status;
	
	// NOTE: This can be turned into a static buffer.
	/// Managed by the object handler.
	void *internal;
	
	/// Used to attach the unload function
	void function(adbg_object_t*) func_unload;
}

// Internal function for submodules to setup internals
package
void adbg_object_postload(adbg_object_t *o,
	AdbgObject type, void function(adbg_object_t *o) funload) {
	assert(o);
	assert(type);
	assert(funload);
	
	o.format = type;
	o.func_unload = funload;
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
	
	o.file = osfopen(path, OSFileOFlags.read);
	if (o.file == null) {
		free(o);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	o.origin = AdbgObjectOrigin.disk;
	
	if (adbg_object_loadv(o)) {
		adbg_object_close(o);
		return null;
	}
	
	version (Trace) if (o.func_unload == null)
		trace("WARNING: object type %d does not have unload function set", o.format);
	
	return o;
}

/// Close object instance.
/// Params: o = Object instance.
export
void adbg_object_close(adbg_object_t *o) {
	if (o == null)
		return;
	
	if (o.func_unload) o.func_unload(o);
	
	if (o.file) osfclose(o.file);
	
	free(o);
}

/// Read data from object at the current position.
/// Params:
/// 	o = Object instance.
/// 	buffer = Buffer pointer.
/// 	rdsize = Size to read.
/// 	flags = Additional settings.
/// Returns: Error code if set.
int adbg_object_read(adbg_object_t *o, void *buffer, size_t rdsize, int flags = 0) {
	version (Trace) trace("buffer=%p rdsize=%zu", buffer, rdsize);
	
	if (o == null || buffer == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (rdsize == 0)
		return 0;
	
	version (Trace) trace("origin=%d", o.origin);
	switch (o.origin) with (AdbgObjectOrigin) {
	case disk:
		int r = osfread(o.file, buffer, cast(int)rdsize);
		version (Trace) trace("osfread=%d", r);
		if (r < 0)
			return adbg_oops(AdbgError.os);
		if (r < rdsize)
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

/// Read data from object from absolute position.
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

/// Allocate a buffer with read size, and read data from object from absolute position.
///
/// On error, this function automatically frees the buffer.
/// Params:
/// 	o = Object instance.
/// 	location = Absolute file offset.
/// 	rdsize = Size to read.
/// 	flags = Additional settings.
/// Returns: Null pointer on error.
void* adbg_object_readalloc_at(adbg_object_t *o, long location, size_t rdsize, int flags = 0) {
	version (Trace) trace("location=%lld rdsize=%zx", location, rdsize);
	
	if (o == null || rdsize == 0) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	void *buffer = malloc(rdsize);
	if (buffer == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Function sets error
	if (adbg_object_read_at(o, location, buffer, rdsize, flags)) {
		free(buffer);
		return null;
	}
	
	return buffer;
}

/// Size of signature buffer.
private enum SIGMAX = MAX!(PDB20_MAGIC.length, PDB70_MAGIC.length);

/// Used in signature detection.
private
union SIGNATURE {
	ubyte[SIGMAX] buffer;
	ulong u64;
	uint u32;
	ushort u16;
	ubyte u8;
	mz_header_t mzheader;
}

// Object detection and loading
private
int adbg_object_loadv(adbg_object_t *o) {
	if (o == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	o.status = 0;
	
	// Load enough for signature detection
	SIGNATURE sig = void;
	int siglen = osfread(o.file, &sig, SIGNATURE.sizeof); /// signature size
	version (Trace) trace("siglen=%d sigmax=%u", siglen, cast(uint)SIGMAX);
	if (siglen < 0)
		return adbg_oops(AdbgError.os);
	if (siglen <= uint.sizeof)
		return adbg_oops(AdbgError.objectTooSmall);
	if (osfseek(o.file, 0, OSFileSeek.start) < 0) // Reset offset, test seek
		return adbg_oops(AdbgError.os);
	
	// Magic detection over 8 Bytes
	if (siglen > PDB20_MAGIC.length &&
		memcmp(sig.buffer.ptr, PDB20_MAGIC.ptr, PDB20_MAGIC.length) == 0)
		return adbg_object_pdb20_load(o);
	if (siglen > PDB70_MAGIC.length &&
		memcmp(sig.buffer.ptr, PDB70_MAGIC.ptr, PDB70_MAGIC.length) == 0)
		return adbg_object_pdb70_load(o);
	
	// 64-bit signature detection
	version (Trace) trace("u64=%#llx", sig.u64);
	if (siglen > ulong.sizeof) switch (sig.u64) {
	case AR_MAGIC:
		return adbg_object_ar_load(o);
	case PAGEDUMP32_MAGIC, PAGEDUMP64_MAGIC:
		return adbg_object_dmp_load(o);
	default:
	}
	
	// 32-bit signature detection
	version (Trace) trace("u32=%#x", sig.u32);
	if (siglen > uint.sizeof) switch (sig.u32) {
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
	if (siglen > ushort.sizeof) switch (sig.u16) {
	// Anonymous MSCOFF
	case 0:
		if (siglen > uint.sizeof && (sig.u32 >> 16) == 0xffff)
			return adbg_object_mscoff_load(o);
		break;
	// MZ executables
	case MAGIC_MZ, MAGIC_ZM: // ZM being the even older signature in some cases
		// TODO: Move new header detection to MZ load function
		// TODO: pre-checked if only the signature is swapped
		version (Trace) trace("e_lfarlc=%#x", sig.mzheader.e_lfarlc);
		
		// If e_lfarlc (relocation table) starts lower than e_lfanew,
		// then assume old MZ.
		// NOTE: e_lfarlc can point to 0x40.
		if (sig.mzheader.e_lfarlc < 0x40)
			return adbg_object_mz_load(o);
		
		// If e_lfanew points within (extended) MZ header
		if (sig.mzheader.e_lfanew <= mz_header_t.sizeof)
			return adbg_object_mz_load(o);
		
		// ReactOS checks if NtHeaderOffset is not higher than 256 MiB.
		// See: sdk/lib/rtl/image.c:RtlpImageNtHeaderEx
		//TODO: Consider if object malformed.
		if (sig.mzheader.e_lfanew >= MiB!256)
			return adbg_object_mz_load(o);
		
		uint newsig = void;
		if (adbg_object_read_at(o, sig.mzheader.e_lfanew, &newsig, uint.sizeof))
			return adbg_errno();
		
		// 32-bit signature check
		version (Trace) trace("newsig=%#x", newsig);
		switch (newsig) {
		case MAGIC_PE32:
			return adbg_object_pe_load(o, &sig.mzheader);
		default:
		}
		
		// 16-bit signature check
		switch (cast(ushort)newsig) {
		case NE_MAGIC:
			return adbg_object_ne_load(o, &sig.mzheader);
		case LX_MAGIC, LE_MAGIC:
			return adbg_object_lx_load(o, &sig.mzheader);
		default:
		}
		
		// If nothing matches, assume MZ
		return adbg_object_mz_load(o);
	// COFF magics
	case COFF_MAGIC_I386:
	case COFF_MAGIC_I386_AIX:
	case COFF_MAGIC_AMD64:
	case COFF_MAGIC_IA64:
	case COFF_MAGIC_Z80:
	case COFF_MAGIC_MSP430:
	case COFF_MAGIC_TMS470:
	case COFF_MAGIC_TMS320C2800:
	case COFF_MAGIC_TMS320C5400:
	case COFF_MAGIC_TMS320C5500:
	case COFF_MAGIC_TMS320C5500P:
	case COFF_MAGIC_TMS320C6000:
	case COFF_MAGIC_MIPSEL:
		return adbg_object_coff_load(o);
	default:
	}
	
	// 8-bit signature detection
	version (Trace) trace("u8=%#x", sig.u8);
	switch (sig.u8) {
	case OMFRecord.LIBRARY: // OMF library header entry
	case OMFRecord.THEADR:  // First OMF object entry of THEADR
	case OMFRecord.LHEADR:  // First OMF object entry of LHEADR
		return adbg_object_omf_load(o, sig.u8);
	default:
	}
	
	return adbg_oops(AdbgError.objectUnknownFormat);
}

/// Add a search parameter query to adbg_object_search_section.
enum AdbgObjectSearch {
	/// Get section exactly by this name. Case-sensitive.
	/// Type: Null terminated string pointer (char*).
	/// Default: null
	exactName = 1,
}

// TODO: Flags: Contains (default: exact), case insensitive, executable only, etc.
// TODO: unix archives (ar), by member name
// TODO: Search Address: if address >= sectionAddress && address < sectionAddress + sectionSize

/// Search and obtain one section from query.
/// Params:
/// 	o = Object instance.
/// 	... = Search parameters (see AdbgObjectSearch).
/// Returns: Allocated section instance.
adbg_section_t* adbg_object_search_section(adbg_object_t *o, ...) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	va_list list = void;
	va_start(list, o);
	
	const(char) *name;
Loption:
	switch (va_arg!int(list)) with (AdbgObjectSearch) {
	case 0: break;
	case exactName:
		name = va_arg!(const(char)*)(list);
		if (name == null) {
			adbg_oops(AdbgError.invalidValue);
			return null;
		}
		goto Loption;
	default:
		adbg_oops(AdbgError.invalidOption);
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
			if (name && strncmp(name, s.Name.ptr, s.Name.sizeof) == 0) {
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
					
					if (name && strncmp(name, s64.sectname.ptr, s64.sectname.sizeof) == 0) {
						section_header = s64;
						section_header_size = macho_section64_t.sizeof;
						section_offset = s64.offset;
						section_size = cast(size_t)s64.size;
						break MACHO_FOR;
					}
				} else { // 32-bit
					macho_section_t *s32 = cast(macho_section_t*)s;
				
					if (name && strncmp(name, s32.sectname.ptr, s32.sectname.sizeof) == 0) {
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
				const(char) *secname = adbg_object_elf_shdr32_name(o, s);
				if (secname == null)
					continue;
				if (name && strcmp(name, secname) == 0) {
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
				const(char) *secname = adbg_object_elf_shdr64_name(o, s);
				if (secname == null)
					continue;
				if (name && strcmp(name, secname) == 0) {
					section_header = s;
					section_header_size = Elf32_Shdr.sizeof;
					section_offset = s.sh_offset;
					section_size = cast(size_t)s.sh_size;
					break;
				}
			}
			break;
		default:
			adbg_oops(AdbgError.objectInvalidClass);
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

void adbg_object_section_close(adbg_object_t *o, adbg_section_t *section) {
	if (section == null)
		return;
	free(section);
}

/// Get the size of the object. Only applies for objects loaded from disks.
/// Params: o = Object instance.
/// Returns: Size in bytes, or -1 on error.
long adbg_object_filesize(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	if (o.file == null) {
		adbg_oops(AdbgError.uninitiated);
		return -1;
	}
	if (o.origin != AdbgObjectOrigin.disk) {
		adbg_oops(AdbgError.unavailable);
		return -1;
	}
	
	return osfsize(o.file);
}

/// Returns the first machine type the object supports.
/// Params: o = Object instance.
/// Returns: Machine value.
AdbgMachine adbg_object_machine(adbg_object_t *o) {
	if (o == null)
		return AdbgMachine.unknown;
	
	// TODO: Turn to function pointer
	switch (o.format) with (AdbgObject) {
	case mz:	return AdbgMachine.i8086;
	case ne:	return adbg_object_ne_machine(o);
	case lx:	return adbg_object_lx_machine(o);
	case pe:	return adbg_object_pe_machine(o);
	case macho:	return adbg_object_macho_machine(o);
	case elf:	return adbg_object_elf_machine(o);
	case coff:	return adbg_object_coff_machine(o);
	// TODO: For UNIX archives, get first object and return machine of sub object instance
	default:
	}
	return AdbgMachine.unknown;
}
const(char)* adbg_object_machine_string(adbg_object_t *o) {
	return adbg_machine_name( adbg_object_machine(o) );
}

/// Get the short name of the loaded object type.
/// Params: o = Object instance.
/// Returns: Object type name.
export
const(char)* adbg_object_type_shortname(adbg_object_t *o) {
	if (o == null)
		goto Lunknown;
	//TODO: Consider merging pdb20 and pdb70 to only "pdb"
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
	case elf:	return adbg_object_elf_kind_string(o);
	case pdb20, pdb70:	return `Debug Database`;
	case mdmp, dmp:	return `Memory Dump`;
	case archive, mscoff:	return `Library`;
	case omf:	return adbg_object_omf_is_library(o) ? `Library` : `Object`;
	case coff:	return `Object`;
	default:
	}
	return null;
}