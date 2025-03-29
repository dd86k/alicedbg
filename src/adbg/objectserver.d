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

import adbg.symbols;
import adbg.types.coff : adbg_type_coff_populate;
import adbg.process.memory : adbg_memory_read;
import adbg.process.base : adbg_process_t;
import adbg.error;
import adbg.machines;
import adbg.utils.math;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import adbg.os.file;
import adbg.objects;
import adbg.utils.list;
import core.stdc.string;

extern (C):

// NOTE: For object submodule implementations.
//
//       Function names
//         At best, prefer adbg_object_OBJECT_xyz where OBJECT is the type
//         (e.g., pe, elf, etc.) to make things consistent. This is why
//         main function names are simply "adbg_object_offset", for example.
//
//       Performance
//         Load and keep only necessary information in memory, like the sectiontable,
//         when possible can greatly accelerate a lot of the operations,
//         including section searches, but should only be allocated on-demand.
//         Headers, program headers, and sections usually should be read when
//         loading a new object instance.

// TODO: Clean the section search functions
// TODO: Consider structure definition, using a template
//       Uses:
//       - For swapping, uses less code than inlining it
//       - For displaying and using field offsets
// TODO: adbg_object_endianness
//       Why? Machine module do not include endianness.
//       And would be beneficial when host has incompatible or both endianness.
// TODO: adbg_object_open_process(int pid, ...)
// TODO: adbg_object_origin_string(adbg_object_t *o)
//       Return string of how object was loaded, mainly for tracing purposes
// TODO: Load debugging object
//       Attach debug object instance to this one. Likely to be used internally for stuff
//       like getting symbols off memory addresses.
//       PE32:
//       - Load PDB from debug entry (absolute path or try relatively with same folder)
//       ELF:
//       - DWARF (".debug_info" and others)
//       - Compact C type Format (CTF, ".ctf"): https://github.com/lovasko/libctf
//       - BPF Type Format (BTF)
//       Mach-O:
//       - uuid_command points to dSYM file
// TODO: Promote "readalloc_at" over "malloc+read" to aid small object optimization

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
	/// Microsoft Program Database format (.pdb)
	pdb,
	/// Windows memory dump format. (.dmp)
	dmp,
	/// Windows Minidump format. (.mdmp)
	mdmp,
	/// OMF object or library. (.obj, .lib)
	omf,
	/// UNIX Library archive. (.lib, .a)
	archive,
	/// COFF object or executable. (.obj)
	coff,
	/// Anonymous COFF object. (.obj)
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
	/// Object is a whole buffer provided externally.
	buffer,
}

deprecated
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

// TODO: All fields should be made private
/// Represents a file object image.
///
/// All fields are used internally and should not be used directly.
struct adbg_object_t {
	private union {
		struct { // opened as file
			OSFILE *file;
		}
		struct { // opened as process
			adbg_process_t *process;
			size_t proc_location;
		}
		struct { // opened as user buffer
			void *user_buffer;
			size_t user_buffersize;
			size_t user_location;
		}
	}
	private:
	
	/// Object's loading origin.
	///
	/// Stuff like disk or in-memory, allowing to select which I/O functions
	/// to be used when interacting with its source material.
	AdbgObjectOrigin origin;
	/// Loaded object format.
	AdbgObject format;
	/// Internal buffer used by the module responsible of handling
	/// the specific object format.
	void *modbuffer;
	// TODO: Event: When closing
	void function(adbg_object_t*, void*) on_unload;
}

// TODO: "adbg_object_register" function to replace adbg_object_postload
//       Detection entry (inits):
//       - unique id (reuse AdbgObject? in case of replacing builtin functions)
//       - signatures/magics (position:size_t + data:ubyte[] or dataptr:void* + datasz:size_t)
//       Default types to be an immutable structure array.
//       Custom list to be allocated on new type registration.
//       Callback registration (in implementation):
//       - shortname (string or callback)
//       - fullname (string or callback)
//       - load (required)
//       - unload (required)
//       - machine type (optional)
//       - object type (optional)
//       - etc.
//         needs an API to set object type and other attributes

/// Open and load an object from disk into memory.
///
/// This function allocates memory.
/// Params:
///   path = File path.
///   ... = Options. Terminated with 0.
/// Returns: Object instance, or null on error.
export
adbg_object_t* adbg_object_open_file(const(char) *path, ...) {
	version (Trace) trace("path=%s", path);
	
	if (path == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	adbg_object_t *o = cast(adbg_object_t*)calloc(1, adbg_object_t.sizeof);
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
	
	// Check after loading
	version (Trace) if (o.func_unload == null)
		trace("WARNING: object type %d does not have unload function set", o.format);
	
	return o;
}

/*
adbg_object_t* adbg_object_open_process(int pid, ...) {
	version (Trace) trace("pid=%", buffer, buffersize);
	
}
*/

/// Open a new instance of an object from a buffer.
///
/// This is useful when extract binary load from an archive, like UNIX Archives,
/// where this function is used internally.
/// Params:
///   buffer = User buffer.
///   buffersize = The size of the buffer, in Bytes.
///   ... = Options. Terminated with 0.
/// Returns: Object instance, or null on error.
adbg_object_t* adbg_object_open_buffer(void *buffer, size_t buffersize, ...) {
	version (Trace) trace("buffer=%p buffersize=%zu", buffer, buffersize);
	
	if (buffer == null || buffersize == 0) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	adbg_object_t *o = cast(adbg_object_t*)calloc(1, adbg_object_t.sizeof);
	if (o == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	o.user_buffer = buffer;
	o.user_buffersize = buffersize;
	o.origin = AdbgObjectOrigin.buffer;
	
	if (adbg_object_loadv(o)) {
		adbg_object_close(o);
		return null;
	}
	
	version (Trace) if (o.func_unload == null)
		trace("NOTE: object type %s does not have unload function set",
			adbg_object_id_string(o));
	
	return o;
}

/// Close object instance.
/// Params: o = Object instance.
export
void adbg_object_close(adbg_object_t *o) {
	if (o == null)
		return;
	
	// Close internal buffer if set
	if (o.modbuffer) {
		// If close handler if set, call it so sub-module can close their buffers
		if (o.on_unload)
			o.on_unload(o, o.modbuffer);
		free(o.modbuffer);
	}
	
	// Close associated handles
	switch (o.origin) with (AdbgObjectOrigin) {
	case disk:
		if (o.file) osfclose(o.file);
		break;
	default:
	}
	
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
	
	if (o == null || buffer == null || rdsize == 0)
		return adbg_oops(AdbgError.invalidArgument);
	
	version (Trace) trace("origin=%d", o.origin);
	switch (o.origin) {
	case AdbgObjectOrigin.disk:
		int r = osfread(o.file, buffer, cast(int)rdsize); // updates file pos
		version (Trace) trace("osfread=%d", r);
		if (r < 0)
			return adbg_oops(AdbgError.os);
		if (r < rdsize)
			return adbg_oops(AdbgError.partialRead);
		return 0;
	case AdbgObjectOrigin.process:
		int e = adbg_memory_read(o.process, o.proc_location, buffer, rdsize);
		if (e == 0) o.proc_location += rdsize;
		return e;
	case AdbgObjectOrigin.buffer:
		if (o.user_location + rdsize >= o.user_buffersize)
			return adbg_oops(AdbgError.offsetBounds);
		if (memcpy(buffer, o.user_buffer + o.user_location, rdsize))
			return adbg_oops(AdbgError.crt);
		o.user_location += rdsize;
		return 0;
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
	
	if (o == null || buffer == null || rdsize == 0) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	
	switch (o.origin) {
	case AdbgObjectOrigin.disk:
		if (osfseek(o.file, location, OSFileSeek.start) < 0)
			return adbg_oops(AdbgError.os);
		break;
	case AdbgObjectOrigin.process:
		o.proc_location = cast(size_t)location;
		break;
	case AdbgObjectOrigin.buffer:
		o.user_location = cast(size_t)location;
		break;
	default:
		return adbg_oops(AdbgError.unimplemented);
	}
	
	return adbg_object_read(o, buffer, rdsize, flags);
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
	version (Trace) trace("location=%lld rdsize=%zu", location, rdsize);
	
	if (o == null || rdsize == 0)
		return adbg_oops_null(AdbgError.invalidArgument);
	
	void *buffer = malloc(rdsize);
	if (buffer == null)
		return adbg_oops_null(AdbgError.crt);
	
	// Function sets error
	if (adbg_object_read_at(o, location, buffer, rdsize, flags)) {
		free(buffer);
		return null;
	}
	
	return buffer;
}

// (Internal) Used by object implementations to setup internals.
package
int adbg_object_impl_setup(adbg_object_t *o,
	AdbgObject type,
	size_t size,
	void function(adbg_object_t*, void*) event_close) {
	if (o == null)
		return adbg_oops(AdbgError.assertion);
	
	if (size) {
		o.modbuffer = calloc(1, size);
		if (o.modbuffer == null)
			return adbg_oops(AdbgError.crt);
	}
	
	o.format = type;
	o.on_unload = event_close;
	return 0;
}

// (Internal) Get internal buffer pointer.
//
// Can be called as-is within implementations.
package
void* adbg_object_impl_get_buffer(adbg_object_t *o) {
	if (o == null)
		return adbg_oops_null(AdbgError.invalidArgument);
	if (o.modbuffer == null)
		return adbg_oops_null(AdbgError.uninitiated);
	return o.modbuffer;
}

/// Used in signature detection.
private
union SIGNATURE {
	// PDB 2.0 magic is 44 Bytes
	ubyte[44] buffer;
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
	
	// Read signature buffer for detection.
	// Unfortunately, this function fails if read bytes is less than
	// the size of the SIGNATURE structure.
	// Hopefully, not many files formats are that small.
	SIGNATURE sig = void;
	memset(&sig, 0, SIGNATURE.sizeof);
	int e = adbg_object_read_at(o, 0, &sig, SIGNATURE.sizeof);
	if (e) return e;
	
	// Magic detection over 8 Bytes
	if (memcmp(sig.buffer.ptr, PDB20_MAGIC.ptr, PDB20_MAGIC.length) == 0)
		return adbg_object_pdb20_load(o);
	if (memcmp(sig.buffer.ptr, PDB70_MAGIC.ptr, PDB70_MAGIC.length) == 0)
		return adbg_object_pdb70_load(o);
	
	// 64-bit signature detection
	version (Trace) trace("u64=%#llx", sig.u64);
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
		if ((sig.u32 >> 16) == 0xffff)
			return adbg_object_mscoff_load(o);
		break;
	
	// MZ executables
	case MAGIC_MZ, MAGIC_ZM: // ZM being the even older signature in some cases
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

/// Get the size of the object.
///
/// For local files, it is the filesize.
/// For user buffers, the buffer size.
/// Params: o = Object instance.
/// Returns: Size in bytes, or -1 on error.
long adbg_object_filesize(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	switch (o.origin) {
	case AdbgObjectOrigin.disk:
		if (o.file == null) {
			adbg_oops(AdbgError.uninitiated);
			return -1;
		}
		return osfsize(o.file);
	case AdbgObjectOrigin.buffer:
		// Verify overflow, size_t -> can lead to overflow due to sign
		long l = cast(long)o.user_buffersize;
		if ( l < 0 ) {
			adbg_oops(AdbgError.assertion);
			return -1;
		}
		return l;
	default:
		adbg_oops(AdbgError.unimplemented);
		return -1;
	}
}

// TODO: Deprecate adbg_object_machine for being ambiguous due to return value
/// Returns the first machine type the object supports.
/// Params: o = Object instance.
/// Returns: Machine value. `AdbgMachine.unknown` on error.
AdbgMachine adbg_object_machine(adbg_object_t *o) {
	if (o == null)
		return AdbgMachine.unknown;
	
	// TODO: For UNIX archives, get first object and return machine of sub object instance
	//       Would that really work, though?
	switch (o.format) with (AdbgObject) {
	case mz:	return AdbgMachine.i8086;
	case ne:	return adbg_object_ne_machine(o);
	case lx:	return adbg_object_lx_machine(o);
	case pe:	return adbg_object_pe_machine(o);
	case macho:	return adbg_object_macho_machine(o);
	case elf:	return adbg_object_elf_machine(o);
	case coff:	return adbg_object_coff_machine(o);
	case dmp:	return adbg_object_dmp_machine(o);
	default:
	}
	return AdbgMachine.unknown;
}

// TODO: adbg_object_machine_list, this function is temporary
/// Returns the first machine type the object supports.
/// Params: o = Object instance.
/// Returns: Machine definition instance. null on error.
immutable(adbg_machine_t)* adbg_object_machine2(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	AdbgMachine machine = void;
	switch (o.format) with (AdbgObject) {
	case mz:	machine = AdbgMachine.i8086; break;
	case ne:	machine = adbg_object_ne_machine(o); break;
	case lx:	machine = adbg_object_lx_machine(o); break;
	case pe:	machine = adbg_object_pe_machine(o); break;
	case macho:	machine = adbg_object_macho_machine(o); break;
	case elf:	machine = adbg_object_elf_machine(o); break;
	case coff:	machine = adbg_object_coff_machine(o); break;
	case dmp:	machine = adbg_object_dmp_machine(o); break;
	default:
		adbg_oops(AdbgError.objectUnsupportedFormat);
		return null;
	}
	
	return adbg_machine(machine);
}

/// Get the object format.
/// Params: o = Object instance.
/// Returns: Object format, see AdbgObject enum.
AdbgObject adbg_object_format(adbg_object_t *o) {
	return o ? o.format : AdbgObject.unknown;
}

/// Get a short identifying string ID for the object format.
///
/// Values:
/// - "mz"
/// - "ne"
/// - "lx"
/// - "pe"
/// - "macho"
/// - "elf"
/// - "pdb"
/// - "mdmp"
/// - "dmp"
/// - "omf"
/// - "archive"
/// - "coff"
/// - "mscoff"
/// - "unknown" (default or parameter is null)
/// Params: o = Object instance.
/// Returns: String pointer. It does not return null.
export
const(char)* adbg_object_id_string(adbg_object_t *o) {
	if (o == null)
		goto Lunknown;
	final switch (o.format) with (AdbgObject) {
	case mz:	return "mz";
	case ne:	return "ne";
	case lx:	return "lx";
	case pe:	return "pe";
	case macho:	return "macho";
	case elf:	return "elf";
	case pdb:	return "pdb";
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

// TODO: adbg_object_id_full: "fuller" id

/// Get the full name of the loaded object type.
///
/// Values:
/// - "Mark Zbikowski"
/// - "New Executable"
/// - "Linked Executable"
/// - "Portable Executable"
/// - "Mach-O"
/// - "Executable and Linkable Format"
/// - "Program Database"
/// - "Windows Minidump"
/// - "Windows Memory Dump"
/// - "Relocatable Object Module Format"
/// - "UNIX Library Archive"
/// - "Common Object File Format"
/// - "Big COFF Object"
/// - "Unknown" (default or parameter is null)
/// Params: o = Object instance.
/// Returns: Object type name.
export
const(char)* adbg_object_format_string(adbg_object_t *o) {
	if (o == null)
	Lunknown: return "Unknown";
	
	final switch (o.format) with (AdbgObject) {
	case mz:	return `Mark Zbikowski`;
	case ne:	return `New Executable`;
	case lx:	return `Linked Executable`;
	case pe:	return `Portable Executable`;
	case macho:	return `Mach-O`;
	case elf:	return `Executable and Linkable Format`;
	case pdb:	return `Program Database`;
	case mdmp:	return `Windows Minidump`;
	case dmp:	return `Windows Memory Dump`;
	case omf:	return `Relocatable Object Module Format`;
	case archive:	return `UNIX Library Archive`;
	case coff:	return `Common Object File Format`;
	case mscoff:	return `Big COFF Object`;
	case unknown:	goto Lunknown;
	}
}

/// Get the kind of object as a string for printing purposes.
///
/// Examples include "Memory Dump", "Object", "Library" (static), etc.
/// Params: o = Object instance.
/// Returns: String pointer or null on error.
const(char)* adbg_object_kind_string(adbg_object_t *o) {
	if (o == null)
		return cast(const(char)*)adbg_oops_null(AdbgError.invalidArgument);
	
	final switch (o.format) with (AdbgObject) {
	case mz:	return adbg_object_mz_kind_string(o);
	case ne:	return adbg_object_ne_kind_string(o);
	case lx:	return adbg_object_lx_kind_string(o);
	case pe:	return adbg_object_pe_kind_string(o);
	case macho:	return adbg_object_macho_kind_string(o);
	case elf:	return adbg_object_elf_kind_string(o);
	case pdb:	return `Debug Database`;
	case mdmp, dmp:	return `Memory Dump`;
	case archive, mscoff:	return `Library`;
	case omf:	return adbg_object_omf_is_library(o) ? `Library` : `Object`;
	case coff:	return `Object`;
	case unknown:
		return cast(const(char)*)adbg_oops_null(AdbgError.objectUnsupportedFormat);
	}
}

/// Get the ABI specified in the object.
/// Params: o = Object instance.
/// Returns: String pointer or null on error.
const(char)* adbg_object_osabi_string(adbg_object_t *o) {
	if (o == null)
		Lunknown: return null;
	final switch (o.format) with (AdbgObject) {
	case ne:
		ne_header_t *nehdr = adbg_object_ne_header(o);
		if (nehdr == null)
			goto Lunknown;
		return adbg_object_ne_type(nehdr.ne_exetyp);
	case lx:
		lx_header_t *lxhdr = adbg_object_lx_header(o);
		if (lxhdr == null)
			goto Lunknown;
		return adbg_object_lx_ostype_string(lxhdr.os);
	case pe:
		return adbg_object_pe_subsys_string(o);
	case macho:	return `macOS`;
	case elf:
		Elf32_Ehdr *ehdr = adbg_object_elf_ehdr32(o);
		if (ehdr == null)
			goto Lunknown;
		return adbg_object_elf_osabi_string(ehdr.e_ident[ELF_EI_OSABI]);
	case pdb, mdmp, dmp, omf, archive, coff, mscoff, mz:
	case unknown:	goto Lunknown;
	}
}

// Load list of symbols associated to object
adbg_symbol_list_t* adbg_object_load_symbols(adbg_object_t *o) {
	if (o == null)
		return cast(adbg_symbol_list_t*)adbg_oops_null(AdbgError.invalidArgument);
	
	adbg_symbol_list_t *symlist = adbg_symbol_list_create();
	if (symlist == null) // error already set
		return null;
	
	switch (o.format) {
	case AdbgObject.coff:
		if (adbg_type_coff_populate(symlist, o)) // sets error
			return null;
		return symlist;
	default:
		adbg_symbol_list_close(symlist);
		return cast(adbg_symbol_list_t*)adbg_oops_null(AdbgError.objectUnsupportedFormat);
	}
}