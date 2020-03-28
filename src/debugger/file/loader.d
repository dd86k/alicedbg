/**
 * Executable image loader.
 *
 * License: BSD 3-Clause
 */
module debugger.file.loader;

import core.stdc.stdio;
import debugger.disasm.core : DisasmISA; // ISA translation
private import debugger.file.objs;
import os.err;

extern (C):

/// File operation error code
enum FileError {
	/// Operating was a success, so no error occurred
	None,
	/// Operation error (e.g. can't seek, can't read)
	Operation,
	/// Format not supported
	Unsupported,
	/// Requested action/feature is not available (from file)
	NotAvailable,
	/// Symbol location not found
	NotFound,
}

/// Loaded, or specified, executable/object format
enum FileType {
	/// Mysterious file format
	Unknown,
	/// Mark Zbikowski format
	MZ,
	/// New Executable format
	NE,
	/// LE/LX
	LE,
	/// Portable Executable format
	PE,
	/// Executable and Linkable Format
	ELF,
	/// Mach Object format
	MachO,
}

/// Executable file information and headers
//TODO: Field saying if image or object?
struct file_info_t {
	/// File handle, used internally.
	FILE *handle;
	/// File type, populated by the respective loading function.
	FileType type;
	/// Unset for little, set for big. Used in cswap functions.
	int endian;
	/// Image's ISA translated value for disasm
	DisasmISA isa;
	//
	// Internal fields
	//
	union {
		file_info_pe_t pe;	/// PE headers
	}
}
struct file_info_pe_t { // PE32
	PE_HEADER hdr;
	union {
		PE_OPTIONAL_HEADER ohdr;
		PE_OPTIONAL_HEADER64 ohdr64;
		PE_OPTIONAL_HEADERROM ohdrrom;
	}
	PE_IMAGE_DATA_DIRECTORY dir;
}

/// Load an executable or object file from path. Uses FILE. If you see
/// an executable image larger than 2 GiB, do let me know.
/// Params:
/// 	path = File path
/// 	info = file_info_t structure
/// 	flags = Load options (placeholder)
/// Returns: OS error code or a FileError on error
int file_load(FILE *file, file_info_t *info, int flags) {
	if (file == null)
		return FileError.Operation;
	info.handle = file;

	//
	// Auto-detection
	//

	info.type = FileType.Unknown;
	file_sig_t sig = void;
	if (fread(&sig, 4, 1, info.handle) == 0)
		return FileError.Operation;

	switch (sig.u16[0]) {
	case SIG_MZ: // 'ZM' files exist, but very rare (MSDOS 2 era)
		if (fseek(info.handle, 0x3C, SEEK_SET))
			return FileError.Operation;
		uint hdrloc = void;
		if (fread(&hdrloc, 4, 1, info.handle) == 0)
			return FileError.Operation;
		if (fseek(info.handle, hdrloc, SEEK_SET))
			return FileError.Operation;
		if (fread(&sig, 4, 1, info.handle) == 0)
			return FileError.Operation;
		switch (sig.u16[0]) {
		case SIG_PE:
			if (sig.u16[1]) // "PE\0\0"
				return FileError.Unsupported;
			return file_load_pe(info);
		default: // MZ
			return FileError.Unsupported;
		}
/*	case SIG_ELF_L:
	
		break;*/
	default:
		return FileError.Unsupported;
	}
}

int file_cmp_section(const(char)* sname, int ssize, const(char) *tname) {
	import core.stdc.string : strncmp;
	return strncmp(sname, tname, ssize) == 0;
}

//const(char) *file_err(FileError)
//const(char) *file_type_string(FileType t)
//uint file_section_fo(file_info_t*,const(char)*)

private:

version (LittleEndian) {
	enum ushort SIG_MZ = 0x5A4D;	// "MZ"
	enum ushort SIG_PE = 0x4550;	// "PE"
	enum ushort SIG_ELF_L = 0x4C45; // "EL", low 2-byte
	enum ushort SIG_ELF_H = 0x7F46; // "F\x7F", high 2-byte
} else {
	enum ushort SIG_MZ = 0x4D5A;	// "MZ"
	enum ushort SIG_PE = 0x5045;	// "PE"
	enum ushort SIG_ELF_L = 0x454C; // "EL", low 2-byte
	enum ushort SIG_ELF_H = 0x467F; // "F\x7F", high 2-byte
}

struct file_sig_t { align(1):
	union {
		uint u32;
		char[4] c8;
		ushort[2] u16;
	}
}