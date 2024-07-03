/// Windows full memory dump format.
///
/// Sources:
/// - https://github.com/volatilityfoundation/volatility/
/// - Windows Kits\10\Include\10.0.22621.0\um\mindumpdef.h
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.format.dmp;

import adbg.error;
import adbg.object.server;
import adbg.utils.bit;
import adbg.utils.math : MAX;
import core.stdc.stdlib;

extern (C):

/// 
enum PAGEDUMP32_MAGIC = CHAR64!"PAGEDUMP";
/// 
enum PAGEDUMP64_MAGIC = CHAR64!"PAGEDU64";
/// 
enum PAGEDUMP32_VALID = CHAR32!"DUMP";
/// 
enum PAGEDUMP64_VALID = CHAR32!"DU64";

//enum PAGEDUMP32_HEADERSIZE = 0x1000;
//enum PAGEDUMP64_HEADERSIZE = 0x2000;

private enum DMP_PHYSICAL_MEMORY_BLOCK_SIZE_32   = 700;
private enum DMP_CONTEXT_RECORD_SIZE_32          = 1200;
private enum DMP_RESERVED_0_SIZE_32              = 1760;
private enum DMP_RESERVED_2_SIZE_32              = 16;
private enum DMP_RESERVED_3_SIZE_32              = 56;

private enum DMP_PHYSICAL_MEMORY_BLOCK_SIZE_64   = 700;
private enum DMP_CONTEXT_RECORD_SIZE_64          = 3000;
private enum DMP_RESERVED_0_SIZE_64              = 4008;

private enum DMP_HEADER_COMMENT_SIZE             = 128;

alias DUMP_TYPES = int;
enum {
	DUMP_TYPE_INVALID           = -1,
	DUMP_TYPE_UNKNOWN           = 0,
	DUMP_TYPE_FULL              = 1,
	DUMP_TYPE_SUMMARY           = 2,
	DUMP_TYPE_HEADER            = 3,
	DUMP_TYPE_TRIAGE            = 4,
	DUMP_TYPE_BITMAP_FULL       = 5,
	DUMP_TYPE_BITMAP_KERNEL     = 6,
	DUMP_TYPE_AUTOMATIC         = 7
}

// _DUMP_FILE_ATTRIBUTES
enum : uint {
	HiberCrash = BIT!0,
	DumpDevicePowerOff = BIT!1,
	InsufficientDumpfileSize = BIT!2,
	KernelGeneratedTriageDump = BIT!3,
	LiveDumpGeneratedDump = BIT!4,
	DumpIsGeneratedOffline = BIT!5,
	FilterDumpFile = BIT!6,
	EarlyBootCrash = BIT!7,
	/// If below flag is set, it means Dump data (i.e. non-secureheader data)
	/// is encrypted, and Secure header is in use
	EncryptedDumpData = BIT!8,
	/// Below flag would be set by dump decryption software to indicate that
	/// the dump was originally encrypted and current dump is obtained after
	/// decryption of the original dump data.
	DecryptedDump = BIT!9,
}

private enum EXCEPTION_MAXIMUM_PARAMETERS = 15; // maximum number of exception parameters

struct EXCEPTION_RECORD32 { align(1):
	uint ExceptionCode;
	uint ExceptionFlags;
	uint ExceptionRecord;
	uint ExceptionAddress;
	uint NumberParameters;
	uint[EXCEPTION_MAXIMUM_PARAMETERS] ExceptionInformation;
}

struct EXCEPTION_RECORD64 { align(1):
	uint ExceptionCode;
	uint ExceptionFlags;
	ulong ExceptionRecord;
	ulong ExceptionAddress;
	uint NumberParameters;
	uint __unusedAlignment;
	ulong[EXCEPTION_MAXIMUM_PARAMETERS] ExceptionInformation;
}

struct dmp32_physical_memory_run_t {
	uint BasePage;
	uint PageCount;
}
struct dmp32_physical_memory_descriptor_t {
	ulong NumberOfRuns;
	ulong NumberOfPages;
	dmp32_physical_memory_run_t[1] Run;
}

/// Windows crash dump header.
struct dmp32_header_t {
	union {
		/// Contains "PAGE"
		char[4] Signature;
		/// Ditto
		uint Signature32;
	}
	union {
		/// Contains "DUMP" or "DU64"
		char[4] ValidDump;
		/// Ditto
		uint ValidDump32;
	}
	/// 0xf for a Free build or 0xc for a Checked build
	uint MajorVersion;
	/// System build number
	uint MinorVersion;
	/// x86: Value of CR3 on crash, physical address of page directory 
	uint DirectoryTableBase;
	/// PFN Database, virtual address
	uint PfnDatabase;
	/// List of loaded modules, virtual address
	uint PsLoadedModuleList;
	/// List of active process, virtual address
	uint PsActiveProcessHead;
	/// WinNT Machine values, same found in PE32
	uint MachineImageType;
	/// Number of processors.
	uint NumberProcessors;
	/// Stop code
	uint BugCheckCode;
	/// Stop code parameters, from 1 to 4.
	uint[4] BugCheckParameters;
	/// 
	char[32] VersionUser;
	/// For 32-bit dumps, this indicates if PAE is enabled.
	ubyte PaeEnabled; // Present only for Win2k and better
	ubyte KdSecondaryVersion; // // Present only for W2K3 SP1 and better
	ubyte[2] Spare3;
	/// Virtual address of KdDebuggerDataBlock structure
	uint KdDebuggerDataBlock; // 32-bit: 0x60, Present only for Win2k SP1 and better.
	
	union {
		dmp32_physical_memory_descriptor_t PhysicalMemoryBlock;
		ubyte[DMP_PHYSICAL_MEMORY_BLOCK_SIZE_32] PhysicalMemoryBlockBuffer;
	}
	
	// NOTE: Rest of fields are inconsistent with actual dumps
	
	ubyte[DMP_CONTEXT_RECORD_SIZE_32] ContextRecord;
	EXCEPTION_RECORD32 Exception;
	char[DMP_HEADER_COMMENT_SIZE] Comment;
	uint Attributes;
	uint BootId;
	ubyte[DMP_RESERVED_0_SIZE_32] _reserved0;
	uint DumpType;	// Present for Win2k and better.
	uint MiniDumpFields;
	uint SecondaryDataState;
	uint ProductType;
	uint SuiteMask;
	uint WriterStatus;
	ulong RequiredDumpSpace; // LARGE_INTEGER
	ubyte[DMP_RESERVED_2_SIZE_32] _reserved2;
	ulong SystemUpTime;	// Present only for Whistler and better.
	ulong SystemTime;	// Present only for Win2k and better.
	ubyte[DMP_RESERVED_3_SIZE_32] _reserved3;
}
static assert(dmp32_header_t.KdDebuggerDataBlock.offsetof == 0x60);

struct dmp64_physical_memory_run64_t {
	ulong BasePage;
	ulong PageCount;
}

struct dmp64_physical_memory_descriptor64_t {
    uint NumberOfRuns;
    ulong NumberOfPages;
    dmp64_physical_memory_run64_t[1] Run;
}

/// 64-bit Windows crash dump header.
struct dmp64_header_t {
	union {
		/// Contains "PAGE"
		char[4] Signature;
		/// Ditto
		uint Signature32;
	}
	union {
		/// Contains "DUMP" or "DU64"
		char[4] ValidDump;
		/// Ditto
		uint ValidDump32;
	}
	/// 0xf for a Free build or 0xc for a Checked build
	uint MajorVersion;
	/// System build number
	uint MinorVersion;
	/// x86: Value of CR3 on crash, physical address of page directory 
	ulong DirectoryTableBase;
	/// PFN Database, virtual address
	ulong PfnDatabase;
	/// List of loaded modules, virtual address
	ulong PsLoadedModuleList;
	/// List of active process, virtual address
	ulong PsActiveProcessHead; // 0x18
	/// WinNT Machine values, same found in PE32
	uint MachineImageType; // 0x30
	/// Number of processors.
	uint NumberProcessors;
	/// Stop code
	uint BugCheckCode; // 0x38
	/// Stop code parameters, from 1 to 4.
	uint[4] BugCheckParameters; // 0x40
	/// 
	char[32] VersionUser;
	/// For 64-bit dumps, virtual address of KdDebuggerDataBlock structure
	ulong KdDebuggerDataBlock; // 64-bit: 0x80
	
	union {
		dmp64_physical_memory_descriptor64_t PhysicalMemoryBlock;
		ubyte[DMP_PHYSICAL_MEMORY_BLOCK_SIZE_64] PhysicalMemoryBlockBuffer;
	}
	
	// NOTE: Rest of fields are inconsistent with actual dumps
	
	ubyte[DMP_CONTEXT_RECORD_SIZE_64] ContextRecord;
	EXCEPTION_RECORD64 Exception;
	uint DumpType;
	ulong RequiredDumpSpace;
	ulong SystemTime;
	char[DMP_HEADER_COMMENT_SIZE] Comment;   // May not be present.
	ulong SystemUpTime;
	uint MiniDumpFields;
	uint SecondaryDataState;
	uint ProductType;
	uint SuiteMask;
	uint WriterStatus;
	ubyte Unused1;
	ubyte KdSecondaryVersion;       // Present only for W2K3 SP1 and better
	ubyte[2] Unused;
	uint Attributes;
	ulong BootId;
	ubyte[DMP_RESERVED_0_SIZE_64] _reserved0;
}

private
struct internal_dmp_t {
	union {
		dmp32_header_t header32;
		dmp64_header_t header64;
	}
}

private enum {
	DUMP_64BIT = 1 << 16
}

int adbg_object_dmp_load(adbg_object_t *o) {
	o.internal = calloc(1, internal_dmp_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	if (adbg_object_read_at(o, 0, o.internal, MAX!(dmp32_header_t.sizeof, dmp64_header_t.sizeof))) {
		free(o.internal);
		return adbg_errno();
	}
	
	adbg_object_postload(o, AdbgObject.dmp, &adbg_object_dmp_unload);
	
	internal_dmp_t *internal = cast(internal_dmp_t*)o.internal;
	
	// NOTE: This avoids a check and a cast for _dmp_is_64bit
	o.status |= internal.header32.ValidDump32 == PAGEDUMP64_VALID ? DUMP_64BIT : 0;
	return 0;
}
void adbg_object_dmp_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
//	internal_dmp_t *internal = cast(internal_dmp_t*)o.internal;
	
	free(o.internal);
}

int adbg_object_dmp_is_64bit(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	return o.status & DUMP_64BIT;
}

void* adbg_object_dmp_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	return &(cast(internal_dmp_t*)o.internal).header32;
}

const(char)* adbg_object_dmp_dumptype_string(uint type) {
	switch (type) {
	case DUMP_TYPE_FULL:	return "FULL";
	case DUMP_TYPE_SUMMARY:	return "SUMMARY";
	case DUMP_TYPE_HEADER:	return "HEADER";
	case DUMP_TYPE_TRIAGE:	return "TRIAGE";
	case DUMP_TYPE_BITMAP_FULL:	return "BITMAP_FULL";
	case DUMP_TYPE_BITMAP_KERNEL:	return "BITMAP_KERNEL";
	case DUMP_TYPE_AUTOMATIC:	return "AUTOMATIC";
	default:	return null;
	}
}
