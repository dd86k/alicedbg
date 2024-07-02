/// Windows full memory dump format.
///
/// Sources:
/// - https://github.com/volatilityfoundation/volatility/
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

/// 
enum PAGEDUMP32_MAGIC = CHAR64!"PAGEDUMP";
/// 
enum PAGEDUMP64_MAGIC = CHAR64!"PAGEDU64";
/// 
enum PAGEDUMP32_VALID = CHAR32!"DUMP";
/// 
enum PAGEDUMP64_VALID = CHAR32!"DU64";

enum PAGEDUMP32_HEADERSIZE = 0x1000;
enum PAGEDUMP64_HEADERSIZE = 0x2000;

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
	union {
		char[4] Unused;
		/// For 32-bit dumps, this indicates if PAE is enabled.
		ubyte PaeEnabled;
	}
	/// Virtual address of KdDebuggerDataBlock structure
	uint KdDebuggerDataBlock; // 32-bit: 0x60
	// _PHYSICAL_MEMORY_DESCRIPTOR PhysicalMemoryBlockBuffer;
}
static assert(dmp32_header_t.KdDebuggerDataBlock.offsetof == 0x60);

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
	uint DirectoryTableBase;
	/// PFN Database, virtual address
	uint PfnDatabase;
	/// List of loaded modules, virtual address
	uint PsLoadedModuleList;
	/// List of active process, virtual address
	uint PsActiveProcessHead; // 0x18
	/// 
	char[16] Unknown3;
	/// WinNT Machine values, same found in PE32
	uint MachineImageType; // 0x30
	/// Number of processors.
	uint NumberProcessors;
	/// Stop code
	uint BugCheckCode; // 0x38
	/// 
	uint Unknown4;
	/// Stop code parameters, from 1 to 4.
	uint[4] BugCheckParameters; // 0x40
	/// 
	char[48] VersionUser;
	/// For 64-bit dumps, virtual address of KdDebuggerDataBlock structure
	ulong KdDebuggerDataBlock; // 64-bit: 0x80
	// _PHYSICAL_MEMORY_DESCRIPTOR PhysicalMemoryBlockBuffer;
}
static assert(dmp64_header_t.MachineImageType.offsetof == 0x30);
static assert(dmp64_header_t.BugCheckParameters.offsetof == 0x40);
static assert(dmp64_header_t.KdDebuggerDataBlock.offsetof == 0x80);

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
	
	o.format = AdbgObject.dmp;
	
	internal_dmp_t *internal = cast(internal_dmp_t*)o.internal;
	
	// NOTE: This avoids a check and a cast for _dmp_is_64bit
	o.status |= internal.header32.ValidDump32 == PAGEDUMP64_VALID ? DUMP_64BIT : 0;
	return 0;
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
