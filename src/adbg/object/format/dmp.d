/// Windows full memory dump format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.object.format.dmp;

import adbg.error;
import adbg.object.server : adbg_object_t, AdbgObject;
import adbg.utils.bit;

// Sources:
// - https://github.com/volatilityfoundation/volatility/

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
struct dmp_header {
	union {
		/// Contains "PAGE"
		char[4] Signature;
		/// Ditto
		uint SignatureInt;
	}
	union {
		/// Contains "DUMP" or "DU64"
		char[4] ValidDump;
		/// Ditto
		uint ValidDumpInt;
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
static assert(dmp_header.KdDebuggerDataBlock.offsetof == 0x60);

/// 64-bit Windows crash dump header.
struct dmp64_header {
	union {
		/// Contains "PAGE"
		char[4] Signature;
		/// Ditto
		uint SignatureInt;
	}
	union {
		/// Contains "DUMP" or "DU64"
		char[4] ValidDump;
		/// Ditto
		uint ValidDumpInt;
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
static assert(dmp64_header.MachineImageType.offsetof == 0x30);
static assert(dmp64_header.BugCheckParameters.offsetof == 0x40);
static assert(dmp64_header.KdDebuggerDataBlock.offsetof == 0x80);

int adbg_object_dmp_load(adbg_object_t *o) {
	o.format = AdbgObject.dmp;
	return 0;
}