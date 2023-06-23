/// Experimental: Project build and internal configurations.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.config;

//TODO: Think of _LIB/_DYN build variants

// Temprary until I think of something better
enum AdbgConfigDisasm {
	builtin,
	capstone,
	//zydis,
}

//
//
//

/// Choose disassembler engine
enum AdbgConfigDisasm CONFIG_DISASM = AdbgConfigDisasm.capstone;

enum bool USE_CAPSTONE = CONFIG_DISASM == AdbgConfigDisasm.capstone;