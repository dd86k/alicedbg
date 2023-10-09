/// Experimental: Project build and internal configurations.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.config;

//TODO: Typically, should be dicdacted by defined Versions
//      e.g., USE_CAPSTONE/AdbgUseCapstone (you get the idea)

// Temprary until I think of something better
enum AdbgConfigDisasm {
	builtin,
	capstone,
	//zydis,
}

/// Choose disassembler engine
enum AdbgConfigDisasm CONFIG_DISASM = AdbgConfigDisasm.capstone;