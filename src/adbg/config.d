/// Project build configuration.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.config;

//
//
//

enum AdbgConfigDisasm {
	builtin,
	capstone,
	//zydis,
}

//
//
//

/// Use the crappy built-in disassembler.
/// Default: false
enum AdbgConfigDisasm CONFIG_DISASM = AdbgConfigDisasm.capstone;

