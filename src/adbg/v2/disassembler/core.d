module adbg.v2.disassembler.core;

import adbg.platform;
import adbg.include.capstone;

version (X86) { // CS_OPT_SYNTAX_DEFAULT
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_X86,	/// Platform default platform
		CS_DEFAULT_MODE = CS_MODE_32,	/// Platform default platform
	}
} else version (X86_64) {
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_X86,	/// Ditto
		CS_DEFAULT_MODE = CS_MODE_64,	/// Ditto
	}
} else version (Thumb) {
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_ARM,	/// Ditto
		CS_DEFAULT_MODE = CS_MODE_THUMB,	/// Ditto
	}
} else version (ARM) {
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_ARM,	/// Ditto
		CS_DEFAULT_MODE = CS_MODE_V8, // or CS_MODE_ARM?,	/// Ditto
	}
} else version (AArch64) {
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_ARM64,	/// Ditto
		CS_DEFAULT_MODE = CS_MODE_ARM,	/// Ditto
	}
} else version (RISCV32) {
	private enum {
		CS_DEFAULT_PLATFORM = -3,	/// Ditto
		CS_DEFAULT_MODE = -3,	/// Ditto
	}
} else version (RISCV64) {
	private enum {
		CS_DEFAULT_PLATFORM = -1,	/// Ditto
		CS_DEFAULT_MODE = -3,	/// Ditto
	}
} else {
	static assert(0, "Set DEFAULT_PLATFORM and DEFAULT_SYNTAX");
}

extern (C):

struct adbg_disassembler_t {
	ulong address_current;
	ulong address_last;
	ulong address_base;
	size_t buffer_size;	/// Buffer size
	csh cs_handle;
}

struct adbg_opcode_t {
	cs_insn *cs_op;
	bool created;
}