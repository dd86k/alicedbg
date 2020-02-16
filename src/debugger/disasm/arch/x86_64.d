/**
 * AMD64 specific disassembler
 */
module debugger.disasm.arch.x86_64;

import debugger.disasm.core;
import debugger.disasm.formatter;
import utils.str;

extern (C):

package
struct x86_64_internals_t {
	union {
		int group1;
		int lock;
		int rep;
		int repne;
		int repe;
	}
	union {
		int group2;
		int segreg;
	}
	union {
		int group3;
		int prefix_operand;
	}
	union {
		int group4;
		int prefix_address;
	}
}

/**
 * AMD64 disassembler.
 * Params: p = Disassembler parameters
 * Returns: DisasmError
 */
void disasm_x86_64(ref disasm_params_t p) {
	x86_64_internals_t internals;
//	p.x86_64 = &internals;

	with (p.x86)
	group1 = group2 = group3 = group4 = 0;

L_CONTINUE:
	ubyte b = *p.addru8;
	++p.addrv;

	if (p.mode >= DisasmMode.File)
		disasm_push_x8(p, b);
	
	main: switch (b) {
	
	default:
	}
}

private:

int x86_64_mapb2(ref disasm_params_t params) {
	const ubyte b = *params.addru8;
	
	
	return DisasmError.None;
}

int x86_64_mapb3_38h(ref disasm_params_t params) {
	
	
	return DisasmError.None;
}

int x86_64_mapb3_3ah(ref disasm_params_t params) {
	
	
	return DisasmError.None;
}

// 1-byte VEX (0xC5)
int x86_64_map2_vex1(ref disasm_params_t params) {
	
	return DisasmError.None;
}

// 2-byte VEX (0xC4)
int x86_64_map2_vex2(ref disasm_params_t params) {
	
	return DisasmError.None;
}

enum PrefixReg : ubyte {
	None,
	CS,
	DS,
	ES,
	FS,
	GS,
	SS
}

__gshared bool x64_pre_op;	/// OPERAND prefix (66H)
__gshared bool x64_pre_ad;	/// ADDRESS prefix (67H)
__gshared PrefixReg x64_prefreg;	/// Preferred segment register prefix