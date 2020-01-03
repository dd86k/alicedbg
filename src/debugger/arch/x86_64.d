/**
 * AMD64 specific disassembler
 */
module debugger.arch.x86_64;

import debugger.disasm;
import utils.str;

extern (C):

/**
 * AMD64 disassembler.
 * Params: p = Disassembler parameters
 * Returns: DisasmError
 */
int disasm_x86_64(ref disasm_params_t p) {
	int e = DisasmError.None;
	x64_prefreg = PrefixReg.None;
	x64_pre_ad = x64_pre_op = false;
	const int INCLUDE_MACHINECODE = p.include & DISASM_I_MACHINECODE;
	const int INCLUDE_MNEMONICS = p.include & DISASM_I_MNEMONICS;
	
L_CONTINUE:
	ubyte b = *p.addru8;
	++p.addrv;

	if (INCLUDE_MACHINECODE)
		mcaddf(p, "%02X ", b);
	
	switch (b) {
	
	default:
	}
	
	with (p) mcbuf[mcbufi] = mnbuf[mnbufi] = 0;
	
	return DisasmError.None;
}

private:

int mapb2(ref disasm_params_t params) {
	const ubyte b = *params.addru8;
	
	
	return DisasmError.None;
}

int mapb3_38h(ref disasm_params_t params) {
	
	
	return DisasmError.None;
}

int mapb3_3ah(ref disasm_params_t params) {
	
	
	return DisasmError.None;
}

// 1-byte VEX (0xC5)
int map2_vex1(ref disasm_params_t params) {
	
	return DisasmError.None;
}

// 2-byte VEX (0xC4)
int map2_vex2(ref disasm_params_t params) {
	
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