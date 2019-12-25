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
	prefix_reg = PrefixReg.None;
	prefix_address = prefix_operand = false;
	const int INCLUDE_MACHINECODE = p.include & DISASM_INCLUDE_MACHINECODE;
	const int INCLUDE_MNEMONICS = p.include & DISASM_INCLUDE_MNEMONICS;
	
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

enum PrefixReg : ubyte {
	None,
	CS,
	DS,
	ES,
	FS,
	GS,
	SS
}

__gshared uint x86_opmode;
__gshared bool prefix_operand;
__gshared bool prefix_address;
__gshared PrefixReg prefix_reg;