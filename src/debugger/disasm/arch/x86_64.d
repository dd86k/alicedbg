/**
 * AMD64 specific disassembler
 *
 * License: BSD 3-Clause
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
		int pf_operand; /// 66H Operand prefix
	}
	union {
		int group4;
		int pf_address; /// 67H Address prefix
	}
	/// REX prefix (after legacy prefixes)
	// 0100 w r x b
	//      | | | +- Set: Extension of the ModRM.RM, SIB.BASE, or Opcode REG fields
	//      | | +--- Set: Extension of the SIB.INDEX field
	//      | +----- Set: Extension of the ModRM.REG field
	//      +------- Unset: Operand size determined by CS.D. Set: 64-bit operand
	//
	// The 4-bit extension borrows from REX, so it's effectively the following:
	// - REX.X and REX.R unset
	//   - REX.B + OPCODE.REG -> Register index
	// - No SIB (REX.X is unset, regardless of ModRM.MOD)
	//   - REX.R + ModRM.REG -> Register index
	//   - REX.B + ModRM.RM  -> Memory spec
	// - With SIB
	//   - REX.R + ModRM.REG -> Register index
	//   - REX.B + SIB.BASE  -> SIB.BASE
	//   - REX.X + SIB.INDEX -> SIB.INDEX
	int rex;
}

/**
 * AMD64 disassembler.
 * Params: p = Disassembler parameters
 * Returns: DisasmError
 */
void disasm_x86_64(ref disasm_params_t p) {
	x86_64_internals_t internals = void;
	p.x86_64 = &internals;

	with (p.x86_64)
	group1 = group2 = group3 = group4 = rex = 0;

L_CONTINUE:
	ubyte b = *p.addru8;
	++p.addrv;

	if (p.mode >= DisasmMode.File)
		disasm_push_x8(p, b);

	switch (b) {
	case 0xCC: // int3
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "int3");
		break;
	case 0x40: .. case 0x4F:
		p.x86_64.rex = b;
		goto L_CONTINUE;
	default: disasm_err(p);
	}
}

private:

void x86_64_mapb2(ref disasm_params_t p) {
	const ubyte b = *p.addru8;
}

void x86_64_mapb3_38h(ref disasm_params_t p) {
}

void x86_64_mapb3_3ah(ref disasm_params_t p) {
}

// 1-byte VEX (0xC5)
void x86_64_map2_vex1(ref disasm_params_t params) {
}

// 2-byte VEX (0xC4)
void x86_64_map2_vex2(ref disasm_params_t params) {
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
