/**
 * x86-specific disassembler.
 */
module debugger.arch.x86;

import debugger.disasm;
import utils.str;

extern (C):

/**
 * x86 disassembler.
 * Params: p = Disassembler parameters
 * Returns: DisasmError
 */
int disasm_x86(ref disasm_params_t p) {
	int e;
	x86_prefreg = PrefixReg.None;
	x86_prefix_address = x86_prefix_operand = false;
	const int INCLUDE_MACHINECODE = p.include & DISASM_I_MACHINECODE;
	const int INCLUDE_MNEMONICS = p.include & DISASM_I_MNEMONICS;

L_CONTINUE:
	ubyte b = *p.addru8;
	++p.addrv;

	if (INCLUDE_MACHINECODE)
		mcaddf(p, "%02X ", b);

	switch (b) {
	case 0x00:	// ADD R/M8, REG8
	case 0x01:	// ADD R/M32, REG32
	case 0x02:	// ADD REG8, R/M8
	case 0x03:	// ADD REG32, R/M32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "ADD ");
		pretty_modrm(p);
		break;
	case 0x04:	// ADD AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MACHINECODE)
			mnaddf(p, "ADD AL, %u", *p.addru8);
		++p.addrv;
		break;
	case 0x05:	// ADD EAX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MACHINECODE)
			mnaddf(p, "ADD EAX, %u", *p.addru32);
		p.addrv += 4;
		break;
	case 0x06:	// PUSH ES
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH ES");
		break;
	case 0x07:	// POP ES
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP ES");
		break;
	case 0x08:	// OR R/M8, REG8
	case 0x09:	// OR R/M32, REG32
	case 0x0A:	// OR REG8, R/M8
	case 0x0B:	// OR REG32, R/M32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "OR ");
		pretty_modrm(p);
		break;
	case 0x0C:	// OR AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "OR EAX, %d", *p.addru8);
		++p.addrv;
		break;
	case 0x0D:	// OR EAX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "OR EAX, %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0x0E:
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH CS");
		break;
	case 0x0F:
		e = mapb2(p);
		break;
	case 0x10:	// ADC R/M8, REG8
	case 0x11:	// ADC R/M32, REG32
	case 0x12:	// ADC REG8, R/M8
	case 0x13:	// ADC REG32, R/M32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "ADC ");
		pretty_modrm(p);
		break;
	case 0x14:	// ADC AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "ADC EAX, %d", *p.addru8);
		++p.addrv;
		break;
	case 0x15:	// ADC EAX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "ADC EAX, %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0x16:	// PUSH SS
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH SS");
		break;
	case 0x17:	// POP SS
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP SS");
		break;
	case 0x18:	// SBB R/M8, REG8
	case 0x19:	// SBB R/M32, REG32
	case 0x1A:	// SBB REG8, R/M8
	case 0x1B:	// SBB REG32, R/M32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "SBB ");
		pretty_modrm(p);
		break;
	case 0x1C:	// SBB AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "SBB EAX, %d", *p.addru8);
		++p.addrv;
		break;
	case 0x1D:	// SBB EAX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "SBB EAX, %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0x1E:	// PUSH DS
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH DS");
		break;
	case 0x1F:	// POP DS
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP DS");
		break;
	case 0x20:	// AND R/M8, REG8
	case 0x21:	// AND R/M32, REG32
	case 0x22:	// AND REG8, R/M8
	case 0x23:	// AND REG32, R/M32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "AND ");
		pretty_modrm(p);
		break;
	case 0x24:	// AND AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "AND EAX, %d", *p.addru8);
		++p.addrv;
		break;
	case 0x25:	// AND EAX, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "AND EAX, %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0x26:	// ES:
		x86_prefreg = PrefixReg.ES;
		goto L_CONTINUE;
	case 0x27:	// DAA
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DAA");
		break;
	case 0x28:	// SUB R/M8, REG8
	case 0x29:	// SUB R/M32, REG32
	case 0x2A:	// SUB REG8, R/M8
	case 0x2B:	// SUB REG32, R/M32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "SUB ");
		pretty_modrm(p);
		break;
	case 0x2C:	// AND AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "AND EAX, %d", *p.addru8);
		++p.addrv;
		break;
	case 0x2D:	// AND EAX, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "AND EAX, %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0x2E:	// CS:
		x86_prefreg = PrefixReg.CS;
		goto L_CONTINUE;
	case 0x2F:	// DAS
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DAA");
		break;
	case 0x30:	// XOR R/M8, REG8
	case 0x31:	// XOR R/M32, REG32
	case 0x32:	// XOR REG8, R/M8
	case 0x33:	// XOR REG32, R/M32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "XOR ");
		pretty_modrm(p);
		break;
	case 0x34:	// XOR AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "XOR EAX, %d", *p.addri8);
		++p.addrv;
		break;
	case 0x35:	// XOR EAX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "XOR EAX, %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0x36:	// SS:
		x86_prefreg = PrefixReg.SS;
		goto L_CONTINUE;
	case 0x37:	// AAA
		if (INCLUDE_MNEMONICS)
			mnadd(p, "AAA");
		break;
	case 0x38:	// CMP R/M8, REG8
	case 0x39:	// CMP R/M32, REG32
	case 0x3A:	// CMP REG8, R/M8
	case 0x3B:	// CMP REG32, R/M32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "CMP ");
		pretty_modrm(p);
		break;
	case 0x3C:	// CMP AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "CMP EAX, %d", *p.addri8);
		++p.addrv;
		break;
	case 0x3D:	// CMP EAX, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "CMP EAX, %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0x3E:	// DS:
		x86_prefreg = PrefixReg.DS;
		goto L_CONTINUE;
	case 0x3F:	// AAS
		if (INCLUDE_MNEMONICS)
			mnadd(p, "AAS");
		break;
	case 0x40:	// INC EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INC EAX");
		break;
	case 0x41:	// INC ECX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INC ECX");
		break;
	case 0x42:	// INC EDX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INC EDX");
		break;
	case 0x43:	// INC EBX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INC EBX");
		break;
	case 0x44:	// INC ESP
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INC ESP");
		break;
	case 0x45:	// INC EBP
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INC EBP");
		break;
	case 0x46:	// INC ESI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INC ESI");
		break;
	case 0x47:	// INC EDI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INC EDI");
		break;
	case 0x48:	// DEC EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DEC EAX");
		break;
	case 0x49:	// DEC ECX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DEC ECX");
		break;
	case 0x4A:	// DEC EDX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DEC EDX");
		break;
	case 0x4B:	// DEC EBX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DEC EBX");
		break;
	case 0x4C:	// DEC ESP
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DEC ESP");
		break;
	case 0x4D:	// DEC EBP
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DEC EBP");
		break;
	case 0x4E:	// DEC ESI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DEC ESI");
		break;
	case 0x4F:	// DEC EDI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "DEC EDI");
		break;
	case 0x50:	// PUSH EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH EAX");
		break;
	case 0x51:	// PUSH ECX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH ECX");
		break;
	case 0x52:	// PUSH EDX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH EDX");
		break;
	case 0x53:	// PUSH EBX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH EBX");
		break;
	case 0x54:	// PUSH ESP
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH ESP");
		break;
	case 0x55:	// PUSH EBP
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH EBP");
		break;
	case 0x56:	// PUSH ESI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH ESI");
		break;
	case 0x57:	// PUSH EDI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSH EDI");
		break;
	case 0x58:	// POP EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP EAX");
		break;
	case 0x59:	// POP ECX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP ECX");
		break;
	case 0x5A:	// POP EDX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP EDX");
		break;
	case 0x5B:	// POP EBX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP EBX");
		break;
	case 0x5C:	// POP ESP
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP ESP");
		break;
	case 0x5D:	// POP EBP
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP EBP");
		break;
	case 0x5E:	// POP ESI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP ESI");
		break;
	case 0x5F:	// POP EDI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POP EDI");
		break;
	case 0x60:	// PUSHAD
		if (INCLUDE_MNEMONICS)
			mnadd(p, "PUSHAD");
		break;
	case 0x61:	// POPAD
		if (INCLUDE_MNEMONICS)
			mnadd(p, "POPAD");
		break;
	case 0x62:	// BOUND REG32, MEM32, MEM32
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X %08X %08X",
				modrm, *p.addru32, *(p.addru32 + 1));
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "BOUND %s, %s %u %u",
				modrm_reg(modrm), segstr, *p.addru32, *(p.addru32 + 1));
		p.addrv += 8;
		break;
	case 0x63:	// ARPL R/M16, REG16
		if (INCLUDE_MNEMONICS)
			mnadd(p, "ARPL ");
		pretty_modrm(p);
		break;
	case 0x64:	// FS:
		x86_prefreg = PrefixReg.FS;
		goto L_CONTINUE;
	case 0x65:	// GS:
		x86_prefreg = PrefixReg.GS;
		goto L_CONTINUE;
	case 0x66:	// PREFIX: OPERAND SIZE
		x86_prefix_operand = true;
		goto L_CONTINUE;
	case 0x67:	// PREFIX: ADDRESS SIZE
		x86_prefix_address = true;
		goto L_CONTINUE;
	case 0x68:	// PUSH IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "PUSH %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0x69:	// IMUL REG32, R/M32, IMM32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "IMUL");
		pretty_modrm(p);
		if (INCLUDE_MACHINECODE)
			mcaddf(p, " %08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, " %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0x6A:	// PUSH IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "PUSH %d", *p.addri8);
		++p.addrv;
		break;
	case 0x6B:	// IMUL REG32, R/M32, IMM8
		if (INCLUDE_MNEMONICS)
			mnadd(p, "IMUL");
		pretty_modrm(p);
		if (INCLUDE_MACHINECODE)
			mcaddf(p, " %02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, " %d", *p.addri8);
		++p.addrv;
		break;
	case 0x6C:	// INSB
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INSB");
		break;
	case 0x6D:	// INSD
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INSD");
		break;
	case 0x6E:	// OUTSB
		if (INCLUDE_MNEMONICS)
			mnadd(p, "OUTSB");
		break;
	case 0x6F:	// OUTSD
		if (INCLUDE_MNEMONICS)
			mnadd(p, "OUTSD");
		break;
	case 0x70:	// JO
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JO %d", *p.addri8);
		++p.addrv;
		break;
	case 0x71:	// JNO
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JNO %d", *p.addri8);
		++p.addrv;
		break;
	case 0x72:	// JB
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JB %d", *p.addri8);
		++p.addrv;
		break;
	case 0x73:	// JNB
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JNB %d", *p.addri8);
		++p.addrv;
		break;
	case 0x74:	// JZ
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JZ %d", *p.addri8);
		++p.addrv;
		break;
	case 0x75:	// JNZ
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JNZ %d", *p.addri8);
		++p.addrv;
		break;
	case 0x76:	// JBE
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JBE %d", *p.addri8);
		++p.addrv;
		break;
	case 0x77:	// JNBE
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JNBE %d", *p.addri8);
		++p.addrv;
		break;
	case 0x78:	// JS
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JS %d", *p.addri8);
		++p.addrv;
		break;
	case 0x79:	// JNS
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JNS %d", *p.addri8);
		++p.addrv;
		break;
	case 0x7A:	// JP
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JP %d", *p.addri8);
		++p.addrv;
		break;
	case 0x7B:	// JNP
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JNP %d", *p.addri8);
		++p.addrv;
		break;
	case 0x7C:	// JL
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JL %d", *p.addri8);
		++p.addrv;
		break;
	case 0x7D:	// JNL
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JNL %d", *p.addri8);
		++p.addrv;
		break;
	case 0x7E:	// JLE
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JLE %d", *p.addri8);
		++p.addrv;
		break;
	case 0x7F:	// JNLE
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JNLE %d", *p.addri8);
		++p.addrv;
		break;
	case 0x81:	// GRP1 REG32, IMM32
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X %08X", modrm, *p.addru32);
		if (INCLUDE_MNEMONICS) {
			const(char) *f = void;
			switch (modrm & RM_RM) {
			case RM_RM_000: f = "ADD"; break;
			case RM_RM_001: f = "OR";  break;
			case RM_RM_010: f = "ADC"; break;
			case RM_RM_011: f = "SBB"; break;
			case RM_RM_100: f = "AND"; break;
			case RM_RM_101: f = "SUB"; break;
			case RM_RM_110: f = "XOR"; break;
			case RM_RM_111: f = "CMP"; break;
			default: // impossible
			}
			mnaddf(p, "%s %s, %u",
				f, modrm_reg(modrm, b & 1, x86_prefix_operand), *p.addru32);
		}
		p.addrv += 4;
		break;
	case 0x80:	// GRP1 REG8, IMM8
	case 0x82:	// GRP1 REG8, IMM8
	case 0x83:	// GRP1 REG32, IMM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X %02X", modrm, *p.addru8);
		if (INCLUDE_MNEMONICS) {
			const(char) *f = void;
			switch (modrm & RM_RM) {
			case RM_RM_000: f = "ADD"; break;
			case RM_RM_001: f = "OR";  break;
			case RM_RM_010: f = "ADC"; break;
			case RM_RM_011: f = "SBB"; break;
			case RM_RM_100: f = "AND"; break;
			case RM_RM_101: f = "SUB"; break;
			case RM_RM_110: f = "XOR"; break;
			case RM_RM_111: f = "CMP"; break;
			default: // impossible
			}
			mnaddf(p, "%s %s, %u",
				f, modrm_reg(modrm, b & 1, x86_prefix_operand), *p.addru8);
		}
		++p.addrv;
		break;
	case 0x84:	// TEST R/M8, REG8
	case 0x85:	// TEST R/M32, REG32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "TEST ");
		pretty_modrm(p);
		break;
	case 0x86:	// XCHG R/M8, REG8
	case 0x87:	// XCHG R/M32, REG32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "XCHG ");
		pretty_modrm(p);
		break;
	case 0x88:	// MOV R/M8, REG8
	case 0x89:	// MOV R/M32, REG32
	case 0x8A:	// MOV REG8, R/M8
	case 0x8B:	// MOV REG32, R/M32
		if (INCLUDE_MNEMONICS)
			mnadd(p, "MOV ");
		pretty_modrm(p);
		break;
	case 0x8C:	// MOV REG32, SREG16
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", modrm);
		if (INCLUDE_MNEMONICS) {
			const(char) *f = void;
			switch (modrm & RM_REG) {
			case RM_REG_000: f = "ES"; break;
			case RM_REG_001: f = "CS"; break;
			case RM_REG_010: f = "SS"; break;
			case RM_REG_011: f = "DS"; break;
			case RM_REG_100: f = "FS"; break;
			case RM_REG_101: f = "GS"; break;
			default: f = "SEGREG?"; break;
			}
			mnaddf(p, "MOV %s, %s", modrm_reg(modrm), f);
		}
		break;
	case 0x8D:	//TODO: LEA REG32, MEM32
		break;
	case 0x8E:	// MOV SREG16, REG16
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", modrm);
		if (INCLUDE_MNEMONICS) {
			const(char) *f = void;
			switch (modrm & RM_REG) {
			case RM_REG_000: f = "ES"; break;
			case RM_REG_001: f = "CS"; break;
			case RM_REG_010: f = "SS"; break;
			case RM_REG_011: f = "DS"; break;
			case RM_REG_100: f = "FS"; break;
			case RM_REG_101: f = "GS"; break;
			default: f = "SEGREG?"; break;
			}
			mnaddf(p, "MOV %s, %s", f, modrm_reg(modrm, 0, 1));
		}
		break;
	case 0x8F:	// GRP1A (POP) REG32
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (modrm & RM_RM) { // Invalid
			if (INCLUDE_MNEMONICS)
				mnadd(p, "??");
			break;
		}
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02", modrm);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "POP %s", modrm_reg(modrm));
		break;
	case 0x90:	// NOP
		if (INCLUDE_MNEMONICS)
			mnadd(p, "NOP");
		break;
	case 0x91:	// XCHG ECX, EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "XCHG ECX, EAX");
		break;
	case 0x92:	// XCHG EDX, EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "XCHG EDX, EAX");
		break;
	case 0x93:	// XCHG EBX, EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "XCHG EBX, EAX");
		break;
	case 0x94:	// XCHG ESP, EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "XCHG ESP, EAX");
		break;
	case 0x95:	// XCHG EBP, EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "XCHG EBP, EAX");
		break;
	case 0x96:	// XCHG ESI, EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "XCHG ESI, EAX");
		break;
	case 0x97:	// XCHG EDI, EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "XCHG EDI, EAX");
		break;
	case 0x98:	// CBW
		if (INCLUDE_MNEMONICS)
			mnadd(p, "CBW");
		break;
	case 0x99:	// CBD
		if (INCLUDE_MNEMONICS)
			mnadd(p, "CBD");
		break;
	case 0x9A:	//TODO: CALL (FAR)
		//if (INCLUDE_MNEMONICS)
		//	mnadd(p, "CALL ");
		break;
	case 0x9B:	// WAIT/FWAIT
		if (INCLUDE_MNEMONICS)
			mnadd(p, "WAIT");
		break;
	case 0x9C:	//TODO: PUSHF/D/Q
	
		break;
	case 0x9D:	//TODO: POPF/D/Q
	
		break;
	case 0x9E:	// SAHF
		if (INCLUDE_MACHINECODE)
			mnadd(p, "SAHF");
		break;
	case 0x9F:	// LAHF
		if (INCLUDE_MACHINECODE)
			mnadd(p, "LAHF");
		break;
	case 0xA0:	// MOV AL, MEM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS) {
			const(char) *f = void;
			with (PrefixReg)
			switch (x86_prefreg) {
			case CS: f = "MOV AL, [CS:%d]"; break;
			case DS: f = "MOV AL, [DS:%d]"; break;
			case ES: f = "MOV AL, [ES:%d]"; break;
			case FS: f = "MOV AL, [FS:%d]"; break;
			case GS: f = "MOV AL, [GS:%d]"; break;
			case SS: f = "MOV AL, [SS:%d]"; break;
			default: f = "MOV AL, [%d]"; break;
			}
			mnaddf(p, f, *p.addri32);
		}
		p.addrv += 4;
		break;
	case 0xA1:	// MOV EAX, MEM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS) {
			const(char) *f = void;
			with (PrefixReg)
			switch (x86_prefreg) {
			case CS: f = "MOV EAX, [CS:%d]"; break;
			case DS: f = "MOV EAX, [DS:%d]"; break;
			case ES: f = "MOV EAX, [ES:%d]"; break;
			case FS: f = "MOV EAX, [FS:%d]"; break;
			case GS: f = "MOV EAX, [GS:%d]"; break;
			case SS: f = "MOV EAX, [SS:%d]"; break;
			default: f = "MOV EAX, [%d]"; break;
			}
			mnaddf(p, f, *p.addri32);
		}
		p.addrv += 4;
		break;
	case 0xA2:	// MOV MEM8, AL
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS) {
			const(char) *f = void;
			with (PrefixReg)
			switch (x86_prefreg) {
			case CS: f = "MOV [CS:%d], AL"; break;
			case DS: f = "MOV [DS:%d], AL"; break;
			case ES: f = "MOV [ES:%d], AL"; break;
			case FS: f = "MOV [FS:%d], AL"; break;
			case GS: f = "MOV [GS:%d], AL"; break;
			case SS: f = "MOV [SS:%d], AL"; break;
			default: f = "MOV [%d], AL"; break;
			}
			mnaddf(p, f, *p.addri32);
		}
		p.addrv += 4;
		break;
	case 0xA3:	// MOV MEM32, EAX
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS) {
			const(char) *f = void;
			with (PrefixReg)
			switch (x86_prefreg) {
			case CS: f = "MOV [CS:%d], EAX"; break;
			case DS: f = "MOV [DS:%d], EAX"; break;
			case ES: f = "MOV [ES:%d], EAX"; break;
			case FS: f = "MOV [FS:%d], EAX"; break;
			case GS: f = "MOV [GS:%d], EAX"; break;
			case SS: f = "MOV [SS:%d], EAX"; break;
			default: f = "MOV [%d], EAX"; break;
			}
			mnaddf(p, f, *p.addri32);
		}
		p.addrv += 4;
		break;
	case 0xA4:	// MOVSB ES:EDI, DS:ESI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "MOVSB ES:EDI, DS:ESI");
		break;
	case 0xA5:	// MOVSD ES:EDI, DS:ESI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "MOVSD ES:EDI, DS:ESI");
		break;
	case 0xA6:	// MOVSB DS:ESI, ES:EDI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "MOVSB DS:ESI, ES:EDI");
		break;
	case 0xA7:	// MOVSD DS:ESI, ES:EDI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "MOVSD DS:ESI, ES:EDI");
		break;
	case 0xA8:	// TEST AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "TEST AL, %d", *p.addru8);
		++p.addrv;
		break;
	case 0xA9:	// TEST EAX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "TEST EAX, %d", *p.addru32);
		p.addrv += 4;
		break;
	case 0xAA:	// STOSB ES:EDI, AL
		if (INCLUDE_MNEMONICS)
			mnadd(p, "STOSB ES:EDI, AL");
		break;
	case 0xAB:	// STOSD ES:EDI, EAX
		if (INCLUDE_MNEMONICS)
			mnadd(p, "STOSD ES:EDI, EAX");
		break;
	case 0xAC:	// LODSB AL, DS:ESI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "LODSB AL, DS:ESI");
		break;
	case 0xAD:	// LODSD EAX, DS:ESI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "LODSD EAX, DS:ESI");
		break;
	case 0xAE:	// SCASB AL, ES:EDI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "SCASB AL, ES:EDI");
		break;
	case 0xAF:	// SCASD EAX, ES:EDI
		if (INCLUDE_MNEMONICS)
			mnadd(p, "SCASD EAX, ES:EDI");
		break;
	case 0xB0:	// MOV AL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV AL, %d", *p.addru8);
		++p.addrv;
		break;
	case 0xB1:	// MOV DL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV DL, %d", *p.addru8);
		++p.addrv;
		break;
	case 0xB2:	// MOV CL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV CL, %d", *p.addru8);
		++p.addrv;
		break;
	case 0xB3:	// MOV BL, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV BL, %d", *p.addru8);
		++p.addrv;
		break;
	case 0xB4:	// MOV AH, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV AH, %d", *p.addru8);
		++p.addrv;
		break;
	case 0xB5:	// MOV CH, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV CH, %d", *p.addru8);
		++p.addrv;
		break;
	case 0xB6:	// MOV DH, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV DH, %d", *p.addru8);
		++p.addrv;
		break;
	case 0xB7:	// MOV BH, IMM8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV BH, %d", *p.addru8);
		++p.addrv;
		break;
	case 0xB8:	// MOV EAX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV EAX, %08X", *p.addru32);
		p.addrv += 4;
		break;
	case 0xB9:	// MOV ECX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV ECX, %08X", *p.addru32);
		p.addrv += 4;
		break;
	case 0xBA:	// MOV EDX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV EDX, %08X", *p.addru32);
		p.addrv += 4;
		break;
	case 0xBB:	// MOV EBX, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV EBX, %08X", *p.addru32);
		p.addrv += 4;
		break;
	case 0xBC:	// MOV ESP, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV ESP, %08X", *p.addru32);
		p.addrv += 4;
		break;
	case 0xBD:	// MOV EBP, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV EBP, %08X", *p.addru32);
		p.addrv += 4;
		break;
	case 0xBE:	// MOV ESI, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV ESI, %08X", *p.addru32);
		p.addrv += 4;
		break;
	case 0xBF:	// MOV EDI, IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "MOV EDI, %08X", *p.addru32);
		p.addrv += 4;
		break;
	case 0xC0:	//TODO: GRP2 R/M8, IMM8
	
		break;
	case 0xC1:	//TODO: GRP2 R/M32, IMM8
	
		break;
	case 0xC2:	// RET IMM16
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%04X", *p.addru16);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "RET %d", *p.addri16);
		p.addrv += 2;
		break;
	case 0xC3:	// RET
		if (INCLUDE_MNEMONICS)
			mnadd(p, "RET");
		break;
	case 0xC7:	// GRP11(1A) - MOV MEM32, IMM32
		ubyte modrm = *p.addru8;
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%X ", modrm);
		if (INCLUDE_MNEMONICS) {
			if (modrm & RM_REG) {
				mnadd(p, "??");
				break;
			} else
				mnadd(p, "MOV ");
		}
		const(char) *r = void;
		switch (modrm & RM_MOD) {
		case RM_MOD_00:
			if (INCLUDE_MNEMONICS) {
				switch (modrm & RM_RM) {
				case RM_RM_000: r = "[EAX]"; break;
				case RM_RM_001: r = "[ECX]"; break;
				case RM_RM_010: r = "[EDX]"; break;
				case RM_RM_011: r = "[EBX]"; break;
				case RM_RM_100: r = "[ESP]"; break;
				case RM_RM_101: r = "[EBP]"; break;
				case RM_RM_110: r = "[ESI]"; break;
				case RM_RM_111: r = "[EDI]"; break;
				default: // never
				}
				mnadd(p, r);
			}
			break;
		case RM_MOD_01:
			byte m = *p.addri8;
			if (INCLUDE_MACHINECODE)
				mcaddf(p, "%X ", m & 0xFF);
			if (INCLUDE_MNEMONICS) {
				switch (modrm & RM_RM) {
				case RM_RM_000: r = "[EAX%s%d]"; break;
				case RM_RM_001: r = "[ECX%s%d]"; break;
				case RM_RM_010: r = "[EDX%s%d]"; break;
				case RM_RM_011: r = "[EBX%s%d]"; break;
				case RM_RM_100: r = "[ESP%s%d]"; break;
				case RM_RM_101: r = "[EBP%s%d]"; break;
				case RM_RM_110: r = "[ESI%s%d]"; break;
				case RM_RM_111: r = "[EDI%s%d]"; break;
				default: // never
				}
				mnaddf(p, r, m >= 0 ? cast(char*)"+" : "", m);
			}
			break;
		case RM_MOD_10:
			int m = *p.addri32;
			if (INCLUDE_MACHINECODE)
				mcaddf(p, "%X ", m);
			if (INCLUDE_MNEMONICS) {
				switch (modrm & RM_RM) {
				case RM_RM_000: r = "[EAX%s%d]"; break;
				case RM_RM_001: r = "[ECX%s%d]"; break;
				case RM_RM_010: r = "[EDX%s%d]"; break;
				case RM_RM_011: r = "[EBX%s%d]"; break;
				case RM_RM_100: r = "[ESP%s%d]"; break;
				case RM_RM_101: r = "[EBP%s%d]"; break;
				case RM_RM_110: r = "[ESI%s%d]"; break;
				case RM_RM_111: r = "[EDI%s%d]"; break;
				default: // never
				}
				mnaddf(p, r, m >= 0 ? cast(char*)"+" : "", m);
			}
			p.addrv += 4;
			break;
		case RM_MOD_11:
			if (INCLUDE_MNEMONICS) {
				switch (modrm & RM_RM) {
				case RM_RM_000: r = "EAX"; break;
				case RM_RM_001: r = "ECX"; break;
				case RM_RM_010: r = "EDX"; break;
				case RM_RM_011: r = "EBX"; break;
				case RM_RM_100: r = "ESP"; break;
				case RM_RM_101: r = "EBP"; break;
				case RM_RM_110: r = "ESI"; break;
				case RM_RM_111: r = "EDI"; break;
				default: // never
				}
				mnadd(p, r);
			}
			break;
		default:
		}
		uint v = void;
		if (x86_prefix_operand) {
			v = *p.addru16;
			p.addrv += 2;
		} else {
			v = *p.addru32;
			p.addrv += 4;
		}
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, ", %08X", *p.addru32);
		break;
	case 0xCC:
		if (INCLUDE_MNEMONICS)
			mnadd(p, "INT 3");
		break;
	case 0xE8:	// CALL IMM32
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "CALL %d", *p.addri32);
		p.addrv += 4;
		break;
	case 0xEB:	// JMP i8
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X ", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "JMP %d", *p.addri8);
		++p.addrv;
		break;
	case 0xF0:	// LOCK
		if (INCLUDE_MNEMONICS)
			mnadd(p, "LOCK ");
		goto L_CONTINUE;
	default:
	}
	
	with (p) mcbuf[mcbufi] = mnbuf[mnbufi] = 0;
	
	return e;
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

__gshared bool x86_prefix_operand;
__gshared bool x86_prefix_address;
__gshared PrefixReg x86_prefreg;

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

enum : ubyte {
	RM_MOD_00 =   0,	/// MOD 00, Memory Mode, no displacement
	RM_MOD_01 =  64,	/// MOD 01, Memory Mode, 8-bit displacement
	RM_MOD_10 = 128,	/// MOD 10, Memory Mode, 16-bit displacement
	RM_MOD_11 = 192,	/// MOD 11, Register Mode
	RM_MOD = RM_MOD_11,	/// Used for masking the MOD bits (11 000 000)

	RM_REG_000 =  0,	/// AL/AX
	RM_REG_001 =  8,	/// CL/CX
	RM_REG_010 = 16,	/// DL/DX
	RM_REG_011 = 24,	/// BL/BX
	RM_REG_100 = 32,	/// AH/SP
	RM_REG_101 = 40,	/// CH/BP
	RM_REG_110 = 48,	/// DH/SI
	RM_REG_111 = 56,	/// BH/DI
	RM_REG = RM_REG_111,	/// Used for masking the REG bits (00 111 000)

	RM_RM_000 = 0,	/// R/M 000 bits
	RM_RM_001 = 1,	/// R/M 001 bits
	RM_RM_010 = 2,	/// R/M 010 bits
	RM_RM_011 = 3,	/// R/M 011 bits
	RM_RM_100 = 4,	/// R/M 100 bits
	RM_RM_101 = 5,	/// R/M 101 bits
	RM_RM_110 = 6,	/// R/M 110 bits
	RM_RM_111 = 7,	/// R/M 111 bits
	RM_RM = RM_RM_111,	/// Used for masking the R/M bits (00 000 111)
}

void pretty_modrm(ref disasm_params_t p) {
	const int INCLUDE_MACHINECODE = p.include & DISASM_I_MACHINECODE;
	const int INCLUDE_MNEMONICS = p.include & DISASM_I_MNEMONICS;
	ubyte op = *(p.addru8 - 1);
	int direction = op & 2;	// If set, direction is towards REG
	//int wide = op & 1;	// If set, WIDE operation is in effect
	ubyte modrm = *p.addru8;
	++p.addrv;
	const(char) *c = ", ";
	const(char) *f = void;

	if (INCLUDE_MACHINECODE)
		mcaddf(p, "%02X ", modrm);

	if (direction)
		goto L_REG;

L_RM:
	switch (modrm & RM_MOD) {
	case RM_MOD_00:	// Memory Mode, no displacement
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "[%s]", modrm_rm(modrm));
		break;
	case RM_MOD_01:	// Memory Mode, 8-bit displacement
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%02X", *p.addru8);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "[%s%s%d]", modrm_rm(modrm),
				(*p.addri8) >=0 ? cast(char*)"+" : "", *p.addri8);
		++p.addrv;
		break;
	case RM_MOD_10:	// Memory Mode, 32-bit displacement
		if (INCLUDE_MACHINECODE)
			mcaddf(p, "%08X", *p.addru32);
		if (INCLUDE_MNEMONICS)
			mnaddf(p, "[%s%s%d]", modrm_rm(modrm),
				(*p.addri32) >=0 ? cast(char*)"+" : "", *p.addri32);
		p.addrv += 4;
		break;
	case RM_MOD_11:	// Register mode
		if (INCLUDE_MNEMONICS)
			mnadd(p, modrm_rm(modrm));
		break;
	default: // Never reached
	}
	
	if (direction)
		return;
	else {
		mnadd(p, c);
	}

L_REG:
	if (INCLUDE_MNEMONICS) {
		switch (modrm & RM_REG) {
		case RM_REG_000: f = "EAX"; break;
		case RM_REG_001: f = "ECX"; break;
		case RM_REG_010: f = "EDX"; break;
		case RM_REG_011: f = "EBX"; break;
		case RM_REG_100: f = "ESP"; break;
		case RM_REG_101: f = "EBP"; break;
		case RM_REG_110: f = "ESI"; break;
		case RM_REG_111: f = "EDI"; break;
		default: // Never reached
		}
		mnadd(p, f);

		if (direction) {
			mnadd(p, c);
			goto L_RM;
		}
	}
}

const(char) *segstr() {
	with (PrefixReg)
	switch (x86_prefreg) {
	case CS: return "CS:";
	case DS: return "DS:";
	case ES: return "ES:";
	case FS: return "FS:";
	case GS: return "GS:";
	case SS: return "SS:";
	default: return "";
	}
}

const(char) *modrm_reg(ubyte modrm, ubyte wide = 1, ubyte prefix = 0) {
	if (wide)
	switch (modrm & RM_REG) {
	case RM_REG_000: return "EAX";
	case RM_REG_001: return "ECX";
	case RM_REG_010: return "EDX";
	case RM_REG_011: return "EBX";
	case RM_REG_100: return "ESP";
	case RM_REG_101: return "EBP";
	case RM_REG_110: return "ESI";
	case RM_REG_111: return "EDI";
	default: return "REG??";
	}
	else {
		if (prefix)
		switch (modrm & RM_REG) {
		case RM_REG_000: return "AX";
		case RM_REG_001: return "CX";
		case RM_REG_010: return "DX";
		case RM_REG_011: return "BX";
		case RM_REG_100: return "SP";
		case RM_REG_101: return "BP";
		case RM_REG_110: return "SI";
		case RM_REG_111: return "DI";
		default: return "REG??";
		}
		else
		switch (modrm & RM_REG) {
		case RM_REG_000: return "AL";
		case RM_REG_001: return "CL";
		case RM_REG_010: return "DL";
		case RM_REG_011: return "BL";
		case RM_REG_100: return "AH";
		case RM_REG_101: return "CH";
		case RM_REG_110: return "DH";
		case RM_REG_111: return "DL";
		default: return "REG??";
		}
	}
}

const(char) *modrm_rm(ubyte modrm) {
	switch (modrm & RM_RM) {
	case RM_RM_000:
		with (PrefixReg)
		switch (x86_prefreg) {
		case CS: return "CS:EAX";
		case DS: return "DS:EAX";
		case ES: return "ES:EAX";
		case FS: return "FS:EAX";
		case GS: return "GS:EAX";
		case SS: return "SS:EAX";
		default:
		}
		return "EAX";
	case RM_RM_001:
		with (PrefixReg)
		switch (x86_prefreg) {
		case CS: return "CS:ECX";
		case DS: return "DS:ECX";
		case ES: return "ES:ECX";
		case FS: return "FS:ECX";
		case GS: return "GS:ECX";
		case SS: return "SS:ECX";
		default:
		}
		return "ECX";
	case RM_RM_010:
		with (PrefixReg)
		switch (x86_prefreg) {
		case CS: return "CS:EDX";
		case DS: return "DS:EDX";
		case ES: return "ES:EDX";
		case FS: return "FS:EDX";
		case GS: return "GS:EDX";
		case SS: return "SS:EDX";
		default:
		}
		return "EDX";
	case RM_RM_011:
		with (PrefixReg)
		switch (x86_prefreg) {
		case CS: return "CS:EBX";
		case DS: return "DS:EBX";
		case ES: return "ES:EBX";
		case FS: return "FS:EBX";
		case GS: return "GS:EBX";
		case SS: return "SS:EBX";
		default:
		}
		return "EBX";
	case RM_RM_100:
		with (PrefixReg)
		switch (x86_prefreg) {
		case CS: return "CS:ESP";
		case DS: return "DS:ESP";
		case ES: return "ES:ESP";
		case FS: return "FS:ESP";
		case GS: return "GS:ESP";
		case SS: return "SS:ESP";
		default:
		}
		return "ESP";
	case RM_RM_101:
		with (PrefixReg)
		switch (x86_prefreg) {
		case CS: return "CS:EBP";
		case DS: return "DS:EBP";
		case ES: return "ES:EBP";
		case FS: return "FS:EBP";
		case GS: return "GS:EBP";
		case SS: return "SS:EBP";
		default:
		}
		return "EBP";
	case RM_RM_110:
		with (PrefixReg)
		switch (x86_prefreg) {
		case CS: return "CS:ESI";
		case DS: return "DS:ESI";
		case ES: return "ES:ESI";
		case FS: return "FS:ESI";
		case GS: return "GS:ESI";
		case SS: return "SS:ESI";
		default:
		}
		return "ESI";
	case RM_RM_111:
		with (PrefixReg)
		switch (x86_prefreg) {
		case CS: return "CS:EDI";
		case DS: return "DS:EDI";
		case ES: return "ES:EDI";
		case FS: return "FS:EDI";
		case GS: return "GS:EDI";
		case SS: return "SS:EDI";
		default:
		}
		return "EDI";
	default: return null; // Never happens
	}
}
