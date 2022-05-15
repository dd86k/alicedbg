/**
 * Formatting module.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.disasm.formatter;

public import adbg.disasm.syntax.intel,
	adbg.disasm.syntax.nasm,
	adbg.disasm.syntax.att,
	adbg.disasm.syntax.ideal,
	adbg.disasm.syntax.hyde,
	adbg.disasm.syntax.rv;
package import adbg.disassembler;
package import adbg.utils.str;

//TODO: Number preferred style or instruction/immediate purpose
//TODO: Make override with 'default' member? (for syntax default)
enum AdbgDisasmNumberStyle : ubyte {
	decimal,	/// 
	hexadecimal,	/// 
}
//TODO: AdbgDisasmHexStyle (syntax setting?)
//TODO: Make override with 'default' member? (for syntax default)
//NOTE: May conflict with syntax styles being constant values
enum AdbgDisasmHexStyle : ubyte {
	defaultPrefix,	/// 0x10, default
	hSuffix,	/// 10h
	hPrefix,	/// 0h10
	poundPrefix,	/// #10
	pourcentPrefix,	/// %10
	dollarPrefix,	/// $10
}

package immutable const(char) *TYPE_UNKNOWN = "word?";
private immutable const(char) *sep = ", ";

//TODO: Add AdbgSyntax to formatting functions
//      In theory, opcode struct should have all the data it needs
//      Maybe transfer decoder settings into opcode structure?

size_t adbg_disasm_format_prefixes(adbg_disasm_t *disasm, char *buffer, size_t size, adbg_disasm_opcode_t *op) {
	if (disasm.opcode.prefixCount == 0) {
		buffer[0] = 0;
		return 0;
	}
	
	adbg_string_t s = adbg_string_t(buffer, size);
	return adbg_disasm_format_prefixes2(disasm, s, op);
}
private
size_t adbg_disasm_format_prefixes2(adbg_disasm_t *disasm, ref adbg_string_t s, adbg_disasm_opcode_t *op) {
	// Prefixes, skipped if empty
	version (Trace) trace("count=%zu", op.prefixCount);
	
	bool isHyde = disasm.syntax == AdbgSyntax.hyde;
	
	if (isHyde) {
		if (op.segment) {
			if (s.addc(op.segment[0]))
				return s.length;
			if (s.adds("seg: "))
				return s.length;
		}
	}
	
	char c = isHyde ? '.' : ' ';
	
	if (op.prefixCount) {
		for (size_t i; i < op.prefixCount; ++i) {
			if (s.adds(op.prefixes[i].name))
				return s.length;
			if (s.addc(c))
				return s.length;
		}
	}
	
	return s.length;
}
size_t adbg_disasm_format_mnemonic(adbg_disasm_t *disasm, char *buffer, size_t size, adbg_disasm_opcode_t *op) {
	if (disasm.opcode.mnemonic == null) {
		buffer[0] = 0;
		return 0;
	}
	
	adbg_string_t s = adbg_string_t(buffer, size);
	return adbg_disasm_format_mnemonic2(disasm, s, op);
}
private
size_t adbg_disasm_format_mnemonic2(adbg_disasm_t *disasm, ref adbg_string_t s, adbg_disasm_opcode_t *op) {
	version (Trace) trace("mnemonic=%s", op.mnemonic);
	
	if (disasm.syntax == AdbgSyntax.att && disasm.decoderFar)
		if (s.addc('l'))
			return s.length;
	s.adds(op.mnemonic);
	//TODO: ATT ambiguiate instruction width suffix
	//if (disasm.syntax == AdbgSyntax.att && disasm.ambiguity)
	//	if (s.addc())
	
	return s.length;
}
size_t adbg_disasm_format_operands(adbg_disasm_t *disasm, char *buffer, size_t size, adbg_disasm_opcode_t *op) {
	if (disasm.opcode.operandCount == 0) {
		buffer[0] = 0;
		return 0;
	}
	
	adbg_string_t s = adbg_string_t(buffer, size);
	return adbg_disasm_format_operands2(disasm, s, op);
}
private
size_t adbg_disasm_format_operands2(adbg_disasm_t *disasm, ref adbg_string_t s, adbg_disasm_opcode_t *op) {
	version (Trace) trace("count=%zu", op.operandCount);
	
	//TODO: Consider letting syntax do its own things
	//      e.g., with AT&T, if the two operands are immediates, they do not flip
	//      As in, do that here instead of the decoder
	//      But then, which architectures does that affect?
	
	switch (disasm.syntax) with (AdbgSyntax) {
	case hyde:
		if (s.adds("( ")) return s.length;
		adbg_disasm_format_operands_right(disasm, s, op);
		if (s.adds(" );")) return s.length;
		return s.length;
	case att:
		if (disasm.decoderNoReverse) 
			adbg_disasm_format_operands_left(disasm, s, op);
		else
			adbg_disasm_format_operands_right(disasm, s, op);
		return s.length;
	default:
		adbg_disasm_format_operands_left(disasm, s, op);
		return s.length;
	}
}

/// 
size_t adbg_disasm_format(adbg_disasm_t *disasm, char *buffer, size_t size, adbg_disasm_opcode_t *op) {
	version (Trace) trace("size=%zu", size);
	
	if (disasm.opcode.mnemonic == null) {
		buffer = empty_string;
		return 0;
	}
	
	adbg_string_t s = adbg_string_t(buffer, size);
	
	if (op.prefixCount)
		adbg_disasm_format_prefixes2(disasm, s, op);
	
	adbg_disasm_format_mnemonic2(disasm, s, op);
	
	if (op.operandCount || disasm.syntax == AdbgSyntax.hyde) {
		if (disasm.syntax != AdbgSyntax.hyde)
			if (s.addc(disasm.userMnemonicTab ? '\t' : ' '))
				return s.length;
		
		return adbg_disasm_format_operands2(disasm, s, op);
	}
	
	return s.length;
}

private
void adbg_disasm_format_operands_right(adbg_disasm_t *disasm, ref adbg_string_t str, adbg_disasm_opcode_t *op) {
	for (size_t i = op.operandCount; i-- > 0;) {
		version (Trace) trace("i=%u", cast(uint)i);
		if (disasm.foperand(disasm, str, op.operands[i]))
			return;
		if (i && str.adds(sep))
			return;
	}
}
private
void adbg_disasm_format_operands_left(adbg_disasm_t *disasm, ref adbg_string_t str, adbg_disasm_opcode_t *op) {
	size_t opCount = op.operandCount - 1;
	for (size_t i; i <= opCount; ++i) {
		version (Trace) trace("i=%u", cast(uint)i);
		if (disasm.foperand(disasm, str, op.operands[i]))
			return;
		if (i < opCount && str.adds(sep))
			return;
	}
}

/// Renders the machine opcode into a buffer.
/// Params:
/// 	p = Disassembler
/// 	buffer = Character buffer
/// 	size = Buffer size
/// 	op = Opcode information
size_t adbg_disasm_machine(adbg_disasm_t *disasm, char *buffer, size_t size, adbg_disasm_opcode_t *op) {
	import adbg.utils.str : empty_string;
	
	if (buffer == null || op.machineCount == 0) {
		buffer = empty_string;
		return 0;
	}
	
	adbg_string_t s = adbg_string_t(buffer, size);
	adbg_disasm_machine_t *num = &op.machine[0];
	
	//TODO: Unpack option would mean e.g., 4*1byte on i32
	size_t edge = op.machineCount - 1;
	A: for (size_t i; i < op.machineCount; ++i, ++num) {
		switch (num.type) with (AdbgDisasmType) {
		case i8:  if (s.addx8(num.i8, true)) break A; break;
		case i16: if (s.addx16(num.i16, true)) break A; break;
		case i32: if (s.addx32(num.i32, true)) break A; break;
		case i64: if (s.addx64(num.i64, true)) break A; break;
		default:  assert(0);
		}
		if (i < edge) s.addc(' ');
	}
	
	return s.length;
}

/// Render a number onto a string.
/// Params:
/// 	s = String.
/// 	n = Number.
/// 	plus = If set, adds '+' if it's a positive number. Often an offset with a register.
/// 	nozero = If set, the number is not printed at all if equals to zero.
/// Returns: True if buffer was exhausted.
package
bool adbg_disasm_render_number(ref adbg_string_t s, ref adbg_disasm_number_t n,
	bool plus, bool nozero) {
	static immutable const(char) *hexPrefix = "0x";
	
	//TODO: function table
	//      adbg_disasm_render_number_minus0(T)
	//      addx{8,16,32,64}
	
	switch (n.type) with (AdbgDisasmType) {
	case i8:
		if (nozero && n.i8 == 0)
			return false;
		if (plus && n.i8 >= 0)
			if (s.addc('+'))
				return true;
		if (n.i8 < 0) {
			if (s.addc('-'))
				return true;
			n.u8 = cast(ubyte)((~cast(int)n.u8) + 1);
		}
		if (s.adds(hexPrefix)) // temp
			return true;
		return s.addx8(n.i8);
	case i16:
		if (nozero && n.i16 == 0)
			return false;
		if (plus && n.i16 >= 0)
			if (s.addc('+'))
				return true;
		if (n.i16 < 0) {
			if (s.addc('-'))
				return true;
			n.u16 = cast(ushort)((~cast(int)n.u16) + 1);
		}
		if (s.adds(hexPrefix)) // temp
			return true;
		return s.addx16(n.i16);
	case i32:
		if (nozero && n.i32 == 0)
			return false;
		if (plus && n.i32 >= 0)
			if (s.addc('+'))
				return true;
		if (n.i32 < 0) {
			if (s.addc('-'))
				return true;
			n.u32 = cast(uint)(~n.u32 + 1);
		}
		if (s.adds(hexPrefix)) // temp
			return true;
		return s.addx32(n.i32);
	case i64:
		if (nozero && n.i64 == 0)
			return false;
		if (plus && n.i64 >= 0)
			if (s.addc('+'))
				return true;
		if (n.i64 < 0) {
			if (s.addc('-'))
				return true;
			n.u64 = cast(uint)(~n.u64 + 1);
		}
		if (s.adds(hexPrefix)) // temp
			return true;
		return s.addx64(n.i64);
	default: assert(0);
	}
}