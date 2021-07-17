/**
 * Implements the Intel syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntax.intel;

import adbg.disasm : adbg_disasm_t;
import adbg.disasm.syntaxer;

extern (C):

private immutable const(char)*[] INTEL_WIDTH = [
	"byte",    "word",    "dword",   "qword",
	"xmmword", "ymmword", "zmmword", "word?"
];

// render intel
void adbg_syntax_op_intel(ref adbg_syntaxer_t p, ref adbg_syntax_op_t op) {
	switch (op.type) {
	case AdbgSyntaxType.immediate:
		p.mnemonicBuffer.add("0x%x", op.imm.value);
		break;
	case AdbgSyntaxType.register:
		p.mnemonicBuffer.add(op.reg.name);
		break;
	case AdbgSyntaxType.memory:
		p.mnemonicBuffer.add(INTEL_WIDTH[op.mem.width]);
		p.mnemonicBuffer.add(" ptr ");
		
		//TODO: p.decoderOpts.noSegment
		if (p.segmentRegister) {
			p.mnemonicBuffer.add(p.segmentRegister);
			p.mnemonicBuffer.add(':');
		}
		
		p.mnemonicBuffer.add('[');
		
		with (AdbgSyntaxMemType)
		switch (op.mem.type) {
		case register:
			p.mnemonicBuffer.add(op.mem.base);
			break;
		case registerOffset:
			p.mnemonicBuffer.add("%s%+d", op.mem.base, op.mem.disp);
			break;
		case registerRegister:
			p.mnemonicBuffer.add("%s+%s", op.mem.base, op.mem.index);
			break;
		case registerRegisterOffset:
			p.mnemonicBuffer.add("%s+%s%+d", op.mem.base, op.mem.index, op.mem.disp);
			break;
		default: assert(0);
		}
		
		p.mnemonicBuffer.add(']');
		break;
	default: assert(0);
	}
	/*with (AdbgSyntaxItem)
	switch (i.type) {
	case immediate:	// 0x50
		p.mnemonicBuffer.add("0x%x", i.immediate.value);
		return;
	case register:	// eax
		p.mnemonicBuffer.add(i.register.name);
		return;
	case realRegister:	// st,st(1)
		p.mnemonicBuffer.add(i.realRegister.name);
		if (i.realRegister.index)
			p.mnemonicBuffer.add("(%d)", i.realRegister.index);
		return;
	case memory:	// dword ptr [0x1000]
		p.mnemonicBuffer.add(INTEL_WIDTH[i.memory.width]);
		p.mnemonicBuffer.add(" ptr ");
		if (p.segmentRegister) {
			p.mnemonicBuffer.add(p.segmentRegister);
			p.mnemonicBuffer.add(':');
		}
		p.mnemonicBuffer.add('[');
		adbg_syntax_render_offset(p, i.memory.offset);
		p.mnemonicBuffer.add(']');
		return;
	case memoryFar:	// [0x10:0x1000] -- segment registers are ignored
		p.mnemonicBuffer.add("%s ptr [0x%x:%x]",
			INTEL_WIDTH[i.memoryFar.width],
			i.memoryFar.segment, i.memoryFar.offset.u32);
		return;
	case memoryRegister:	// cs:[eax]
		p.mnemonicBuffer.add(INTEL_WIDTH[i.memoryRegisterOffset.width]);
		p.mnemonicBuffer.add(" ptr ");
		if (p.segmentRegister) {
			p.mnemonicBuffer.add(i.memoryRegister.register);
			p.mnemonicBuffer.add(':');
		}
		p.mnemonicBuffer.add("[%s]", i.memoryRegister.register);
		return;
	case memoryRegisterFar:	// dword ptr [0x10:eax]
		p.mnemonicBuffer.add("%s ptr [%x:%s]",
			INTEL_WIDTH[i.memoryRegisterFar.width],
			i.memoryRegisterFar.segment,
			i.memoryRegisterFar.register);
		return;
	case memoryRegisterOffset:	// dword ptr cs:[eax+0x100]
		p.mnemonicBuffer.add(INTEL_WIDTH[i.memoryRegisterOffset.width]);
		p.mnemonicBuffer.add(" ptr ");
		if (p.segmentRegister) {
			p.mnemonicBuffer.add(p.segmentRegister);
			p.mnemonicBuffer.add(':');
		}
		p.mnemonicBuffer.add('[');
		p.mnemonicBuffer.add(i.memoryRegisterOffset.register);
		adbg_syntax_render_offset(p, i.memoryRegisterOffset.offset);
		p.mnemonicBuffer.add(']');
		return;
	case memoryScaleBaseIndexScale:	// dword ptr [eax+ecx*2]
	
		return;
	case memoryScaleBase:	// dword ptr cs:[eax]
	
		return;
	case memoryScaleIndexScaleOffset:	// dword ptr cs:[ecx*2+0x50]
	
		return;
	case memoryScaleOffset:	// dword ptr cs:[0x50]
	
		return;
	case memoryScaleBaseIndexScaleOffset:	// dword ptr cs:[eax+ecx*2+0x50]
	
		return;
	case memoryScaleBaseOffset:	// dword ptr cs:[eax+0x50]
	
		return;
	default:
		assert(0, "intel: implement disasm type");
	}*/
}