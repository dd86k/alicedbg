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

private immutable const(char)*[] WIDTHS = [
	"byte",    "word",    "dword",   "qword",
	"xmmword", "ymmword", "zmmword", "word?"
];

// render intel
void adbg_syntax_intel_item(adbg_syntax_t *p, adbg_syntax_item_t *i) {
	
	
	with (AdbgSyntaxItem)
	switch (i.type) {
	case prefix:	// loop
		if (p.decoderOpts.noPrefixes)
			return;
		p.mnemonic.add(i.svalue);
		return;
	case mnemonic:	// add
		p.mnemonic.add(i.svalue);
		return;
	case immediate:	// 0x50
		adbg_syntax_render_immediate_hex(p, i);
		return;
	case register:	// eax
	
		return;
	case realRegister:	// eax
	
		return;
	case memory:	// [0x1000]
	
		return;
	case memoryFar:	// [0x10:0x1000] -- can't take segment
	
		return;
	case memoryRegister:	// [eax]
	
		return;
	case memoryRegisterFar:	// [0x10:eax]
	
		return;
	case memoryRegisterOffset:	// [eax+0x100]
		
		return;
	case memoryScaleBaseIndexScale:	// [eax+ecx*2]
	
		return;
	case memoryScaleBase:	// [eax]
	
		return;
	case memoryScaleIndexScaleOffset:	// [ecx*2+0x50]
	
		return;
	case memoryScaleOffset:	// [0x50]
	
		return;
	case memoryScaleBaseIndexScaleOffset:	// [eax+ecx*2+0x50]
	
		return;
	case memoryScaleBaseOffset:	// [eax+0x50]
	
		return;
	default:
		assert(0, "intel: implement disasm type");
	}
}