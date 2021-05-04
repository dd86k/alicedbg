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

// render intel
int adbg_syntax_intel(adbg_syntax_t *p) {
	for (size_t i; i < p.index; ++i) {
		// or ref
		adbg_syntax_item_t *item = &p.buffer[i];
		
		with (AdbgSyntaxItem)
		switch (item.type) {
		case prefix:	// loop
			if (p.decoderOpts.noPrefixes)
				continue;
			p.mnemonic.add(item.svalue);
			continue;
		case mnemonic:	// add
			p.mnemonic.add(item.svalue);
			continue;
		case immediate:	// 0x50
			continue;
		case register:	// eax
		
			continue;
		case memory:	// [0x1000]
		
			continue;
		case memoryFar:	// [0x10:0x1000] -- can't take segment
		
			continue;
		case memoryRegister:	// [eax]
		
			continue;
		case memoryFarRegister:	// [0x10:eax]
		
			continue;
		case memoryRegisterOffset:	// [eax+0x100]
			
			continue;
		case memoryScaleBaseIndexScale:	// [eax+ecx*2]
		
			continue;
		case memoryScaleBase:	// [eax]
		
			continue;
		case memoryScaleIndexScaleOffset:	// [ecx*2+0x50]
		
			continue;
		case memoryScaleOffset:	// [0x50]
		
			continue;
		case memoryScaleBaseIndexScaleOffset:	// [eax+ecx*2+0x50]
		
			continue;
		case memoryScaleBaseOffset:	// [eax+0x50]
		
			continue;
		default:
			assert(0, "intel: implement disasm type");
		}
	}
	
	return 0;
}