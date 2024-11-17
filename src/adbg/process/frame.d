/// Process frame management.
///
/// Stack frames, unwinding operations, etc.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.frame;

import adbg.error;
import adbg.machines;
import adbg.process.base; // for machine info
import adbg.process.thread; // for accessing thread information
import adbg.utils.list;

// Stack frame layouts
//
// # x86-32
//
// ## Frame Pointers
// 
// ### Windows
//
// With EBP, [EBP] points to the previous EBP value, [EBP+4] points to the return
// address, and [EBP+8] points to the first stack argument. [EBP-n] have function
// parameters.
//
// ## FPO
//
// TODO
//

extern (C):

struct adbg_stackframe_t {
	int level;
	// TODO: Frame type/function (e.g., points to memory, register, etc.)
	ulong address;
}

private
struct __machine_pc_reg {
	AdbgMachine machine;
	AdbgRegister reg;
}
// Level 0: Current location, typically Program Counter
// Level 1: Frame Pointer if available
private
static immutable __machine_pc_reg[] stackregs = [
	{ AdbgMachine.i386,	AdbgRegister.x86_eip },
	{ AdbgMachine.amd64,	AdbgRegister.amd64_rip },
	{ AdbgMachine.arm,	AdbgRegister.arm_pc },
	{ AdbgMachine.aarch64,	AdbgRegister.aarch64_pc },
];

void* adbg_frame_list(adbg_process_t *process, adbg_thread_t *thread) {
	if (process == null || thread == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	if (adbg_thread_context_update(process, thread))
		return null;
	
	// Map a set of registers to use at primary stackframe levels
	AdbgMachine mach = adbg_process_machine(process);
	AdbgRegister register;
	foreach (ref regs; stackregs) {
		if (mach == regs.machine) {
			register = regs.reg;
			goto Lfound;
		}
	}
	adbg_oops(AdbgError.unavailable);
	return null;
Lfound:
	
	// New frame list
	list_t *list = adbg_list_new(adbg_stackframe_t.sizeof, 8);
	if (list == null)
		return null;
	
	// Start with the first frame, which is always PC
	// If we can't have that, then we cannot even obtain frames at all
	adbg_register_t *reg = adbg_register_by_id(thread, register);
	if (reg == null) {
		adbg_oops(AdbgError.unavailable);
		adbg_list_close(list);
		return null;
	}
	ulong *address = cast(ulong*)adbg_register_value(reg);
	if (address == null || *address == 0) {
		adbg_list_close(list);
		return null;
	}
	adbg_stackframe_t frame = void;
	frame.level = 0;
	frame.address = *address;
	list = adbg_list_add(list, &frame);
	if (list == null) {
		adbg_list_close(list);
		return null;
	}
	
	return list;
}

size_t adbg_frame_list_count(void *list) {
	return adbg_list_count(cast(list_t*)list);
}

adbg_stackframe_t* adbg_frame_list_at(void *list, size_t index) {
	return cast(adbg_stackframe_t*)adbg_list_get(cast(list_t*)list, index);
}

void adbg_frame_list_close(void *list) {
	adbg_list_close(cast(list_t*)list);
}