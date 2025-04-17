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

void* adbg_frame_list(adbg_process_thread_t *thread) {
	if (thread == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	// No process attached
	if (thread.process == null) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	// Get (updated) context because PC/IP being the first frame is
	// important
	adbg_thread_context_t *ctx = adbg_process_thread_context(thread);
	if (ctx == null)
		return null;
	
	// Get register denoting PC depending on machine
	AdbgMachine mach = adbg_process_machine(thread.process);
	AdbgRegister register = void;
	foreach (ref regs; stackregs) {
		// Found it
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
	adbg_register_t *reg = adbg_register_by_id(&thread.context, register);
	if (reg == null) {
		adbg_oops(AdbgError.unavailable);
		adbg_list_close(list);
		return null;
	}
	
	void *address = adbg_register_value(reg);
	if (address == null) {
		adbg_list_close(list);
		return null;
	}
	
	adbg_stackframe_t frame = void;
	frame.level = 0;
	
	// Get its value
	switch (mach) {
	// 32-bit PC
	case AdbgMachine.i386, AdbgMachine.arm:
		frame.address = *cast(uint*)address;
		break;
	// 64-bit PC
	case AdbgMachine.amd64, AdbgMachine.aarch64:
		frame.address = *cast(ulong*)address;
		break;
	default:
		adbg_oops(AdbgError.assertion);
		adbg_list_close(list);
		return null;
	}
	
	list = adbg_list_add(list, &frame);
	if (list == null) {
		adbg_list_close(list);
		return null;
	}
	
	// TODO: Next frame
	//
	//       Frame pointers (EBP: x86, RBP: amd64, FP: arm) usually
	//       designate the next stack frame.
	//       Typically, for example under Linux (amd64), RBP is assigned
	//       for segmentation faults, but not breakpoints (in the parent
	//       process, at least, like a debugger).
	//
	//       Otherwise, the next frame will have to be obtained from
	//       debugging information (FPO, etc.)
	
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