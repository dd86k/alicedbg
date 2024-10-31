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

// NOTE: Stack frame layouts
//
//       # Windows
//
//       There are basically two layouts: EBP frames and FPO frames.
//
//       With EBP, EBP points to the previous value, EBP+4 points to the return
//       address, and EBP+8 points to the first stack argument.
//
//       With FPO (POGO?)... To find out.
//
//       # Linux
//

extern (C):

struct adbg_stackframe_t {
	int level;
	ulong address;
	// TODO: Function information
	// TODO: Line information
}

private
struct __machine_pc_reg {
	AdbgMachine machine;
	AdbgRegister[] set;
}
// Level 0: Current location, typically Program Counter
// Level 1: Frame Pointer if available
private
static immutable __machine_pc_reg[] stackregs = [
	{ AdbgMachine.i386,	[ AdbgRegister.x86_eip,	AdbgRegister.x86_ebp ] },
	{ AdbgMachine.amd64,	[ AdbgRegister.amd64_rip,	AdbgRegister.amd64_rbp ] },
	{ AdbgMachine.arm,	[ AdbgRegister.arm_pc,	AdbgRegister.arm_fp ] },
	{ AdbgMachine.aarch64,	[ AdbgRegister.aarch64_pc,	AdbgRegister.aarch64_fp ] },
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
	immutable(AdbgRegister)[] registers;
	foreach (ref regs; stackregs) {
		if (mach == regs.machine) {
			registers = regs.set;
			break;
		}
	}
	if (registers.length == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// New frame list
	list_t *list = adbg_list_new(adbg_stackframe_t.sizeof, 8);
	if (list == null)
		return null;
	
	// Start with the first frame, which is always PC
	// If we can't have that, then we cannot even obtain frames at all
	adbg_register_t *reg = adbg_register_by_id(thread, registers[0]);
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
	
	// Add additional frames from additional registers
	// As best as we can, otherwise just return the list
	foreach (AdbgRegister r; registers[1..$]) {
		reg = adbg_register_by_id(thread, r);
		if (reg == null)
			break;
		address = cast(ulong*)adbg_register_value(reg);
		if (address == null || *address == 0)
			break;
		
		++frame.level; // frame[0] is level=0, so increment
		frame.address = *address;
		list = adbg_list_add(list, &frame);
		if (list == null) {
			adbg_list_close(list);
			return null;
		}
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