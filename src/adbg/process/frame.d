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
import adbg.process.memory;
import adbg.process.thread; // for accessing thread information
import adbg.utils.list;

extern (C):

private enum FRAME_MAX_DEPTH = 128;

alias adbg_frames_t = list_t;

struct adbg_stackframe_t {
	int level;
	// TODO: Frame type/function (e.g., points to memory, register, etc.)
	//       Shouldn't that be on-demand and not done eagerly?
	//       What was the point for this thing again?
	ulong address;
}

private
struct __machine_stack_regs {
	AdbgMachine machine;
	AdbgRegister pc_reg;
	AdbgRegister fp_reg;
	ubyte ptr_size;
}

private
static immutable __machine_stack_regs[] stackregs = [
	{ AdbgMachine.i386,    AdbgRegister.x86_eip,     AdbgRegister.x86_ebp,    4 },
	{ AdbgMachine.amd64,   AdbgRegister.amd64_rip,   AdbgRegister.amd64_rbp,  8 },
	{ AdbgMachine.arm,     AdbgRegister.arm_pc,      AdbgRegister.arm_fp,     4 },
	{ AdbgMachine.aarch64, AdbgRegister.aarch64_pc,  AdbgRegister.aarch64_fp, 8 },
];

adbg_frames_t* adbg_frame_list(adbg_process_thread_t *thread) {
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
	
	// Get register denoting PC and FP depending on machine
	AdbgMachine mach = adbg_process_machine(thread.process);
	AdbgRegister pc_register = void;
	AdbgRegister fp_register = void;
	ubyte ptr_size = void;
	foreach (ref regs; stackregs) {
		if (mach == regs.machine) {
			pc_register = regs.pc_reg;
			fp_register = regs.fp_reg;
			ptr_size = regs.ptr_size;
			goto Lfound;
		}
	}

	adbg_oops(AdbgError.unavailable);
	return null;

Lfound:
	// New frame list
	adbg_frames_t *frames = cast(adbg_frames_t*)adbg_list_new(adbg_stackframe_t.sizeof, 8);
	if (frames == null)
		return null;

	// Start with the first frame, which is always PC
	// If we can't have that, then we cannot even obtain frames at all
	adbg_register_t *pc_reg = adbg_register_by_id(&thread.context, pc_register);
	if (pc_reg == null) {
		adbg_oops(AdbgError.unavailable);
		adbg_list_close(frames);
		return null;
	}

	// Build frame 0 (PC)
	void *pc_val = adbg_register_value(pc_reg);
	if (pc_val == null) {
		adbg_list_close(frames);
		return null;
	}
	adbg_stackframe_t frame = void;
	frame.level = 0;
	frame.address = (ptr_size == 4) ? *cast(uint*)pc_val : *cast(ulong*)pc_val;
	frames = adbg_list_add(frames, &frame);
	if (frames == null) {
		adbg_list_close(frames);
		return null;
	}

	// Walk frame pointer chain
	adbg_register_t *fp_reg = adbg_register_by_id(&thread.context, fp_register);
	if (fp_reg == null)
		return frames; // No FP available, return with just level 0

	void *fp_val = adbg_register_value(fp_reg);
	if (fp_val == null)
		return frames;

	ulong fp = (ptr_size == 4) ? *cast(uint*)fp_val : *cast(ulong*)fp_val;
	int level = 1;
	while (fp != 0 && level < FRAME_MAX_DEPTH) {
		// Alignment check
		if (fp % ptr_size != 0)
			break;

		// Read [fp] = saved_fp, [fp + ptr_size] = return_address
		ulong saved_fp = void;
		ulong ret_addr = void;

		switch (ptr_size) {
		case 4:
			uint[2] pair = void;
			if (adbg_memory_read(thread.process, cast(size_t)fp, &pair, pair.sizeof) != 0)
				break;
			saved_fp = pair[0];
			ret_addr = pair[1];
			break;
		case 8:
			ulong[2] pair = void;
			if (adbg_memory_read(thread.process, cast(size_t)fp, &pair, pair.sizeof) != 0)
				break;
			saved_fp = pair[0];
			ret_addr = pair[1];
			break;
		default:
			ret_addr = 0;
		}

		if (ret_addr == 0)
			break;

		frame.level = level;
		frame.address = ret_addr;
		frames = adbg_list_add(frames, &frame);
		if (frames == null)
			return null;

		// Forward progress check
		// Most stacks grow down and FP chain grows up
		if (saved_fp <= fp)
			break;

		fp = saved_fp;
		level++;
	}

	return frames;
}

size_t adbg_frame_list_count(adbg_frames_t *list) {
	return adbg_list_count(cast(list_t*)list);
}

adbg_stackframe_t* adbg_frame_list_at(adbg_frames_t *list, size_t index) {
	return cast(adbg_stackframe_t*)adbg_list_get(cast(list_t*)list, index);
}

void adbg_frame_list_close(adbg_frames_t *list) {
	adbg_list_close(cast(list_t*)list);
}