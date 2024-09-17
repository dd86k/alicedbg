/// Thread management.
///
/// Including stack frame and context information.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.thread;

import adbg.machines : AdbgMachine;
import adbg.error;
import adbg.process.base;
import adbg.utils.list;
import core.stdc.stdlib : malloc, free;
import core.stdc.stdio : snprintf;

version (Windows) {
	import adbg.include.windows.tlhelp32;
	import adbg.include.windows.wow64apiset;
	import adbg.include.windows.winnt;
	import core.sys.windows.basetsd;
	import core.sys.windows.winbase;
	import core.sys.windows.windef;
} else version (linux) {
	import adbg.include.linux.ptrace;
	import adbg.include.linux.user;
	import core.stdc.ctype : isdigit;
	import core.stdc.stdio : snprintf;
	import core.stdc.stdlib : atoi;
	import core.sys.posix.dirent;
	import core.sys.posix.libgen : basename;
} else version (FreeBSD) {
	import adbg.include.freebsd.ptrace;
	import adbg.include.freebsd.reg;
	import core.sys.posix.sys.types : pid_t;
}

extern (C):

private enum THREAD_LIST_CAPACITY = 32;

// TODO: Move regset fat pointer in thread

struct adbg_thread_t {
version (Windows) {
	HANDLE handle;
	int id;
}
version (linux) {
	pid_t handle;
}
version (FreeBSD) {
	pid_t handle;
}
	adbg_thread_context_t context;
}

/// Get a list of threads for target process.
/// Params: process = Process.
/// Returns: Thread list.
int adbg_thread_list_update(adbg_process_t *process) {
	version (Trace) trace("process=%p", process);
version (Windows) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (process.pid == 0)
		return adbg_oops(AdbgError.uninitiated);
	
	if (process.thread_list == null)
		process.thread_list = adbg_list_new(adbg_thread_t.sizeof, THREAD_LIST_CAPACITY);
	if (process.thread_list == null)
		return adbg_errno();
	
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, process.pid);
	if (snap == INVALID_HANDLE_VALUE) {
		adbg_list_free(process.thread_list);
		return adbg_oops(AdbgError.os);
	}
	scope(exit) CloseHandle(snap);
	
	THREADENTRY32 te32 = void;
	te32.dwSize = THREADENTRY32.sizeof;
	if (Thread32First(snap, &te32) == FALSE) {
		adbg_list_free(process.thread_list);
		return adbg_oops(AdbgError.os);
	}
	
	adbg_list_clear(process.thread_list);
	adbg_thread_t t = void;
	adbg_thread_context_config(&t.context, adbg_process_machine(process));
	do {
		if (te32.th32OwnerProcessID != process.pid)
			continue;
		
		enum THREAD_ACCESS = SYNCHRONIZE | THREAD_QUERY_INFORMATION |
			THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
			THREAD_SUSPEND_RESUME;
		
		// Get thread handle
		t.handle = OpenThread(THREAD_ACCESS, FALSE, te32.th32ThreadID);
		if (t.handle == INVALID_HANDLE_VALUE) {
			adbg_list_free(process.thread_list);
			return adbg_oops(AdbgError.os);
		}
		
		// Set thread ID
		t.id = te32.th32ThreadID;
		process.thread_list = adbg_list_add(process.thread_list, &t);
		if (process.thread_list == null) {
			adbg_list_free(process.thread_list);
			return adbg_errno();
		}
	} while (Thread32Next(snap, &te32));
	
	return 0;
} else version (linux) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (process.pid == 0)
		return adbg_oops(AdbgError.uninitiated);
	
	if (process.thread_list == null)
		process.thread_list = adbg_list_new(adbg_thread_t.sizeof, THREAD_LIST_CAPACITY);
	if (process.thread_list == null)
		return adbg_oops(AdbgError.crt);
	
	enum BSZ = 32; // "/proc/4294967295/task/".sizeof == 22
	char[BSZ] path = void;
	int l = snprintf(path.ptr, BSZ, "/proc/%u/task", process.pid);
	if (l < 0)
		return adbg_oops(AdbgError.crt);
	
	DIR *procfd = opendir(path.ptr);
	if (procfd == null)
		return adbg_oops(AdbgError.crt);
	scope(exit) closedir(procfd);
	
	// Go through kernel thread IDs
	adbg_list_clear(process.thread_list);
	adbg_thread_t t = void;
	adbg_thread_context_config(&t.context, adbg_process_machine(process));
	for (dirent *entry = void; (entry = readdir(procfd)) != null;) {
		// readdir() includes "." and "..", skip them
		if (isdigit(entry.d_name[0]) == 0)
			continue;
		
		t.handle = cast(pid_t)atoi( basename(entry.d_name.ptr) );
		process.thread_list = adbg_list_add(process.thread_list, &t);
		if (process.thread_list == null) {
			adbg_list_free(process.thread_list);
			return adbg_errno();
		}
	}
	
	return 0;
} else {
	// TODO: FreeBSD PT_GETLWPLIST
	return adbg_oops(AdbgError.unimplemented);
}
}

/// Get thread from list using index.
/// Params:
/// 	process = Process instance.
/// 	index = Zero-based index.
/// Returns: Thread instance. On error, null.
adbg_thread_t* adbg_thread_list_get(adbg_process_t *process, size_t index) {
	version (Trace) trace("process=%p index=%zu", process, index);
	if (process == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	// NOTE: adbg_list_get checks both list pointer and index and sets error
	return cast(adbg_thread_t*)adbg_list_get(process.thread_list, index);
}

/// Get the thread ID out of this thread instance.
/// Params: thread = Thread instance.
/// Returns: Thread ID. On error, zero.
int adbg_thread_id(adbg_thread_t *thread) {
	version (Trace) trace("thread=%p", thread);
version (Windows) {
	if (thread == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	return thread.id;
} else version (Posix) {
	if (thread == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	return cast(int)thread.handle;
} else {
	adbg_oops(AdbgError.unimplemented);
	return 0;
}
}

//
// Context management
//

// TODO: Support FPU registers (f32, f64, f80 types)
// TODO: Thread struct type, to hold its context, and other info

enum AdbgRegister {
	// x86
	x86_eip	= 0,	/// (x86) Extended Instruction Pointer
	x86_eflags	= 1,	/// (x86) Extended FLAGS
	x86_eax	= 2,	/// (x86)
	x86_ebx	= 3,	/// (x86)
	x86_ecx	= 4,	/// (x86)
	x86_edx	= 5,	/// (x86)
	x86_esp	= 6,	/// (x86) Extended Stack Pointer (top of stack)
	x86_ebp	= 7,	/// (x86) Extended Base Pointer (start of function)
	x86_esi	= 8,	/// (x86) Extended Source Index
	x86_edi	= 9,	/// (x86) Extended Destination Index
	x86_cs	= 10,	/// (x86) Code Segment
	x86_ds	= 11,	/// (x86) Data Segment
	x86_es	= 12,	/// (x86) Extra Segment
	x86_fs	= 13,	/// (x86) 
	x86_gs	= 14,	/// (x86) 
	x86_ss	= 15,	/// (x86) Stack Segment
	
	// x86-64
	amd64_rip	= 0,	/// (x86-64) Re-extended Intruction Pointer
	amd64_rflags	= 1,	/// (x86-64) Re-extended FLAGS
	amd64_rax	= 2,	/// (x86-64) 
	amd64_rbx	= 3,	/// (x86-64) 
	amd64_rcx	= 4,	/// (x86-64) 
	amd64_rdx	= 5,	/// (x86-64) 
	amd64_rsp	= 6,	/// (x86-64) Re-extended Stack Pointer (top of stack)
	amd64_rbp	= 7,	/// (x86-64) Re-extended Base Pointer (start of function)
	amd64_rsi	= 8,	/// (x86-64) Re-extended Source Index
	amd64_rdi	= 9,	/// (x86-64) Re-extended Destination Index
	amd64_r8	= 10,	/// (x86-64) 
	amd64_r9	= 11,	/// (x86-64) 
	amd64_r10	= 12,	/// (x86-64) 
	amd64_r11	= 13,	/// (x86-64) 
	amd64_r12	= 14,	/// (x86-64) 
	amd64_r13	= 15,	/// (x86-64) 
	amd64_r14	= 16,	/// (x86-64) 
	amd64_r15	= 17,	/// (x86-64) 
	amd64_cs	= 18,	/// (x86-64) Code Segment
	amd64_ds	= 19,	/// (x86-64) Data Segment
	amd64_es	= 20,	/// (x86-64) Extra Segment
	amd64_fs	= 21,	/// (x86-64) 
	amd64_gs	= 22,	/// (x86-64) 
	amd64_ss	= 23,	/// (x86-64) Stack Segment
	
	// Arm (A32)
	arm_r0	= 0,	/// (Arm) 
	arm_r1	= 1,	/// (Arm) 
	arm_r2	= 2,	/// (Arm) 
	arm_r3	= 3,	/// (Arm) 
	arm_r4	= 4,	/// (Arm) 
	arm_r5	= 5,	/// (Arm) 
	arm_r6	= 6,	/// (Arm) 
	arm_r7	= 7,	/// (Arm) 
	arm_r8	= 8,	/// (Arm) 
	arm_r9	= 9,	/// (Arm) 
	arm_r10	= 10,	/// (Arm) 
	arm_r11	= 11,	/// (Arm) 
	arm_fp	= arm_r11,	/// (Arm) Frame Pointer (R11)
	arm_r12	= 12,	/// (Arm) 
	arm_ip	= arm_r12,	/// (Arm) (R12)
	arm_r13	= 13,	/// (Arm) 
	arm_sp	= arm_r13,	/// (Arm) Stack Pointer (R13)
	arm_r14	= 14,	/// (Arm) 
	arm_lr	= arm_r14,	/// (Arm) Link Register (R14)
	arm_r15	= 15,	/// (Arm) 
	arm_pc	= arm_r15,	/// (Arm) Program Counter (R15)
	arm_cpsr	= 16,	/// (Arm) Current Program Status Register (System)
	
	// AArch64 (A64)
	aarch64_x0	= 0,	/// (AArch64) 
	aarch64_x1	= 1,	/// (AArch64) 
	aarch64_x2	= 2,	/// (AArch64) 
	aarch64_x3	= 3,	/// (AArch64) 
	aarch64_x4	= 4,	/// (AArch64) 
	aarch64_x5	= 5,	/// (AArch64) 
	aarch64_x6	= 6,	/// (AArch64) 
	aarch64_x7	= 7,	/// (AArch64) 
	aarch64_x8	= 8,	/// (AArch64) 
	aarch64_x9	= 9,	/// (AArch64) 
	aarch64_x10	= 10,	/// (AArch64) 
	aarch64_x11	= 11,	/// (AArch64) 
	aarch64_x12	= 12,	/// (AArch64) 
	aarch64_x13	= 13,	/// (AArch64) 
	aarch64_x14	= 14,	/// (AArch64) 
	aarch64_x15	= 15,	/// (AArch64) 
	aarch64_x16	= 16,	/// (AArch64) 
	aarch64_x17	= 17,	/// (AArch64) 
	aarch64_x18	= 18,	/// (AArch64) 
	aarch64_x19	= 19,	/// (AArch64) 
	aarch64_x20	= 20,	/// (AArch64) 
	aarch64_x21	= 21,	/// (AArch64) 
	aarch64_x22	= 22,	/// (AArch64) 
	aarch64_x23	= 23,	/// (AArch64) 
	aarch64_x24	= 24,	/// (AArch64) 
	aarch64_x25	= 25,	/// (AArch64) 
	aarch64_x26	= 26,	/// (AArch64) 
	aarch64_x27	= 27,	/// (AArch64) 
	aarch64_x28	= 28,	/// (AArch64) 
	aarch64_x29	= 29,	/// (AArch64) 
	aarch64_fp	= aarch64_x29,	/// (AArch64) Frame Pointer (X29)
	aarch64_x30	= 30,	/// (AArch64) 
	aarch64_lr	= aarch64_x30,	/// (AArch64) Link Register (X30)
	aarch64_sp	= 31,	/// (AArch64) Stack Pointer
	aarch64_pc	= 32,	/// (AArch64) Program Counter
}

/// Register size
enum AdbgRegisterType : ubyte {
	u8, u16, u32, u64,
	f32, f64
}

/// Register 
enum AdbgRegisterFormat {
	dec,
	hex,
	hexPadded,
}

/// Register name and type.
struct adbg_register_info_t {
	const(char) *name;	/// Register name
	AdbgRegisterType type;	/// Register type (size)
}

/// Register structure, designs a single register for UI ends to understand
struct adbg_register_t {
	/// Register name and type.
	adbg_register_info_t info;
	union { // Data
		ulong  u64;	/// Register data: ulong (u64)
		uint   u32;	/// Register data: uint (u32)
		ushort u16;	/// Register data: ushort (u16)
		ubyte  u8;	/// Register data: ubyte (u8)
		double f64;	/// Register data: double (f64)
		float  f32;	/// Register data: float (f32)
	}
}

/// Represents a thread context structure with the register values once a
/// process is paused.
struct adbg_thread_context_t {
	/// Register count in registers field.
	size_t count;
	/// Register population, this may depends by platform.
	adbg_register_t[REG_COUNT] items;
}

// Register sets
private immutable adbg_register_info_t[] regset_x86 = [
	{ "eip",	AdbgRegisterType.u32 },
	{ "eflags",	AdbgRegisterType.u32 },
	{ "eax",	AdbgRegisterType.u32 },
	{ "ebx",	AdbgRegisterType.u32 },
	{ "ecx",	AdbgRegisterType.u32 },
	{ "edx",	AdbgRegisterType.u32 },
	{ "esp",	AdbgRegisterType.u32 },
	{ "ebp",	AdbgRegisterType.u32 },
	{ "esi",	AdbgRegisterType.u32 },
	{ "edi",	AdbgRegisterType.u32 },
	{ "cs",	AdbgRegisterType.u16 },
	{ "ds",	AdbgRegisterType.u16 },
	{ "es",	AdbgRegisterType.u16 },
	{ "fs",	AdbgRegisterType.u16 },
	{ "gs",	AdbgRegisterType.u16 },
	{ "ss",	AdbgRegisterType.u16 },
];
private immutable adbg_register_info_t[] regset_x86_64 = [
	{ "rip",	AdbgRegisterType.u64 },
	{ "rflags",	AdbgRegisterType.u64 },
	{ "rax",	AdbgRegisterType.u64 },
	{ "rbx",	AdbgRegisterType.u64 },
	{ "rcx",	AdbgRegisterType.u64 },
	{ "rdx",	AdbgRegisterType.u64 },
	{ "rsp",	AdbgRegisterType.u64 },
	{ "rbp",	AdbgRegisterType.u64 },
	{ "rsi",	AdbgRegisterType.u64 },
	{ "rdi",	AdbgRegisterType.u64 },
	{ "r8",	AdbgRegisterType.u64 },
	{ "r9",	AdbgRegisterType.u64 },
	{ "r10",	AdbgRegisterType.u64 },
	{ "r11",	AdbgRegisterType.u64 },
	{ "r12",	AdbgRegisterType.u64 },
	{ "r13",	AdbgRegisterType.u64 },
	{ "r14",	AdbgRegisterType.u64 },
	{ "r15",	AdbgRegisterType.u64 },
	{ "cs",	AdbgRegisterType.u16 },
	{ "ds",	AdbgRegisterType.u16 },
	{ "es",	AdbgRegisterType.u16 },
	{ "fs",	AdbgRegisterType.u16 },
	{ "gs",	AdbgRegisterType.u16 },
	{ "ss",	AdbgRegisterType.u16 },
];
private immutable adbg_register_info_t[] regset_arm = [
	{ "r0",	AdbgRegisterType.u32 },
	{ "r1",	AdbgRegisterType.u32 },
	{ "r2",	AdbgRegisterType.u32 },
	{ "r3",	AdbgRegisterType.u32 },
	{ "r4",	AdbgRegisterType.u32 },
	{ "r5",	AdbgRegisterType.u32 },
	{ "r6",	AdbgRegisterType.u32 },
	{ "r7",	AdbgRegisterType.u32 },
	{ "r8",	AdbgRegisterType.u32 },
	{ "r9",	AdbgRegisterType.u32 },
	{ "r10",	AdbgRegisterType.u32 },
	{ "fp",	AdbgRegisterType.u32 },
	{ "ip",	AdbgRegisterType.u32 },
	{ "sp",	AdbgRegisterType.u32 },
	{ "lr",	AdbgRegisterType.u32 },
	{ "pc",	AdbgRegisterType.u32 },
	{ "cpsr",	AdbgRegisterType.u32 },
];
private immutable adbg_register_info_t[] regset_aarch64 = [
	{ "x0",	AdbgRegisterType.u64 },
	{ "x1",	AdbgRegisterType.u64 },
	{ "x2",	AdbgRegisterType.u64 },
	{ "x3",	AdbgRegisterType.u64 },
	{ "x4",	AdbgRegisterType.u64 },
	{ "x5",	AdbgRegisterType.u64 },
	{ "x6",	AdbgRegisterType.u64 },
	{ "x7",	AdbgRegisterType.u64 },
	{ "x8",	AdbgRegisterType.u64 },
	{ "x9",	AdbgRegisterType.u64 },
	{ "x10",	AdbgRegisterType.u64 },
	{ "x11",	AdbgRegisterType.u64 },
	{ "x12",	AdbgRegisterType.u64 },
	{ "x13",	AdbgRegisterType.u64 },
	{ "x14",	AdbgRegisterType.u64 },
	{ "x15",	AdbgRegisterType.u64 },
	{ "x16",	AdbgRegisterType.u64 },
	{ "x17",	AdbgRegisterType.u64 },
	{ "x18",	AdbgRegisterType.u64 },
	{ "x19",	AdbgRegisterType.u64 },
	{ "x20",	AdbgRegisterType.u64 },
	{ "x21",	AdbgRegisterType.u64 },
	{ "x22",	AdbgRegisterType.u64 },
	{ "x23",	AdbgRegisterType.u64 },
	{ "x24",	AdbgRegisterType.u64 },
	{ "x25",	AdbgRegisterType.u64 },
	{ "x26",	AdbgRegisterType.u64 },
	{ "x27",	AdbgRegisterType.u64 },
	{ "x28",	AdbgRegisterType.u64 },
	{ "fp",	AdbgRegisterType.u64 },
	{ "lr",	AdbgRegisterType.u64 },
	{ "sp",	AdbgRegisterType.u64 },
	{ "pc",	AdbgRegisterType.u64 },
];

version (X86)
	/// Buffer size for register set.
	private enum REG_COUNT = regset_x86.length;
else version (X86_64)
	/// Ditto
	private enum REG_COUNT = regset_x86_64.length;
else version (ARM)
	/// Ditto
	private enum REG_COUNT = regset_arm.length;
else version (AArch64)
	/// Ditto
	private enum REG_COUNT = regset_aarch64.length;
else
	/// Ditto
	private enum REG_COUNT = 0;

adbg_register_t* adbg_register_get(adbg_thread_t *thread, size_t index) {
	version (Trace) trace("thread=%p index=%zu", thread, index);
	if (thread == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	if (index >= thread.context.count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	return &thread.context.items[index];
}

const(char)* adbg_register_name(adbg_register_t *register) {
	version (Trace) trace("register=%p", register);
	if (register == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return register.info.name;
}

// Configure register set, used internally
private
void adbg_thread_context_config(adbg_thread_context_t *ctx, AdbgMachine mach) {
	version (Trace) trace("ctx=%p mach=%d", ctx, mach);
	assert(ctx);
	
	// Select register set
	immutable(adbg_register_info_t)[] regs = void;
	switch (mach) with (AdbgMachine) {
	case i386:	regs = regset_x86; break;
	case amd64:	regs = regset_x86_64; break;
	case arm:	regs = regset_arm; break;
	case aarch64:	regs = regset_aarch64; break;
	default:	regs = [];
	}
	
	version (Trace) trace("regs.length=%d", cast(int)regs.length);
	for (size_t i; i < regs.length; ++i)
		ctx.items[i].info = regs[i];
	ctx.count = regs.length;
}

// Update the context for thread
int adbg_thread_context_update(adbg_process_t *proc, adbg_thread_t *thread) {
	version (Trace) trace("proc=%p thread=%p", proc, thread);
	
	if (proc == null || thread == null)
		return adbg_oops(AdbgError.invalidArgument);
	
version (Win64) {
	AdbgMachine mach = adbg_process_machine(proc);
	version (X86_64) switch (mach) {
	case AdbgMachine.amd64:
		CONTEXT_X64 winctx = void; // CONTEXT
		winctx.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext(thread.handle, cast(LPCONTEXT)&winctx) == FALSE) {
			return adbg_oops(AdbgError.os);
		}
		thread.context.items[AdbgRegister.amd64_rip].u64    = winctx.Rip;
		thread.context.items[AdbgRegister.amd64_rflags].u64 = winctx.EFlags;
		thread.context.items[AdbgRegister.amd64_rax].u64    = winctx.Rax;
		thread.context.items[AdbgRegister.amd64_rbx].u64    = winctx.Rbx;
		thread.context.items[AdbgRegister.amd64_rcx].u64    = winctx.Rcx;
		thread.context.items[AdbgRegister.amd64_rdx].u64    = winctx.Rdx;
		thread.context.items[AdbgRegister.amd64_rsp].u64    = winctx.Rsp;
		thread.context.items[AdbgRegister.amd64_rbp].u64    = winctx.Rbp;
		thread.context.items[AdbgRegister.amd64_rsi].u64    = winctx.Rsi;
		thread.context.items[AdbgRegister.amd64_rdi].u64    = winctx.Rdi;
		thread.context.items[AdbgRegister.amd64_r8].u64     = winctx.R8;
		thread.context.items[AdbgRegister.amd64_r9].u64     = winctx.R9;
		thread.context.items[AdbgRegister.amd64_r10].u64    = winctx.R10;
		thread.context.items[AdbgRegister.amd64_r11].u64    = winctx.R11;
		thread.context.items[AdbgRegister.amd64_r12].u64    = winctx.R12;
		thread.context.items[AdbgRegister.amd64_r13].u64    = winctx.R13;
		thread.context.items[AdbgRegister.amd64_r14].u64    = winctx.R14;
		thread.context.items[AdbgRegister.amd64_r15].u64    = winctx.R15;
		thread.context.items[AdbgRegister.amd64_cs].u64     = winctx.SegCs;
		thread.context.items[AdbgRegister.amd64_ds].u64     = winctx.SegDs;
		thread.context.items[AdbgRegister.amd64_es].u64     = winctx.SegEs;
		thread.context.items[AdbgRegister.amd64_fs].u64     = winctx.SegFs;
		thread.context.items[AdbgRegister.amd64_gs].u64     = winctx.SegGs;
		thread.context.items[AdbgRegister.amd64_ss].u64     = winctx.SegSs;
		break;
	case AdbgMachine.i386: // WoW64 process
		WOW64_CONTEXT winctxwow64 = void;
		winctxwow64.ContextFlags = CONTEXT_ALL;
		if (Wow64GetThreadContext(thread.handle, &winctxwow64) == FALSE) {
			return adbg_oops(AdbgError.os);
		}
		thread.context.items[AdbgRegister.x86_eip].u32    = winctxwow64.Eip;
		thread.context.items[AdbgRegister.x86_eflags].u32 = winctxwow64.EFlags;
		thread.context.items[AdbgRegister.x86_eax].u32    = winctxwow64.Eax;
		thread.context.items[AdbgRegister.x86_ebx].u32    = winctxwow64.Ebx;
		thread.context.items[AdbgRegister.x86_ecx].u32    = winctxwow64.Ecx;
		thread.context.items[AdbgRegister.x86_edx].u32    = winctxwow64.Edx;
		thread.context.items[AdbgRegister.x86_esp].u32    = winctxwow64.Esp;
		thread.context.items[AdbgRegister.x86_ebp].u32    = winctxwow64.Ebp;
		thread.context.items[AdbgRegister.x86_esi].u32    = winctxwow64.Esi;
		thread.context.items[AdbgRegister.x86_edi].u32    = winctxwow64.Edi;
		thread.context.items[AdbgRegister.x86_cs].u32     = winctxwow64.SegCs;
		thread.context.items[AdbgRegister.x86_ds].u32     = winctxwow64.SegDs;
		thread.context.items[AdbgRegister.x86_es].u32     = winctxwow64.SegEs;
		thread.context.items[AdbgRegister.x86_fs].u32     = winctxwow64.SegFs;
		thread.context.items[AdbgRegister.x86_gs].u32     = winctxwow64.SegGs;
		thread.context.items[AdbgRegister.x86_ss].u32     = winctxwow64.SegSs;
		break;
	default:
		return adbg_oops(AdbgError.assertion);
	}
	version (AArch64) switch (mach) {
	case AdbgMachine.aarch64:
		ARM64_NT_CONTEXT winctx = void; // CONTEXT
		winctx.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext(thread.handle, cast(LPCONTEXT)&winctx) == FALSE) {
			return adbg_oops(AdbgError.os);
		}
		thread.context.items[AdbgRegister.aarch64_x0].u64  = winctx.X0;
		thread.context.items[AdbgRegister.aarch64_x1].u64  = winctx.X1;
		thread.context.items[AdbgRegister.aarch64_x2].u64  = winctx.X2;
		thread.context.items[AdbgRegister.aarch64_x3].u64  = winctx.X3;
		thread.context.items[AdbgRegister.aarch64_x4].u64  = winctx.X4;
		thread.context.items[AdbgRegister.aarch64_x5].u64  = winctx.X5;
		thread.context.items[AdbgRegister.aarch64_x6].u64  = winctx.X6;
		thread.context.items[AdbgRegister.aarch64_x7].u64  = winctx.X7;
		thread.context.items[AdbgRegister.aarch64_x8].u64  = winctx.X8;
		thread.context.items[AdbgRegister.aarch64_x9].u64  = winctx.X9;
		thread.context.items[AdbgRegister.aarch64_x10].u64 = winctx.X10;
		thread.context.items[AdbgRegister.aarch64_x11].u64 = winctx.X11;
		thread.context.items[AdbgRegister.aarch64_x12].u64 = winctx.X12;
		thread.context.items[AdbgRegister.aarch64_x13].u64 = winctx.X13;
		thread.context.items[AdbgRegister.aarch64_x14].u64 = winctx.X14;
		thread.context.items[AdbgRegister.aarch64_x15].u64 = winctx.X15;
		thread.context.items[AdbgRegister.aarch64_x16].u64 = winctx.X16;
		thread.context.items[AdbgRegister.aarch64_x17].u64 = winctx.X17;
		thread.context.items[AdbgRegister.aarch64_x18].u64 = winctx.X18;
		thread.context.items[AdbgRegister.aarch64_x19].u64 = winctx.X19;
		thread.context.items[AdbgRegister.aarch64_x20].u64 = winctx.X20;
		thread.context.items[AdbgRegister.aarch64_x21].u64 = winctx.X21;
		thread.context.items[AdbgRegister.aarch64_x22].u64 = winctx.X22;
		thread.context.items[AdbgRegister.aarch64_x23].u64 = winctx.X23;
		thread.context.items[AdbgRegister.aarch64_x24].u64 = winctx.X24;
		thread.context.items[AdbgRegister.aarch64_x25].u64 = winctx.X25;
		thread.context.items[AdbgRegister.aarch64_x26].u64 = winctx.X26;
		thread.context.items[AdbgRegister.aarch64_x27].u64 = winctx.X27;
		thread.context.items[AdbgRegister.aarch64_x28].u64 = winctx.X28;
		thread.context.items[AdbgRegister.aarch64_x29].u64 = winctx.X29;
		thread.context.items[AdbgRegister.aarch64_x30].u64 = winctx.X30;
		thread.context.items[AdbgRegister.aarch64_lr].u64  = winctx.Lr;
		thread.context.items[AdbgRegister.aarch64_pc].u64  = winctx.Pc;
		break;
	case AdbgMachine.arm: // WoW64 process
		ARM_NT_CONTEXT winctxwow64 = void;
		winctxwow64.ContextFlags = CONTEXT_ALL;
		if (Wow64GetThreadContext(thread.handle, &winctxwow64) == FALSE) {
			return adbg_oops(AdbgError.os);
		}
		thread.context.items[AdbgRegister.arm_r0].u32   = winctxwow64.r0;
		thread.context.items[AdbgRegister.arm_r1].u32   = winctxwow64.r1;
		thread.context.items[AdbgRegister.arm_r2].u32   = winctxwow64.r2;
		thread.context.items[AdbgRegister.arm_r3].u32   = winctxwow64.r3;
		thread.context.items[AdbgRegister.arm_r4].u32   = winctxwow64.r4;
		thread.context.items[AdbgRegister.arm_r5].u32   = winctxwow64.r5;
		thread.context.items[AdbgRegister.arm_r6].u32   = winctxwow64.r6;
		thread.context.items[AdbgRegister.arm_r7].u32   = winctxwow64.r7;
		thread.context.items[AdbgRegister.arm_r8].u32   = winctxwow64.r8;
		thread.context.items[AdbgRegister.arm_r9].u32   = winctxwow64.r9;
		thread.context.items[AdbgRegister.arm_r10].u32  = winctxwow64.r10;
		thread.context.items[AdbgRegister.arm_fp].u32   = winctxwow64.r11;
		thread.context.items[AdbgRegister.arm_ip].u32   = winctxwow64.r12;
		thread.context.items[AdbgRegister.arm_sp].u32   = winctxwow64.r13;
		thread.context.items[AdbgRegister.arm_lr].u32   = winctxwow64.r14;
		thread.context.items[AdbgRegister.arm_pc].u32   = winctxwow64.Pc;
		thread.context.items[AdbgRegister.arm_cpsr].u32 = winctxwow64.cpsr;
		break;
	default:
		return adbg_oops(AdbgError.assertion);
	}
	return 0;
} else version (Win32) {
	version (X86) {
		X86_NT_CONTEXT winctx = void; // CONTEXT
		winctx.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext(tracee.htid, cast(LPCONTEXT)&winctx) == FALSE)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.x86_eip].u32    = winctx.Eip;
		thread.context.items[AdbgRegister.x86_eflags].u32 = winctx.EFlags;
		thread.context.items[AdbgRegister.x86_eax].u32    = winctx.Eax;
		thread.context.items[AdbgRegister.x86_ebx].u32    = winctx.Ebx;
		thread.context.items[AdbgRegister.x86_ecx].u32    = winctx.Ecx;
		thread.context.items[AdbgRegister.x86_edx].u32    = winctx.Edx;
		thread.context.items[AdbgRegister.x86_esp].u32    = winctx.Esp;
		thread.context.items[AdbgRegister.x86_ebp].u32    = winctx.Ebp;
		thread.context.items[AdbgRegister.x86_esi].u32    = winctx.Esi;
		thread.context.items[AdbgRegister.x86_edi].u32    = winctx.Edi;
		return 0;
	} else version (ARM) {
		ARM_NT_CONTEXT winctx = void; // CONTEXT
		winctx.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext(tracee.htid, cast(LPCONTEXT)&winctx) == FALSE)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.arm_r0].u32   = winctx.r0;
		thread.context.items[AdbgRegister.arm_r1].u32   = winctx.r1;
		thread.context.items[AdbgRegister.arm_r2].u32   = winctx.r2;
		thread.context.items[AdbgRegister.arm_r3].u32   = winctx.r3;
		thread.context.items[AdbgRegister.arm_r4].u32   = winctx.r4;
		thread.context.items[AdbgRegister.arm_r5].u32   = winctx.r5;
		thread.context.items[AdbgRegister.arm_r6].u32   = winctx.r6;
		thread.context.items[AdbgRegister.arm_r7].u32   = winctx.r7;
		thread.context.items[AdbgRegister.arm_r8].u32   = winctx.r8;
		thread.context.items[AdbgRegister.arm_r9].u32   = winctx.r9;
		thread.context.items[AdbgRegister.arm_r10].u32  = winctx.r10;
		thread.context.items[AdbgRegister.arm_fp].u32   = winctx.r11;
		thread.context.items[AdbgRegister.arm_ip].u32   = winctx.r12;
		thread.context.items[AdbgRegister.arm_sp].u32   = winctx.r13;
		thread.context.items[AdbgRegister.arm_lr].u32   = winctx.r14;
		thread.context.items[AdbgRegister.arm_pc].u32   = winctx.Pc;
		thread.context.items[AdbgRegister.arm_cpsr].u32 = winctx.cpsr;
		return 0;
	} else {
		return adbg_oops(AdbgError.unimplemented);
	}
} else version (linux) {
	//TODO: PT_GETFPREGS
	//      PT_GETWMMXREGS
	//      PT_GET_THREAD_AREA
	//      PT_GETCRUNCHREGS
	//      PT_GETVFPREGS
	//      PT_GETHBPREGS
	
	version (X86) {
		user_regs_struct u = void;
		if (ptrace(PT_GETREGS, thread.handle, null, &u) < 0)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.x86_eip].u32    = u.eip;
		thread.context.items[AdbgRegister.x86_eflags].u32 = u.eflags;
		thread.context.items[AdbgRegister.x86_eax].u32    = u.eax;
		thread.context.items[AdbgRegister.x86_ebx].u32    = u.ebx;
		thread.context.items[AdbgRegister.x86_ecx].u32    = u.ecx;
		thread.context.items[AdbgRegister.x86_edx].u32    = u.edx;
		thread.context.items[AdbgRegister.x86_esp].u32    = u.esp;
		thread.context.items[AdbgRegister.x86_ebp].u32    = u.ebp;
		thread.context.items[AdbgRegister.x86_esi].u32    = u.esi;
		thread.context.items[AdbgRegister.x86_edi].u32    = u.edi;
		thread.context.items[AdbgRegister.x86_cs].u16     = cast(ushort)u.xcs;
		thread.context.items[AdbgRegister.x86_ds].u16     = cast(ushort)u.xds;
		thread.context.items[AdbgRegister.x86_es].u16     = cast(ushort)u.xes;
		thread.context.items[AdbgRegister.x86_fs].u16     = cast(ushort)u.xfs;
		thread.context.items[AdbgRegister.x86_gs].u16     = cast(ushort)u.xgs;
		thread.context.items[AdbgRegister.x86_ss].u16     = cast(ushort)u.xss;
		return 0;
	} else version (X86_64) {
		user_regs_struct u = void;
		if (ptrace(PT_GETREGS, thread.handle, null, &u) < 0)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.amd64_rip].u64    = u.rip;
		thread.context.items[AdbgRegister.amd64_rflags].u64 = u.eflags;
		thread.context.items[AdbgRegister.amd64_rax].u64    = u.rax;
		thread.context.items[AdbgRegister.amd64_rbx].u64    = u.rbx;
		thread.context.items[AdbgRegister.amd64_rcx].u64    = u.rcx;
		thread.context.items[AdbgRegister.amd64_rdx].u64    = u.rdx;
		thread.context.items[AdbgRegister.amd64_rsp].u64    = u.rsp;
		thread.context.items[AdbgRegister.amd64_rbp].u64    = u.rbp;
		thread.context.items[AdbgRegister.amd64_rsi].u64    = u.rsi;
		thread.context.items[AdbgRegister.amd64_rdi].u64    = u.rdi;
		thread.context.items[AdbgRegister.amd64_r8].u64     = u.r8;
		thread.context.items[AdbgRegister.amd64_r9].u64     = u.r9;
		thread.context.items[AdbgRegister.amd64_r10].u64    = u.r10;
		thread.context.items[AdbgRegister.amd64_r11].u64    = u.r11;
		thread.context.items[AdbgRegister.amd64_r12].u64    = u.r12;
		thread.context.items[AdbgRegister.amd64_r13].u64    = u.r13;
		thread.context.items[AdbgRegister.amd64_r14].u64    = u.r14;
		thread.context.items[AdbgRegister.amd64_r15].u64    = u.r15;
		thread.context.items[AdbgRegister.amd64_cs].u16     = cast(ushort)u.cs;
		thread.context.items[AdbgRegister.amd64_ds].u16     = cast(ushort)u.ds;
		thread.context.items[AdbgRegister.amd64_es].u16     = cast(ushort)u.es;
		thread.context.items[AdbgRegister.amd64_fs].u16     = cast(ushort)u.fs;
		thread.context.items[AdbgRegister.amd64_gs].u16     = cast(ushort)u.gs;
		thread.context.items[AdbgRegister.amd64_ss].u16     = cast(ushort)u.ss;
		return 0;
	} else version (ARM) {
		user_regs_struct u = void;
		if (ptrace(PT_GETREGS, thread.handle, null, &u) < 0)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.arm_r0].u32   = u.r0;
		thread.context.items[AdbgRegister.arm_r1].u32   = u.r1;
		thread.context.items[AdbgRegister.arm_r2].u32   = u.r2;
		thread.context.items[AdbgRegister.arm_r3].u32   = u.r3;
		thread.context.items[AdbgRegister.arm_r4].u32   = u.r4;
		thread.context.items[AdbgRegister.arm_r5].u32   = u.r5;
		thread.context.items[AdbgRegister.arm_r6].u32   = u.r6;
		thread.context.items[AdbgRegister.arm_r7].u32   = u.r7;
		thread.context.items[AdbgRegister.arm_r8].u32   = u.r8;
		thread.context.items[AdbgRegister.arm_r9].u32   = u.r9;
		thread.context.items[AdbgRegister.arm_r10].u32  = u.r10;
		thread.context.items[AdbgRegister.arm_fp].u32   = u.fp;
		thread.context.items[AdbgRegister.arm_ip].u32   = u.ip;
		thread.context.items[AdbgRegister.arm_sp].u32   = u.sp;
		thread.context.items[AdbgRegister.arm_lr].u32   = u.lr;
		thread.context.items[AdbgRegister.arm_pc].u32   = u.pc;
		thread.context.items[AdbgRegister.arm_cpsr].u32 = u.cpsr;
		return 0;
	} else version (AArch64) {
		user_regs_struct u = void;
		if (ptrace(PT_GETREGS, thread.handle, null, &u) < 0)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.aarch64_x0].u64  = u.regs[0];
		thread.context.items[AdbgRegister.aarch64_x1].u64  = u.regs[1];
		thread.context.items[AdbgRegister.aarch64_x2].u64  = u.regs[2];
		thread.context.items[AdbgRegister.aarch64_x3].u64  = u.regs[3];
		thread.context.items[AdbgRegister.aarch64_x4].u64  = u.regs[4];
		thread.context.items[AdbgRegister.aarch64_x5].u64  = u.regs[5];
		thread.context.items[AdbgRegister.aarch64_x6].u64  = u.regs[6];
		thread.context.items[AdbgRegister.aarch64_x7].u64  = u.regs[7];
		thread.context.items[AdbgRegister.aarch64_x8].u64  = u.regs[8];
		thread.context.items[AdbgRegister.aarch64_x9].u64  = u.regs[9];
		thread.context.items[AdbgRegister.aarch64_x10].u64 = u.regs[10];
		thread.context.items[AdbgRegister.aarch64_x11].u64 = u.regs[11];
		thread.context.items[AdbgRegister.aarch64_x12].u64 = u.regs[12];
		thread.context.items[AdbgRegister.aarch64_x13].u64 = u.regs[13];
		thread.context.items[AdbgRegister.aarch64_x14].u64 = u.regs[14];
		thread.context.items[AdbgRegister.aarch64_x15].u64 = u.regs[15];
		thread.context.items[AdbgRegister.aarch64_x16].u64 = u.regs[16];
		thread.context.items[AdbgRegister.aarch64_x17].u64 = u.regs[17];
		thread.context.items[AdbgRegister.aarch64_x18].u64 = u.regs[18];
		thread.context.items[AdbgRegister.aarch64_x19].u64 = u.regs[19];
		thread.context.items[AdbgRegister.aarch64_x20].u64 = u.regs[20];
		thread.context.items[AdbgRegister.aarch64_x21].u64 = u.regs[21];
		thread.context.items[AdbgRegister.aarch64_x22].u64 = u.regs[22];
		thread.context.items[AdbgRegister.aarch64_x23].u64 = u.regs[23];
		thread.context.items[AdbgRegister.aarch64_x24].u64 = u.regs[24];
		thread.context.items[AdbgRegister.aarch64_x25].u64 = u.regs[25];
		thread.context.items[AdbgRegister.aarch64_x26].u64 = u.regs[26];
		thread.context.items[AdbgRegister.aarch64_x27].u64 = u.regs[27];
		thread.context.items[AdbgRegister.aarch64_x28].u64 = u.regs[28];
		thread.context.items[AdbgRegister.aarch64_x29].u64 = u.regs[29];
		thread.context.items[AdbgRegister.aarch64_x30].u64 = u.regs[30];
		thread.context.items[AdbgRegister.aarch64_sp].u64 = u.sp;
		thread.context.items[AdbgRegister.aarch64_pc].u64 = u.pc;
		return 0;
	} else {
		return adbg_oops(AdbgError.unimplemented);
	}
} else version (FreeBSD) {
	version (X86) {
		reg u = void;
		if (ptrace(PT_GETREGS, thread.handle, &u, 0) < 0)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.x86_eip].u32    = u.r_eip;
		thread.context.items[AdbgRegister.x86_eflags].u32 = u.r_eflags;
		thread.context.items[AdbgRegister.x86_eax].u32    = u.r_eax;
		thread.context.items[AdbgRegister.x86_ebx].u32    = u.r_ebx;
		thread.context.items[AdbgRegister.x86_ecx].u32    = u.r_ecx;
		thread.context.items[AdbgRegister.x86_edx].u32    = u.r_edx;
		thread.context.items[AdbgRegister.x86_esp].u32    = u.r_esp;
		thread.context.items[AdbgRegister.x86_ebp].u32    = u.r_ebp;
		thread.context.items[AdbgRegister.x86_esi].u32    = u.r_esi;
		thread.context.items[AdbgRegister.x86_edi].u32    = u.r_edi;
		thread.context.items[AdbgRegister.x86_cs].u16     = cast(ushort)u.r_cs;
		thread.context.items[AdbgRegister.x86_ds].u16     = cast(ushort)u.r_ds;
		thread.context.items[AdbgRegister.x86_es].u16     = cast(ushort)u.r_es;
		thread.context.items[AdbgRegister.x86_fs].u16     = cast(ushort)u.r_fs;
		thread.context.items[AdbgRegister.x86_gs].u16     = cast(ushort)u.r_gs;
		thread.context.items[AdbgRegister.x86_ss].u16     = cast(ushort)u.r_ss;
		return 0;
	} else version (X86_64) {
		reg u = void;
		if (ptrace(PT_GETREGS, thread.handle, &u, 0) < 0)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.amd64_rip].u64    = u.r_rip;
		thread.context.items[AdbgRegister.amd64_rflags].u64 = u.r_rflags;
		thread.context.items[AdbgRegister.amd64_rax].u64    = u.r_rax;
		thread.context.items[AdbgRegister.amd64_rbx].u64    = u.r_rbx;
		thread.context.items[AdbgRegister.amd64_rcx].u64    = u.r_rcx;
		thread.context.items[AdbgRegister.amd64_rdx].u64    = u.r_rdx;
		thread.context.items[AdbgRegister.amd64_rsp].u64    = u.r_rsp;
		thread.context.items[AdbgRegister.amd64_rbp].u64    = u.r_rbp;
		thread.context.items[AdbgRegister.amd64_rsi].u64    = u.r_rsi;
		thread.context.items[AdbgRegister.amd64_rdi].u64    = u.r_rdi;
		thread.context.items[AdbgRegister.amd64_r8].u64     = u.r_r8;
		thread.context.items[AdbgRegister.amd64_r9].u64     = u.r_r9;
		thread.context.items[AdbgRegister.amd64_r10].u64    = u.r_r10;
		thread.context.items[AdbgRegister.amd64_r11].u64    = u.r_r11;
		thread.context.items[AdbgRegister.amd64_r12].u64    = u.r_r12;
		thread.context.items[AdbgRegister.amd64_r13].u64    = u.r_r13;
		thread.context.items[AdbgRegister.amd64_r14].u64    = u.r_r14;
		thread.context.items[AdbgRegister.amd64_r15].u64    = u.r_r15;
		thread.context.items[AdbgRegister.amd64_cs].u16     = cast(ushort)u.r_cs;
		thread.context.items[AdbgRegister.amd64_ds].u16     = u.r_ds;
		thread.context.items[AdbgRegister.amd64_es].u16     = u.r_es;
		thread.context.items[AdbgRegister.amd64_fs].u16     = u.r_fs;
		thread.context.items[AdbgRegister.amd64_gs].u16     = u.r_gs;
		thread.context.items[AdbgRegister.amd64_ss].u16     = cast(ushort)u.r_ss;
		return 0;
	} else version (ARM) {
		reg u = void;
		if (ptrace(PT_GETREGS, thread.handle, &u, 0) < 0)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.arm_r0].u32   = u.r[0];
		thread.context.items[AdbgRegister.arm_r1].u32   = u.r[1];
		thread.context.items[AdbgRegister.arm_r2].u32   = u.r[2];
		thread.context.items[AdbgRegister.arm_r3].u32   = u.r[3];
		thread.context.items[AdbgRegister.arm_r4].u32   = u.r[4];
		thread.context.items[AdbgRegister.arm_r5].u32   = u.r[5];
		thread.context.items[AdbgRegister.arm_r6].u32   = u.r[6];
		thread.context.items[AdbgRegister.arm_r7].u32   = u.r[7];
		thread.context.items[AdbgRegister.arm_r8].u32   = u.r[8];
		thread.context.items[AdbgRegister.arm_r9].u32   = u.r[9];
		thread.context.items[AdbgRegister.arm_r10].u32  = u.r[10];
		thread.context.items[AdbgRegister.arm_fp].u32   = u.r[11];
		thread.context.items[AdbgRegister.arm_ip].u32   = u.r[12];
		thread.context.items[AdbgRegister.arm_sp].u32   = u.r_sp;
		thread.context.items[AdbgRegister.arm_lr].u32   = u.r_lr;
		thread.context.items[AdbgRegister.arm_pc].u32   = u.r_pc;
		thread.context.items[AdbgRegister.arm_cpsr].u32 = u.r_cpsr;
		return 0;
	} else version (AArch64) {
		reg u = void;
		if (ptrace(PT_GETREGS, thread.handle, &u, 0) < 0)
			return adbg_oops(AdbgError.os);
		thread.context.items[AdbgRegister.aarch64_x0].u64  = u.x[0];
		thread.context.items[AdbgRegister.aarch64_x1].u64  = u.x[1];
		thread.context.items[AdbgRegister.aarch64_x2].u64  = u.x[2];
		thread.context.items[AdbgRegister.aarch64_x3].u64  = u.x[3];
		thread.context.items[AdbgRegister.aarch64_x4].u64  = u.x[4];
		thread.context.items[AdbgRegister.aarch64_x5].u64  = u.x[5];
		thread.context.items[AdbgRegister.aarch64_x6].u64  = u.x[6];
		thread.context.items[AdbgRegister.aarch64_x7].u64  = u.x[7];
		thread.context.items[AdbgRegister.aarch64_x8].u64  = u.x[8];
		thread.context.items[AdbgRegister.aarch64_x9].u64  = u.x[9];
		thread.context.items[AdbgRegister.aarch64_x10].u64 = u.x[10];
		thread.context.items[AdbgRegister.aarch64_x11].u64 = u.x[11];
		thread.context.items[AdbgRegister.aarch64_x12].u64 = u.x[12];
		thread.context.items[AdbgRegister.aarch64_x13].u64 = u.x[13];
		thread.context.items[AdbgRegister.aarch64_x14].u64 = u.x[14];
		thread.context.items[AdbgRegister.aarch64_x15].u64 = u.x[15];
		thread.context.items[AdbgRegister.aarch64_x16].u64 = u.x[16];
		thread.context.items[AdbgRegister.aarch64_x17].u64 = u.x[17];
		thread.context.items[AdbgRegister.aarch64_x18].u64 = u.x[18];
		thread.context.items[AdbgRegister.aarch64_x19].u64 = u.x[19];
		thread.context.items[AdbgRegister.aarch64_x20].u64 = u.x[20];
		thread.context.items[AdbgRegister.aarch64_x21].u64 = u.x[21];
		thread.context.items[AdbgRegister.aarch64_x22].u64 = u.x[22];
		thread.context.items[AdbgRegister.aarch64_x23].u64 = u.x[23];
		thread.context.items[AdbgRegister.aarch64_x24].u64 = u.x[24];
		thread.context.items[AdbgRegister.aarch64_x25].u64 = u.x[25];
		thread.context.items[AdbgRegister.aarch64_x26].u64 = u.x[26];
		thread.context.items[AdbgRegister.aarch64_x27].u64 = u.x[27];
		thread.context.items[AdbgRegister.aarch64_x28].u64 = u.x[28];
		thread.context.items[AdbgRegister.aarch64_x29].u64 = u.x[29];
		thread.context.items[AdbgRegister.aarch64_x30].u64 = u.x[30];
		thread.context.items[AdbgRegister.aarch64_sp].u64 = u.sp;
		// NOTE: PC substitution
		//       FreeBSD's reg structure for AArch64 does not include PC.
		//       While ELR holds the address to return to, it might not
		//       always be present.
		thread.context.items[AdbgRegister.aarch64_pc].u64 = u.lr;
		return 0;
	} else {
		return adbg_oops(AdbgError.unimplemented);
	}
} else {
	return adbg_oops(AdbgError.unimplemented);
}
}

/// Format a register's value into a string buffer.
/// Errors: invalidOption for format.
/// Params:
/// 	buffer = Reference to text buffer.
/// 	len = Size of buffer.
/// 	reg = Register.
/// 	format = String format.
/// Returns: Number of characters written.
int adbg_register_format(char *buffer, size_t len, adbg_register_t *reg, AdbgRegisterFormat format) {
	if (reg == null || buffer == null || len == 0)
		return 0;
	
	// Get value
	ulong n = void;
	switch (reg.info.type) with (AdbgRegisterType) {
	case u8:  n = reg.u8; break;
	case u16: n = reg.u16; break;
	case u32: n = reg.u32; break;
	case u64: n = reg.u64; break;
	case f32: *cast(double*)n = reg.f32; break;
	case f64: *cast(double*)n = reg.f64; break;
	default:
		adbg_oops(AdbgError.invalidOption);
		return 0;
	}
	
	// Get format
	const(char) *sformat = void;
	switch (format) with (AdbgRegisterFormat) {
	case dec:
		switch (reg.info.type) with (AdbgRegisterType) {
		case u8, u16, u32, u64:
			sformat = "%llu"; break;
		case f32, f64:
			sformat = "%f"; break;
		default:
			adbg_oops(AdbgError.assertion);
			return 0;
		}
		break;
	case hex:
		sformat = "%llx";
		break;
	case hexPadded:
		switch (reg.info.type) with (AdbgRegisterType) {
		case u8:       sformat = "%02x"; break;
		case u16:      sformat = "%04x"; break;
		case u32, f32: sformat = "%08x"; break;
		case u64, f64: sformat = "%016llx"; break;
		default:
			adbg_oops(AdbgError.assertion);
			return 0;
		}
		break;
	default:
		adbg_oops(AdbgError.invalidOption);
		return 0;
	}
	
	return snprintf(buffer, len, sformat, n);
}
unittest {
	adbg_register_t reg = void;
	reg.info.type = AdbgRegisterType.u16;
	reg.u16  = 0x1234;
	enum BUFSZ = 16;
	char[BUFSZ] buffer = void;
	int r = adbg_register_format(buffer.ptr, BUFSZ, &reg, AdbgRegisterFormat.hex);
	assert(r == 4);
	assert(buffer[r] == 0);
	assert(buffer[0..r] == "1234");
}
