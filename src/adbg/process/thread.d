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
	import core.stdc.ctype : isdigit;
	import core.stdc.stdio : snprintf;
	import core.stdc.stdlib : atoi;
	import core.sys.posix.dirent;
	import core.sys.posix.libgen : basename;
	import adbg.include.linux.user;
	import adbg.include.posix.ptrace;
}

extern (C):

private enum INIT_COUNT = 32;

struct adbg_thread_t {
version (Windows) {
	HANDLE handle;
	int id;
}
version (linux) {
	pid_t handle;
}
	adbg_thread_context_t context;
}

/// Get a list of threads for target process.
/// Params: process = Process.
/// Returns: Thread list.
int adbg_thread_list_update(adbg_process_t *process) {
version (Windows) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (process.pid == 0)
		return adbg_oops(AdbgError.uninitiated);
	
	if (process.thread_list == null)
		process.thread_list = adbg_list_new(adbg_thread_t.sizeof, INIT_COUNT);
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
	adbg_thread_context_config(&t.context, adbg_process_get_machine(process));
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
		process.thread_list = adbg_list_new(adbg_thread_t.sizeof, INIT_COUNT);
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
	adbg_thread_context_config(&t.context, adbg_process_get_machine(process));
	for (dirent *entry = void; (entry = readdir(procfd)) != null;) {
		version (Trace) trace("entry=%s", entry.d_name.ptr);
		
		// readdir() includes "." and "..", skip them
		if (isdigit(entry.d_name[0]) == 0)
			continue;
		
		int tid = atoi( basename(entry.d_name.ptr) );
		process.thread_list = adbg_list_add(process.thread_list, &tid);
		if (process.thread_list == null) {
			adbg_list_free(process.thread_list);
			return adbg_errno();
		}
	}
	
	return 0;
} else {
	return adbg_oops(AdbgError.unimplemented);
}
}

/// Get thread from list using index.
/// Params:
/// 	proc = Process instance.
/// 	index = Zero-based index.
/// Returns: Thread instance. On error, null.
adbg_thread_t* adbg_thread_list_get(adbg_process_t *proc, size_t index) {
	if (proc == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	// NOTE: adbg_list_get checks both list pointer and index and sets error
	return cast(adbg_thread_t*)adbg_list_get(proc.thread_list, index);
}

/// Get the thread ID out of this thread instance.
/// Params: thread = Thread instance.
/// Returns: Thread ID. On error, zero.
int adbg_thread_id(adbg_thread_t *thread) {
	if (thread == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	version (Windows)    return thread.id;
	else version (linux) return cast(int)thread.handle;
	else {
		adbg_oops(AdbgError.unimplemented);
		return 0;
	}
}

/// Close the thread list instance.
/// Params: list = Thread list instance.
void adbg_thread_list_free(void *list) {
	if (list == null)
		return;
	adbg_list_free(cast(list_t*)list);
}

//
// Context management
//

// TODO: Support FPU registers (f32, f64, f80 types)
// TODO: Thread struct type, to hold its context, and other info

enum AdbgRegister {
	// x86
	eip	= 0,	/// (x86) Extended Instruction Pointer
	eflags	= 1,	/// (x86) Extended FLAGS
	eax	= 2,	/// (x86)
	ebx	= 3,	/// (x86)
	ecx	= 4,	/// (x86)
	edx	= 5,	/// (x86)
	esp	= 6,	/// (x86) Extended Stack Pointer (top of stack)
	ebp	= 7,	/// (x86) Extended Base Pointer (start of function)
	esi	= 8,	/// (x86) Extended Source Index
	edi	= 9,	/// (x86) Extended Destination Index
	
	// x86-64
	rip	= 0,	/// (x86-64) Re-extended Intruction Pointer
	rflags	= 1,	/// (x86-64) Re-extended FLAGS
	rax	= 2,	/// (x86-64) 
	rbx	= 3,	/// (x86-64) 
	rcx	= 4,	/// (x86-64) 
	rdx	= 5,	/// (x86-64) 
	rsp	= 6,	/// (x86-64) Re-extended Stack Pointer (top of stack)
	rbp	= 7,	/// (x86-64) Re-extended Base Pointer (start of function)
	rsi	= 8,	/// (x86-64) Re-extended Source Index
	rdi	= 9,	/// (x86-64) Re-extended Destination Index
	r8	= 10,	/// (x86-64) 
	r9	= 11,	/// (x86-64) 
	r10	= 12,	/// (x86-64) 
	r11	= 13,	/// (x86-64) 
	r12	= 14,	/// (x86-64) 
	r13	= 15,	/// (x86-64) 
	r14	= 16,	/// (x86-64) 
	r15	= 17,	/// (x86-64) 
}

/// Buffer size for register set.
private enum REG_COUNT = AdbgRegister.max + 1;

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
];

adbg_register_t* adbg_register_get(adbg_thread_t *thread, size_t i) {
	if (thread == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	if (i >= thread.context.count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	return &thread.context.items[i];
}

const(char)* adbg_register_name(adbg_register_t *register) {
	if (register == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return register.info.name;
}

// Configure register set, used internally
private
int adbg_thread_context_config(adbg_thread_context_t *ctx, AdbgMachine mach) {
	if (ctx == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	// Select register set
	immutable(adbg_register_info_t)[] regs = void;
	switch (mach) with (AdbgMachine) {
	case i386:	regs = regset_x86; break;
	case amd64:	regs = regset_x86_64; break;
	default:	return adbg_oops(AdbgError.unimplemented);
	}
	
	version (Trace) trace("regs.length=%d", cast(int)regs.length);
	for (size_t i; i < regs.length; ++i)
		ctx.items[i].info = regs[i];
	ctx.count = regs.length;
	return 0;
}

// Update the context for thread
int adbg_thread_context_update(adbg_process_t *proc, adbg_thread_t *thread) {
	version (Trace) trace("tracee=%p ctx=%p", ctx, tracee);
	
	if (proc == null || thread == null)
		return adbg_oops(AdbgError.invalidArgument);
	
version (Win64) {
	AdbgMachine mach = adbg_process_get_machine(proc);
	switch (mach) {
	case AdbgMachine.amd64:
		CONTEXT_X64 winctx = void; // CONTEXT
		winctx.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext(thread.handle, cast(LPCONTEXT)&winctx) == FALSE) {
			return adbg_oops(AdbgError.os);
		}
		thread.context.items[0].u64  = winctx.Rip;
		thread.context.items[1].u64  = winctx.EFlags;
		thread.context.items[2].u64  = winctx.Rax;
		thread.context.items[3].u64  = winctx.Rbx;
		thread.context.items[4].u64  = winctx.Rcx;
		thread.context.items[5].u64  = winctx.Rdx;
		thread.context.items[6].u64  = winctx.Rsp;
		thread.context.items[7].u64  = winctx.Rbp;
		thread.context.items[8].u64  = winctx.Rsi;
		thread.context.items[9].u64  = winctx.Rdi;
		thread.context.items[10].u64 = winctx.R8;
		thread.context.items[11].u64 = winctx.R9;
		thread.context.items[12].u64 = winctx.R10;
		thread.context.items[13].u64 = winctx.R11;
		thread.context.items[14].u64 = winctx.R12;
		thread.context.items[15].u64 = winctx.R13;
		thread.context.items[16].u64 = winctx.R14;
		thread.context.items[17].u64 = winctx.R15;
		break;
	case AdbgMachine.i386: // WoW64 process
		WOW64_CONTEXT winctxwow64 = void;
		winctxwow64.ContextFlags = CONTEXT_ALL;
		if (Wow64GetThreadContext(thread.handle, &winctxwow64) == FALSE) {
			return adbg_oops(AdbgError.os);
		}
		thread.context.items[0].u32 = winctxwow64.Eip;
		thread.context.items[1].u32 = winctxwow64.EFlags;
		thread.context.items[2].u32 = winctxwow64.Eax;
		thread.context.items[3].u32 = winctxwow64.Ebx;
		thread.context.items[4].u32 = winctxwow64.Ecx;
		thread.context.items[5].u32 = winctxwow64.Edx;
		thread.context.items[6].u32 = winctxwow64.Esp;
		thread.context.items[7].u32 = winctxwow64.Ebp;
		thread.context.items[8].u32 = winctxwow64.Esi;
		thread.context.items[9].u32 = winctxwow64.Edi;
		break;
	default:
		return adbg_oops(AdbgError.objectInvalidMachine);
	}
	return 0;
} else version (Win32) {
	X86_NT_CONTEXT winctx = void; // CONTEXT
	winctx.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(tracee.htid, cast(LPCONTEXT)&winctx) == FALSE) {
		return adbg_oops(AdbgError.os);
	}
	thread.context.items[0].u32 = winctx.Eip;
	thread.context.items[1].u32 = winctx.EFlags;
	thread.context.items[2].u32 = winctx.Eax;
	thread.context.items[3].u32 = winctx.Ebx;
	thread.context.items[4].u32 = winctx.Ecx;
	thread.context.items[5].u32 = winctx.Edx;
	thread.context.items[6].u32 = winctx.Esp;
	thread.context.items[7].u32 = winctx.Ebp;
	thread.context.items[8].u32 = winctx.Esi;
	thread.context.items[9].u32 = winctx.Edi;
	return 0;
} else version (linux) {
	//TODO: PT_GETFPREGS
	//      PT_GETWMMXREGS
	//      PT_GET_THREAD_AREA
	//      PT_GETCRUNCHREGS
	//      PT_GETVFPREGS
	//      PT_GETHBPREGS
	user_regs_struct u = void;
	if (ptrace(PT_GETREGS, thread.handle, null, &u) < 0)
		return adbg_oops(AdbgError.os);
	
	version (X86) {
		thread.context.items[0].u32 = u.eip;
		thread.context.items[1].u32 = u.eflags;
		thread.context.items[2].u32 = u.eax;
		thread.context.items[3].u32 = u.ebx;
		thread.context.items[4].u32 = u.ecx;
		thread.context.items[5].u32 = u.edx;
		thread.context.items[6].u32 = u.esp;
		thread.context.items[7].u32 = u.ebp;
		thread.context.items[8].u32 = u.esi;
		thread.context.items[9].u32 = u.edi;
	} else version (X86_64) {
		thread.context.items[0].u64 = u.rip;
		thread.context.items[1].u64 = u.eflags;
		thread.context.items[2].u64 = u.rax;
		thread.context.items[3].u64 = u.rbx;
		thread.context.items[4].u64 = u.rcx;
		thread.context.items[5].u64 = u.rdx;
		thread.context.items[6].u64 = u.rsp;
		thread.context.items[7].u64 = u.rbp;
		thread.context.items[8].u64 = u.rsi;
		thread.context.items[9].u64 = u.rdi;
		thread.context.items[10].u64 = u.r8;
		thread.context.items[11].u64 = u.r9;
		thread.context.items[12].u64 = u.r10;
		thread.context.items[13].u64 = u.r11;
		thread.context.items[14].u64 = u.r12;
		thread.context.items[15].u64 = u.r13;
		thread.context.items[16].u64 = u.r14;
		thread.context.items[17].u64 = u.r15;
	}
	return 0;
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
