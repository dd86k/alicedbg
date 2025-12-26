/// Utility function for memory management.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.memory;

import adbg.process.base : adbg_process_t, __PROC_STATUS_NO_PROC_MEM;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import core.stdc.string : memcpy;
import adbg.error;
import adbg.utils.math; // For MiB template
import adbg.utils.list;

// TODO: Minimum pagesize per platform enum

// NOTE: Linux ptrace memory I/O based on https://www.linuxjournal.com/article/6100
//       However, when possible, /proc/PID/mem is used.
//       On BSD, PT_IO is used.

version (Windows) {
	import core.sys.windows.winbase; // WriteProcessMemory
	import core.sys.windows.winnt;
	import adbg.include.windows.psapi_dyn;
} else version (Posix) {
	import core.sys.posix.fcntl : open, O_RDWR, O_RDONLY, O_WRONLY;
	import adbg.include.c.stdio : snprintf, sscanf;
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd : sysconf, read, write, ssize_t, _SC_PAGESIZE;
	import core.stdc.config : c_long;
	
	version (linux)
		import core.stdc.errno : errno;
}

extern (C):

/// Get the system configured size of a page, typically target's smallest size.
/// Returns: Page size in bytes; Or 0 on error.
size_t adbg_memory_pagesize() {
version (Windows) {
	SYSTEM_INFO sysinfo = void;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwPageSize;
} else version (Posix) {
	// NOTE: sysconf, on error, returns -1
	c_long r = sysconf(_SC_PAGESIZE);
	if (r < 0) {
		adbg_oops(AdbgError.os);
		return 0;
	}
	return cast(size_t)r;
} else assert(0, "adbg_memory_pagesize unimplemented for platform");
}

//TODO: adbg_memory_hugesize
//      Windows: GetLargePageMinimum
//      Linux: /proc/meminfo:Hugepagesize
/*size_t adbg_memory_hugepagesize() {
}*/

version (linux)
// Opens a write/read handle to proc mem.
// The single handle makes things easier until we need granular access.
// Return non-zero on error
private
int __adbg_memory_open_linux(adbg_process_t *proc) {
	assert(proc);
	// Open an handle to /proc/PID/mem
	char[32] pathbuf = void;
	snprintf(pathbuf.ptr, 32, "/proc/%d/mem", proc.pid);
	int fd = open(pathbuf.ptr, O_RDWR);
	if (fd < 0) {
		// On failure, mark "do not retry opening proc/mem"
		// So future I/O attempts skips this initialization function
		proc.status |= __PROC_STATUS_NO_PROC_MEM;
		// NOTE: This returns -1 as generic instead of adbg error
		//       because there are no particular soft warnings about this
		return -1;
	}
	proc.procmemfd = fd;
	return 0;
}

/// Memory type
enum AdbgMemory {
	data,
	instruction,
}

/// Read from process data memory area.
/// Params:
/// 	proc = Process instance.
/// 	addr = Memory address (within the children address space).
/// 	data = Pointer to data.
/// 	size = Size of data.
/// Returns: Error code.
int adbg_memory_read(adbg_process_t *proc, size_t addr, void *data, size_t size) {
	return adbg_memory_read2(proc, AdbgMemory.data, addr, data, size);
}

/// Read from process memory area.
/// Params:
/// 	proc = Process instance.
/// 	type = Memory type (data, instruction, etc.), see AdbgMemory.
/// 	addr = Memory address (within the children address space).
/// 	data = Pointer to data.
/// 	size = Size of data.
/// Returns: Error code.
int adbg_memory_read2(adbg_process_t *proc, int type, size_t addr, void *data, size_t size) {
	if (proc == null || data == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (size == 0)
		return 0;
	
version (Windows) {
	HANDLE phandle = OpenProcess(PROCESS_VM_READ, FALSE, cast(DWORD)proc.pid);
	if (phandle == null)
		return adbg_oops(AdbgError.os);
	scope(exit) CloseHandle(phandle);
	
	if (ReadProcessMemory(phandle, cast(void*)addr, data, size, null) == 0)
		return adbg_oops(AdbgError.os);
	return 0;
} else version (linux) {
	// If "do not use proc memory" bit is set,
	// then /proc/PID/mem is unavaialble, skip it
	if ((proc.status & __PROC_STATUS_NO_PROC_MEM) == 0) {
		// Since the handle is unopened, open an handle to /proc/PID/mem
		if (proc.procmemfd == 0 && __adbg_memory_open_linux(proc))
			goto Lptrace;
		
		// If it succeeds, return immediately.
		// Otherwise, try via ptrace(3)
		if (read(proc.procmemfd, data, size) >= 0)
			return 0;
	}
	
Lptrace:
	switch (type) {
	case AdbgMemory.data:        type = PTRACE_PEEKDATA; break;
	case AdbgMemory.instruction: type = PTRACE_PEEKTEXT; break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	// If reading mem fails, try ptrace method
	c_long *dest = cast(c_long*)data;	/// target
	int r = cast(int)(size / c_long.sizeof);	/// number of "long"s to read
	
	for (; r > 0; --r, ++dest, addr += c_long.sizeof) {
		errno = 0; // Clear errno on PT_PEEK*
		*dest = ptrace(type, proc.pid, addr, null);
		if (errno)
			return adbg_oops(AdbgError.os);
	}
	
	r = size % c_long.sizeof;
	if (r) {
		errno = 0; // Clear errno for PT_PEEK*
		c_long l = ptrace(type, proc.pid, addr, null);
		if (errno)
			return adbg_oops(AdbgError.os);
		ubyte* dest8 = cast(ubyte*)dest, src8 = cast(ubyte*)&l;
		for (; r; --r) *dest8++ = *src8++; // inlined memcpy
	}
	return 0;
} else version (FreeBSD) {
	switch (type) {
	case AdbgMemory.data:        type = PIOD_READ_D; break;
	case AdbgMemory.instruction: type = PIOD_READ_I; break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	ptrace_io_desc io = ptrace_io_desc(type, cast(void*)addr, data, size);
	if (ptrace(PT_IO, proc.pid, &io, 0) < 0) // sets errno
		return adbg_oops(AdbgError.crt);
	// TODO: Check ptrace_io_desc.piod_len
	return 0;
} else // Unsupported
	return adbg_oops(AdbgError.unimplemented);
}

/// Write to process data memory area.
/// Params:
/// 	proc = Process instance.
/// 	addr = Memory address (within the children address space).
/// 	data = Pointer to data.
/// 	size = Size of data.
/// Returns: Error code.
int adbg_memory_write(adbg_process_t *proc, size_t addr, void *data, size_t size) {
	return adbg_memory_write2(proc, AdbgMemory.data, addr, data, size);
}

/// Write to process memory area.
/// Params:
/// 	proc = Process instance.
/// 	type = Memory type (data, instruction, etc.), see AdbgMemory.
/// 	addr = Memory address (within the children address space).
/// 	data = Pointer to data.
/// 	size = Size of data.
/// Returns: Error code.
int adbg_memory_write2(adbg_process_t *proc, int type, size_t addr, void *data, size_t size) {
	if (proc == null || data == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (size == 0)
		return 0;
	
version (Windows) {
	HANDLE phandle = OpenProcess(PROCESS_VM_WRITE, FALSE, cast(DWORD)proc.pid);
	if (phandle == null)
		return adbg_oops(AdbgError.os);
	scope(exit) CloseHandle(phandle);
	
	if (WriteProcessMemory(phandle, cast(void*)addr, data, size, null) == 0)
		return adbg_oops(AdbgError.os);
	return 0;
} else version (linux) {
	// If "do not use proc memory" bit is set,
	// then /proc/PID/mem is unavaialble, skip it
	if ((proc.status & __PROC_STATUS_NO_PROC_MEM) == 0) {
		// Since the handle is unopened, open an handle to /proc/PID/mem
		if (proc.procmemfd == 0 && __adbg_memory_open_linux(proc))
			goto Lptrace;
		
		// If it succeeds, return immediately.
		// Otherwise, try via ptrace(3)
		if (write(proc.procmemfd, data, size) >= 0)
			return 0;
	}
	
Lptrace:
	switch (type) {
	case AdbgMemory.data:        type = PTRACE_PEEKDATA; break;
	case AdbgMemory.instruction: type = PTRACE_PEEKTEXT; break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	// If reading mem fails, try ptrace method
	c_long *user = cast(c_long*)data;	/// user data pointer
	int i;	/// offset index
	int j = cast(int)(size / c_long.sizeof);	/// number of "blocks" to process
	
	for (; i < j; ++i, ++user)
		if (ptrace(type, proc.pid, addr + (i * c_long.sizeof), user) < 0)
			return adbg_oops(AdbgError.os);
	
	j = size % c_long.sizeof;
	if (j && ptrace(type, proc.pid, addr + (i * c_long.sizeof), user) < 0)
		return adbg_oops(AdbgError.os);
	return 0;
} else version (FreeBSD) {
	switch (type) {
	case AdbgMemory.data:        type = PIOD_WRITE_D; break;
	case AdbgMemory.instruction: type = PIOD_WRITE_I; break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	ptrace_io_desc io = ptrace_io_desc(type, cast(void*)addr, data, size);
	if (ptrace(PT_IO, proc.pid, &io, 0) < 0)
		return adbg_oops(AdbgError.os);
	// TODO: Check ptrace_io_desc.piod_len
	return 0;
} else // Unsupported
	return adbg_oops(AdbgError.unimplemented);
}

/// Memory permission access bits.
enum AdbgMemPerm : ushort {
	read	= 1,	/// Read permission
	write	= 1 << 1,	/// Write permission
	exec	= 1 << 2,	/// Execute permission
	private_	= 1 << 8,	/// Process memory is private; Otherwise shared
	
	// Common access patterns
	readWrite	= read | write,	/// Read and write permissions
	readExec	= read | exec,	/// Read and execution permissions
	writeExec	= write | exec,	/// Read and execution permissions
	all	= read | write | exec,	/// Read, write, and execute permissions
}

/// Page usage.
enum AdbgPageUse : ubyte {
	/// Unknown.
	unknown,
	/// Private memory.
	resident,
	/// Slice or memory-mapped file.
	mapped,
	/// Older alias to mapped.
	fileview = mapped,
	/// Module, like a shared object or dynamic linked library.
	module_,
}

private enum MEM_MAP_NAME_LEN = 512;
//TODO: Map groups
/// Represents a mapped memory region.
struct adbg_memory_map_t {
	//TODO: type (file, free, commited, etc.)
	/// Base memory region address.
	void *base;
	/// Size of region.
	size_t size;
	/// Access permissions.
	ushort access;
	/// Page type (private, image, view, etc.)
	ubyte type;
	/// Page attributes (large, etc.)
	ubyte attributes;
	//TODO: Should take this out into its own function
	//      e.g., adbg_memory_get_map_name()
	/// Module name or mapped file.
	char[MEM_MAP_NAME_LEN] name;
}

//TODO: Options for process modules and process memory regions separatively
//TODO: Option to include free/reserved memory regions (linux: ---p)
// Memory options for adbg_memory_maps.
enum AdbgMappingOption {
	/// Get all modules.
	/// Type: int
	/// Default: 0 (false)
	allModules	= 2,
}

void* adbg_memory_mapping(adbg_process_t *proc, ...) {
	if (proc == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	enum {
		OPTION_ALLMODULES = 2,
	}
	
	// Get options
	va_list valist = void;
	va_start(valist, proc);
	int options;
Loption:
	switch (va_arg!int(valist)) {
	case 0: break;
	case AdbgMappingOption.allModules:
		if (va_arg!int(valist)) options |= OPTION_ALLMODULES;
		goto Loption;
	default:
		adbg_oops(AdbgError.invalidOption);
		return null;
	}
	
version (Windows) {
	if (__dynlib_psapi_load()) // EnumProcessModules, QueryWorkingSet
		return null;
	
	HANDLE phandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.pid);
	if (phandle == null) {
		adbg_oops(AdbgError.os);
		return null;
	}
	scope(exit) CloseHandle(phandle);
	
	// NOTE: Windows memory mappings
	//
	//       There are two parts to this rather length block of code.
	//       1. The first one are about the working sets
	//       2. The second are loaded modules
	
	// Don't use scope(exit), because this is a two-part process, and this
	// allocated is cleared before allocating the second portion
	uint bfsz = MiB!1;
	PSAPI_WORKING_SET_INFORMATION *mbinfo = cast(PSAPI_WORKING_SET_INFORMATION*)malloc(bfsz);
	if (mbinfo == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Part 1. Working Sets
	
	// NOTE: NtPssCaptureVaSpaceBulk is only available since Windows 10 20H1
	// Should we use EnumPageFilesA?
	// This queries workset addresses regardless of size, page-bounded.
	// e.g., it will add 0x30000 and 0x31000 as entries, despite being a 8K "block".
Lretry:
	uint setcnt = QueryWorkingSet(phandle, mbinfo, bfsz);
	if (setcnt == 0) {
		if (GetLastError() == ERROR_BAD_LENGTH) {
			bfsz = cast(uint)(mbinfo.NumberOfEntries * ULONG_PTR.sizeof);
			mbinfo = cast(PSAPI_WORKING_SET_INFORMATION*)realloc(mbinfo, bfsz);
			if (mbinfo == null) {
				adbg_oops(AdbgError.crt);
				free(mbinfo);
				return null;
			}
			goto Lretry;
		}
		
		adbg_oops(AdbgError.os);
		free(mbinfo);
		return null;
	}
	
	// Needed to group working sets
	size_t pagesize = adbg_memory_pagesize();
	if (pagesize == 0) {
		free(mbinfo);
		return null;
	}
	
	// Create new list
	// While it'd be clever to reserve an initial capacity of the return
	// value of QueryWorkingSet's NumberOfEntries, many entries are grouped/duplicates
	// NOTE: Putty 0.80 will have around 1095 entries
	list_t *list = adbg_list_new(adbg_memory_map_t.sizeof, 64);
	if (list == null)
		return list;
	
	// TODO: If WoW64, use MEMORY_BASIC_INFORMATION32
	
	//PSAPI_WORKING_SET_EX_INFORMATION wsinfoex = void;
	adbg_memory_map_t map = void;
	for (size_t i; i < mbinfo.NumberOfEntries; ++i) {
		// NOTE: Win64 doesn't populate block flag bits
		PSAPI_WORKING_SET_BLOCK *blk = &mbinfo.WorkingSetInfo.ptr[i];
		
		/*TODO: Large page support + adjustment needed
		wsinfoex.VirtualAddress = cast(void*)blk.VirtualPage;
		if (QueryWorkingSetEx(tracee.hproc, &wsinfoex,
			PSAPI_WORKING_SET_EX_INFORMATION.sizeof) == 0)
			continue;
		import adbg.utils.bit : adbg_bits_extract32;
		uint pageflags = cast(uint)wsinfoex.VirtualAttributes.Flags;
		version (Trace) trace("page=%zx attr=%zx valid=%d share=%d prot=%d shared=%d node=%d locked=%d large=%d bad=%d",
			cast(size_t)wsinfoex.VirtualAddress,
			wsinfoex.VirtualAttributes.Flags,
			adbg_bits_extract32(pageflags, 1, 0),
			adbg_bits_extract32(pageflags, 3, 1),
			adbg_bits_extract32(pageflags, 11, 4),
			adbg_bits_extract32(pageflags, 1, 15),
			adbg_bits_extract32(pageflags, 6, 16),
			adbg_bits_extract32(pageflags, 1, 22),
			adbg_bits_extract32(pageflags, 1, 23),
			adbg_bits_extract32(pageflags, 1, 31));*/
		
		// Query with whatever page value
		MEMORY_BASIC_INFORMATION mem = void;
		if (VirtualQueryEx(phandle, cast(void*)blk.VirtualPage,
			&mem, MEMORY_BASIC_INFORMATION.sizeof) == 0) {
			continue;
		}
		
		// Skip memory region when non-commited
		// Usually never happens with addresses given by QueryWorkingSet
		if (mem.State & (MEM_FREE | MEM_RESERVE))
			continue;
		
		// Get mapped file
		if (GetMappedFileNameA(phandle, mem.BaseAddress, map.name.ptr, MEM_MAP_NAME_LEN)) {
			map.name[GetModuleFileNameExA(phandle, null, map.name.ptr, MEM_MAP_NAME_LEN)] = 0;
		} else {
			map.name[0] = 0;
		}
		
		// Adjust protection bits
		map.access = mem.Type & MEM_PRIVATE ? AdbgMemPerm.private_ : 0;
		if (mem.Protect & PAGE_EXECUTE_WRITECOPY)
			map.access |= AdbgMemPerm.readExec;
		else if (mem.Protect & PAGE_EXECUTE_READWRITE)
			map.access |= AdbgMemPerm.all;
		else if (mem.Protect & PAGE_EXECUTE_READ)
			map.access |= AdbgMemPerm.readExec;
		else if (mem.Protect & PAGE_EXECUTE)
			map.access |= AdbgMemPerm.exec;
		else if (mem.Protect & PAGE_WRITECOPY)
			map.access |= AdbgMemPerm.read;
		else if (mem.Protect & PAGE_READWRITE)
			map.access |= AdbgMemPerm.readWrite;
		else if (mem.Protect & PAGE_READONLY)
			map.access |= AdbgMemPerm.read;
		
		if (mem.Type & MEM_IMAGE)
			map.type = AdbgPageUse.module_;
		else if (mem.Type & MEM_MAPPED)
			map.type = AdbgPageUse.fileview;
		else if (mem.Type & MEM_PRIVATE)
			map.type = AdbgPageUse.resident;
		else
			map.type = AdbgPageUse.unknown;
		
		map.base = mem.BaseAddress;
		map.size = mem.RegionSize;
		
		list = adbg_list_add(list, &map);
		if (list == null) {
			adbg_list_close(list);
			return null;
		}
		
		// Memory region is less or equal to pagesize?
		// No further adjustments to do
		if (mem.RegionSize <= pagesize)
			continue;
		
		// Otherwise, get ready to skip future pages if they are
		// related (memory address and size follows by pagesize).
		void *end = mem.BaseAddress + mem.RegionSize;
		while (i + 1 < mbinfo.NumberOfEntries) {
			void *page = cast(void*)mbinfo.WorkingSetInfo.ptr[i + 1].VirtualPage;
			if (VirtualQueryEx(phandle, page,
				&mem, MEMORY_BASIC_INFORMATION.sizeof) == 0)
				break;
			if (mem.BaseAddress > end) break;
			++i;
		}
	}
	
	// Free temporary PSAPI_WORKING_SET_INFORMATION buffer
	free(mbinfo);
	
	// Part 2. Modules
	if ((options & OPTION_ALLMODULES) == 0)
		return list;
	
	// Allocate temp buffer for module handles
	uint buffersz = cast(uint)(pagesize / HMODULE.sizeof);
	HMODULE *mods = cast(HMODULE*)malloc(buffersz);
	if (mods == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Enum process modules
	DWORD needed = void; //TODO: Could re-use this with option
	bool tried = false;
Lenum:
	if (EnumProcessModules(phandle, mods, buffersz, &needed) == FALSE) {
		if (tried == false && buffersz > needed) {
			void *t = realloc(mods, needed);
			if (t == null) {
				adbg_oops(AdbgError.crt);
				free(mods);
				return null;
			}
			mods = cast(HMODULE*)t;
			tried = true;
			goto Lenum;
		}
		adbg_oops(AdbgError.os);
		free(mods);
		return null;
	}
	scope(exit) free(mods);
	
	// Module information
	DWORD modcount = needed / HMODULE.sizeof;
	for (DWORD mod_i; mod_i < modcount; ++mod_i) {
		HMODULE mod = mods[mod_i];
		
		MODULEINFO minfo = void;
		if (GetModuleInformation(phandle, mod, &minfo, MODULEINFO.sizeof) == FALSE)
			continue;
		
		// Get base name (e.g., from \Device\HarddiskVolume5\xyz.dll)
		if (GetMappedFileNameA(phandle, minfo.lpBaseOfDll, map.name.ptr, MEM_MAP_NAME_LEN)) {
			map.name[GetModuleFileNameExA(phandle, mod, map.name.ptr, MEM_MAP_NAME_LEN)] = 0;
		} else {
			map.name[0] = 0;
		}
		
		//TODO: if WoW64, use MEMORY_BASIC_INFORMATION32
		
		MEMORY_BASIC_INFORMATION mem = void;
		if (VirtualQueryEx(phandle, minfo.lpBaseOfDll, &mem, MEMORY_BASIC_INFORMATION.sizeof) == 0)
			continue;
		
		// Adjust protection bits
		map.access = mem.Type & MEM_PRIVATE ? AdbgMemPerm.private_ : 0;
		if (mem.Protect & PAGE_EXECUTE_WRITECOPY)
			map.access |= AdbgMemPerm.readExec;
		else if (mem.Protect & PAGE_EXECUTE_READWRITE)
			map.access |= AdbgMemPerm.all;
		else if (mem.Protect & PAGE_EXECUTE_READ)
			map.access |= AdbgMemPerm.readExec;
		else if (mem.Protect & PAGE_EXECUTE)
			map.access |= AdbgMemPerm.exec;
		else if (mem.Protect & PAGE_WRITECOPY)
			map.access |= AdbgMemPerm.read;
		else if (mem.Protect & PAGE_READWRITE)
			map.access |= AdbgMemPerm.readWrite;
		else if (mem.Protect & PAGE_READONLY)
			map.access |= AdbgMemPerm.read;
		
		map.type = AdbgPageUse.module_;
		map.base = minfo.lpBaseOfDll;
		map.size = minfo.SizeOfImage;
		list = adbg_list_add(list, &map);
		if (list == null) {
			adbg_list_close(list);
			return null;
		}
	}
	
	return list;
} else version (linux) {
	// Inspired by libscanmem
	// https://github.com/scanmem/scanmem/blob/main/maps.c
	
	import core.sys.linux.unistd : readlink;
	import adbg.utils.strings : adbg_util_getline;
	import core.sys.linux.unistd : read, close;
	import core.sys.linux.fcntl : open, O_RDONLY;
	
	// Formulate proc map path
	enum PROC_MAPS_LEN = 32;
	char[PROC_MAPS_LEN] proc_maps = void;
	snprintf(proc_maps.ptr, PROC_MAPS_LEN, "/proc/%u/maps", proc.pid);
	version (Trace) trace("maps: %s", proc_maps.ptr);
	
	// Open process maps
	int fd_maps = open(proc_maps.ptr, O_RDONLY);
	if (fd_maps == -1) {
		adbg_oops(AdbgError.os);
		return null;
	}
	scope(exit) close(fd_maps);
	
	// TODO: Implement allModules (Linux)
	//       Use process path to distinguish modules v. this process
	/*
	// Get proc exe path (e.g., /usr/bin/cat)
	enum PROC_EXE_LEN = 256;
	char[PROC_EXE_LEN] proc_exe = void;
	snprintf(proc_exe.ptr, PROC_EXE_LEN, "/proc/%u/exe", proc.pid);
	
	// Read link from proc exe for process path
	enum EXE_PATH_LEN = 256;
	char[EXE_PATH_LEN] exe_path = void;
	version (Trace) trace("exe: %s", proc_exe.ptr);
	ssize_t linksz = readlink(proc_exe.ptr, exe_path.ptr, EXE_PATH_LEN);
	if (linksz > 0) {
		exe_path[linksz] = 0;
	} else { // Failed or empty
		exe_path[0] = 0;
	}*/
	
	// TODO: Redo line-reading part
	//       While a little slower (due to I/O), reading a character
	//       at a time for each line will be more future proof than
	//       allocating a fixed-sized buffer and filling it.
	
	// Allocate enough for maps buffer
	// For example: One Firefox process has around 149 KiB worth of
	// maps data with 1953 entries.
	enum READSZ = MiB!2;
	char *procbuf = cast(char*)malloc(READSZ);
	if (procbuf == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	scope(exit) free(procbuf);
	
	// Read maps, as much as possible
	ssize_t readsz = read(fd_maps, procbuf, READSZ);
	if (readsz < 0) {
		adbg_oops(AdbgError.os);
		return null;
	}
	version (Trace) trace("flen=%zu", readsz);
	
	// Allocate list
	list_t *list = adbg_list_new(adbg_memory_map_t.sizeof, 64);
	if (list == null)
		return null;
	
	// Go through each entry, which may look like this (without header):
	// Address range             Perm Offset   Dev   inode      Path
	// 55adaf007000-55adaf009000 r--p 00000000 08:02 1311130    /usr/bin/cat
	// Perms: r=read, w=write, x=execute, s=shared or p=private (CoW)
	// Path: Path or [stack], [stack:%id] (3.4 to 4.4), [heap]
	//       [vdso]: virtual dynamic shared object: https://lwn.net/Articles/615809/
	//       [vvar]: Stores a "mirror" of kernel variables required by virt syscalls
	//       [vsyscall]: Legacy user-kernel (jump?) table for some syscalls
	enum LINE_LEN = 256;
	char[LINE_LEN] line = void;
	size_t linesz = void; /// line size
	size_t srcidx; /// maps source buffer index
	size_t i; /// maps index
	adbg_memory_map_t map = void;
	while (adbg_util_getline(line.ptr, LINE_LEN, &linesz, procbuf, &srcidx)) {
		size_t range_start = void;
		size_t range_end   = void;
		char[4] perms      = void; // rwxp/rwxs
		uint offset        = void;
		uint dev_major     = void;
		uint dev_minor     = void;
		uint inode         = void;
		
		//TODO: Check for (deleted) column (last)
		// NOTE: GDC (tested with 11.4) is likely getting the wrong types
		//       Affects: Likely GDC 11 and earlier.
		//       D definitions aliases size_t (%zx) to uint/ulong and
		//       pointer types aren't properly passed.
		if (sscanf(line.ptr, "%zx-%zx %4s %x %x:%x %u %512s",
			&range_start, &range_end,
			perms.ptr, &offset,
			&dev_major, &dev_minor,
			&inode, map.name.ptr) < 8) {
			continue;
		}
		
		// Skip regions with empty permissions as they seem unallocated
		if (perms[0] == '-' && perms[1] == '-' && perms[2] == '-')
			continue;
		
		// NOTE: ELF regions with same executable path
		//
		// section  perms  comment
		// .text:   r-x
		// .rodata: r--    could be absent
		// .data:   rw-
		// .bss:    rw-    empty path and inode=0, could be absent
		
		//TODO: Adjust memory region permissions like libscanmem does
		
		version (Trace) trace("entry: %zu %zx %s", i, range_start, map.name.ptr);
		
		map.base = cast(void*)range_start;
		map.size = range_end - range_start;
		
		bool priv = perms[3] == 'p';
		
		//if (offset)
		//	map.type = AdbgPageUse.view;
		//TODO: procfs name
		//else if (strcmp(procname, map.name.ptr) == 0)
		//	map.type = AdbgPageUse.image;
		//else
			map.type = AdbgPageUse.resident;
		
		map.access = priv ? AdbgMemPerm.private_ : 0;
		if (perms[0] == 'r') map.access |= AdbgMemPerm.read;
		if (perms[1] == 'w') map.access |= AdbgMemPerm.write;
		if (perms[2] == 'x') map.access |= AdbgMemPerm.exec;
		
		list = adbg_list_add(list, &map);
		if (list == null) {
			adbg_list_close(list);
			return null;
		}
	}
	
	return list;
} else {
	// FreeBSD: procstat(1) / pmap(9)
	// - https://man.freebsd.org/cgi/man.cgi?query=vm_map
	// - https://github.com/freebsd/freebsd-src/blob/main/lib/libutil/kinfo_getvmmap.c
	// - args[0] = CTL_KERN
	// - args[1] = KERN_PROC
	// - args[2] = KERN_PROC_VMMAP
	// - args[3] = pid
	// NetBSD: pmap(1) / uvm_map(9)
	// OpenBSD: procmap(1)
	// - kvm_open + kvm_getprocs + KERN_PROC_PID
	adbg_oops(AdbgError.unimplemented);
	return null;
}
}

adbg_memory_map_t* adbg_memory_mapping_at(void *list, size_t index) {
	if (list == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return cast(adbg_memory_map_t*)adbg_list_get(cast(list_t*)list, index);
}

void adbg_memory_mapping_close(void *list) {
	if (list == null) return;
	adbg_list_close(cast(list_t*)list);
}
