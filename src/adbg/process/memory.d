/// Utility function for memory management.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.memory;

import adbg.process.base : AdbgProcStatus, adbg_process_t;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import core.stdc.string : memcpy;
import core.stdc.config : c_long;
import adbg.error;
import adbg.utils.math; // For MiB template

// TODO: Minimum pagesize per platform enum

// NOTE: Linux ptrace memory I/O based on https://www.linuxjournal.com/article/6100
//       However, when possible, /proc/PID/mem is used.
//       On BSD, PT_IO is used.

version (Windows) {
	import core.sys.windows.winbase; // WriteProcessMemory
	import core.sys.windows.winnt;
	import adbg.include.windows.psapi_dyn;
} else version (Posix) {
	import core.sys.posix.fcntl : open, O_RDWR;
	import adbg.include.c.stdio : snprintf, sscanf;
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd : sysconf, read, write, ssize_t, _SC_PAGESIZE;
	
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
	return r < 0 ? 0 : r;
} else assert(0, "adbg_memory_pagesize unimplemented for platform");
}

//TODO: adbg_memory_hugesize
//      Windows: GetLargePageMinimum
//      Linux: /proc/meminfo:Hugepagesize
/*size_t adbg_memory_hugepagesize() {
}*/

//TODO: Provide a way to return number of bytes written/read
//      1. Could make size parameter a pointer
//      2. Could return a ptrdiff_t, -1 on error
/// Read memory from tracee data memory area.
/// Params:
/// 	tracee = Reference to tracee instance.
/// 	addr = Memory address (within the children address space).
/// 	data = Pointer to data.
/// 	size = Size of data.
/// Returns: Error code.
int adbg_memory_read(adbg_process_t *tracee, size_t addr, void *data, uint size) {
	if (tracee == null || data == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (size == 0)
		return 0;
	
version (Windows) {
	if (ReadProcessMemory(tracee.hpid, cast(void*)addr, data, size, null) == 0)
		return adbg_oops(AdbgError.os);
	return 0;
} else version (linux) {
	// Try reading from mem if able
	if (tracee.memfailed == false) {
		if (tracee.mhandle) {
		Lread:
			if (read(tracee.mhandle, data, size) >= 0)
				return 0;
			
			// Mark as failed and don't try again
			tracee.memfailed = true;
		} else { // open mem handle
			char[32] pathbuf = void;
			snprintf(pathbuf.ptr, 32, "/proc/%d/mem", tracee.pid);
			tracee.mhandle = open(pathbuf.ptr, O_RDWR);
			// Success? Try reading
			if (tracee.mhandle)
				goto Lread;
			// On failure, mark fail and proceed to try ptrace fallback
			tracee.memfailed = true;
		}
	}
	
	// If reading mem fails, try ptrace method
	c_long *dest = cast(c_long*)data;	/// target
	int r = size / c_long.sizeof;	/// number of "long"s to read
	
	for (; r > 0; --r, ++dest, addr += c_long.sizeof) {
		errno = 0; // Clear errno on PT_PEEK*
		*dest = ptrace(PT_PEEKDATA, tracee.pid, addr, null);
		if (errno)
			return adbg_oops(AdbgError.os);
	}
	
	r = size % c_long.sizeof;
	if (r) {
		errno = 0; // Clear errno on PT_PEEK*
		c_long l = ptrace(PT_PEEKDATA, tracee.pid, addr, null);
		if (errno)
			return adbg_oops(AdbgError.os);
		ubyte* dest8 = cast(ubyte*)dest, src8 = cast(ubyte*)&l;
		for (; r; --r) *dest8++ = *src8++; // inlined memcpy
	}
	return 0;
} else version (FreeBSD) {
	ptrace_io_desc io = ptrace_io_desc(PIOD_READ_D, cast(void*)addr, data, size);
	if (ptrace(PT_IO, tracee.pid, &io, 0) < 0) // sets errno
		return adbg_oops(AdbgError.crt);
	return 0;
} else // Unsupported
	return adbg_oops(AdbgError.unimplemented);
}

/// Write memory to tracee data memory area.
/// Params:
/// 	tracee = Reference to tracee instance.
/// 	addr = Memory address (within the children address space).
/// 	data = Pointer to data.
/// 	size = Size of data.
/// Returns: Error code.
int adbg_memory_write(adbg_process_t *tracee, size_t addr, void *data, uint size) {
	if (tracee == null || data == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (size == 0)
		return 0;
	
version (Windows) {
	if (WriteProcessMemory(tracee.hpid, cast(void*)addr, data, size, null) == 0)
		return adbg_oops(AdbgError.os);
	return 0;
} else version (linux) {
	// Try reading from mem if able
	if (tracee.memfailed == false) {
		if (tracee.mhandle) {
		Lread:
			if (write(tracee.mhandle, data, size) >= 0)
				return 0;
			
			// Mark as failed and don't try again
			tracee.memfailed = true;
		} else { // open mem handle
			char[32] pathbuf = void;
			snprintf(pathbuf.ptr, 32, "/proc/%d/mem", tracee.pid);
			tracee.mhandle = open(pathbuf.ptr, O_RDWR);
			// Success? Try reading
			if (tracee.mhandle)
				goto Lread;
			// On failure, mark fail and proceed to try ptrace fallback
			tracee.memfailed = true;
		}
	}
	
	// If reading mem fails, try ptrace method
	c_long *user = cast(c_long*)data;	/// user data pointer
	int i;	/// offset index
	int j = size / c_long.sizeof;	/// number of "blocks" to process
	
	for (; i < j; ++i, ++user) {
		if (ptrace(PT_POKEDATA, tracee.pid, addr + (i * c_long.sizeof), user) < 0)
			return adbg_oops(AdbgError.os);
	}
	
	//TODO: Save remainder before writing
	j = size % c_long.sizeof;
	if (j) {
		if (ptrace(PT_POKEDATA, tracee.pid,
			addr + (i * c_long.sizeof), user) < 0)
			return adbg_oops(AdbgError.os);
	}
	return 0;
} else version (FreeBSD) {
	ptrace_io_desc io = ptrace_io_desc(PIOD_WRITE_D, cast(void*)addr, data, size);
	if (ptrace(PT_IO, tracee.pid, &io, 0) < 0) // sets errno
		return adbg_oops(AdbgError.crt);
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
	fileview,
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
/*enum AdbgMapOpt {
	// Only get the memory regions for this process.
	// Type: int
	// Default: 0 (false)
	//processOnly	= 2,
	// With given Process ID instead
	// Permission issues may be raised
	//pid = 2,
}*/

//TODO: Process name hash (here cached in structure or on stack)
//      Function will eventually have to filter out of a lot of entries
//      Especially on Linux.
// TODO: use list_t
/// Obtain the memory map of modules for the current process.
///
/// To close, call adbg_memory_maps_close. On error, all memory buffers
/// are cleaned.
/// Params:
/// 	tracee = Tracee, in the ready or paused state.
/// 	mmaps = Reference to map list.
/// 	mcount = Reference to map count.
/// 	... = Options.
/// Returns: Error code.
int adbg_memory_maps(adbg_process_t *tracee, adbg_memory_map_t **mmaps, size_t *mcount, ...) {
	if (tracee == null || mmaps == null || mcount == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	// Get options
	va_list list = void;
	va_start(list, mcount);
	/*
	int options;
Loption:
	*/
	switch (va_arg!int(list)) {
	case 0: break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	version (Trace) trace("tracee=%p mmaps=%p mcount=%p", tracee, mmaps, mcount);
	
	// Failsafe
	*mcount = 0;
	
	if (tracee.pid == 0)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	// Add EnumPageFilesA?
version (Windows) {
	if (__dynlib_psapi_load()) // EnumProcessModules, QueryWorkingSet
		return adbg_errno();
	
	size_t uindex; /// (user) map index
	
	// Create user buffer
	adbg_memory_map_t *map = *mmaps = cast(adbg_memory_map_t*)malloc(2048 * adbg_memory_map_t.sizeof);
	if (map == null)
		return adbg_oops(AdbgError.os);
	
	//
	// Query memory regions for process
	//
	
	// NOTE: Putty 0.80 will have around 1095 entries
	uint bfsz = MiB!1;
	PSAPI_WORKING_SET_INFORMATION *mbinfo =
		cast(PSAPI_WORKING_SET_INFORMATION*)malloc(bfsz);
	if (mbinfo == null)
		return adbg_oops(AdbgError.crt);
	
	// NOTE: NtPssCaptureVaSpaceBulk is only available since Windows 10 20H1
	// This queries workset addresses regardless of size, page-bounded.
	// e.g., it will add 0x30000 and 0x31000 as entries, despite being a 8K "block".
Lretry:
	uint r = QueryWorkingSet(tracee.hpid, mbinfo, bfsz);
	switch (r) {
	case 0:
		return adbg_oops(AdbgError.os);
	case ERROR_BAD_LENGTH:
		bfsz = cast(uint)(mbinfo.NumberOfEntries * ULONG_PTR.sizeof);
		mbinfo = cast(PSAPI_WORKING_SET_INFORMATION*)realloc(mbinfo, bfsz);
		if (mbinfo == null)
			return adbg_oops(AdbgError.crt);
		goto Lretry;
	default:
	}
	scope(exit) free(mbinfo);
	
	size_t pagesize = adbg_memory_pagesize();
	if (pagesize == 0)
		return adbg_oops(AdbgError.os);
	
	//TODO: Huge page support
	//TODO: Use MEMORY_BASIC_INFORMATION32 or 64 depending on wow64
	
	//PSAPI_WORKING_SET_EX_INFORMATION wsinfoex = void;
	for (size_t i; i < mbinfo.NumberOfEntries; ++i) {
		// NOTE: Win64 doesn't populate block flag bits
		PSAPI_WORKING_SET_BLOCK *blk = &mbinfo.WorkingSetInfo.ptr[i];
		
		/*TODO: Large page support + adjustment needed
		
		wsinfoex.VirtualAddress = cast(void*)blk.VirtualPage;
		if (QueryWorkingSetEx(tracee.hpid, &wsinfoex,
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
		if (VirtualQueryEx(tracee.hpid, cast(void*)blk.VirtualPage,
			&mem, MEMORY_BASIC_INFORMATION.sizeof) == 0) {
			continue;
		}
		
		// Skip memory region when non-commited
		// Usually never happens with addresses given by QueryWorkingSet
		if (mem.State & (MEM_FREE | MEM_RESERVE))
			continue;
		
		// Get mapped file
		if (GetMappedFileNameA(tracee.hpid, mem.BaseAddress, map.name.ptr, MEM_MAP_NAME_LEN)) {
			map.name[GetModuleFileNameExA(tracee.hpid, null, map.name.ptr, MEM_MAP_NAME_LEN)] = 0;
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
		
		++uindex; ++map;
		
		// Memory region is less or equal to pagesize?
		// No further adjustments to do
		if (mem.RegionSize <= pagesize)
			continue;
		
		// Otherwise, get ready to skip future pages if they are
		// related (memory address and size follows by pagesize).
		void *end = mem.BaseAddress + mem.RegionSize;
		while (i + 1 < mbinfo.NumberOfEntries) {
			void *page = cast(void*)mbinfo.WorkingSetInfo.ptr[i + 1].VirtualPage;
			if (VirtualQueryEx(tracee.hpid, page,
				&mem, MEMORY_BASIC_INFORMATION.sizeof) == 0)
				break;
			if (mem.BaseAddress > end) break;
			++i;
		}
	}
	
	//
	// Query modules for process
	//
	
	// Allocate temp buffer for module handles
	uint buffersz = cast(uint)(512 * HMODULE.sizeof);
	HMODULE *mods = cast(HMODULE*)malloc(buffersz);
	if (mods == null)
		return adbg_oops(AdbgError.crt);
	scope(exit) free(mods);
	
	// Enum process modules
	DWORD needed = void; //TODO: Could re-use this with option
	if (EnumProcessModules(tracee.hpid, mods, buffersz, &needed) == FALSE)
		return adbg_oops(AdbgError.os);
	
	DWORD modcount = needed / HMODULE.sizeof;
	for (DWORD mod_i; mod_i < modcount; ++mod_i) {
		HMODULE mod = mods[mod_i];
		MODULEINFO minfo = void;
		if (GetModuleInformation(tracee.hpid, mod, &minfo, MODULEINFO.sizeof) == FALSE) {
			continue;
		}
		
		// Get base name (e.g., from \Device\HarddiskVolume5\xyz.dll)
		if (GetMappedFileNameA(tracee.hpid, minfo.lpBaseOfDll, map.name.ptr, MEM_MAP_NAME_LEN)) {
			map.name[GetModuleFileNameExA(tracee.hpid, mod, map.name.ptr, MEM_MAP_NAME_LEN)] = 0;
		} else {
			map.name[0] = 0;
		}
		
		//TODO: version (Win64) if (proc.wow) use MEMORY_BASIC_INFORMATION32
		
		MEMORY_BASIC_INFORMATION mem = void;
		if (VirtualQueryEx(tracee.hpid, minfo.lpBaseOfDll, &mem, MEMORY_BASIC_INFORMATION.sizeof) == 0) {
			continue;
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
		
		map.type = AdbgPageUse.module_;
		map.base = minfo.lpBaseOfDll;
		map.size = minfo.SizeOfImage;
		
		++uindex; ++map;
	}
	
	*mcount = uindex;
	return 0;
} else version (linux) {
	// Inspired by libscanmem
	// https://github.com/scanmem/scanmem/blob/main/maps.c
	
	import core.sys.linux.unistd : readlink;
	import adbg.utils.strings : adbg_util_getline, adbg_util_getlinef;
	import core.sys.linux.unistd : read, close;
	import core.sys.linux.fcntl : open, O_RDONLY;
	
	*mcount = 0;
	
	// Formulate proc map path
	enum PROC_MAPS_LEN = 32;
	char[PROC_MAPS_LEN] proc_maps = void;
	snprintf(proc_maps.ptr, PROC_MAPS_LEN, "/proc/%u/maps", tracee.pid);
	version (Trace) trace("maps: %s", proc_maps.ptr);
	
	// Open process maps
	int fd_maps = open(proc_maps.ptr, O_RDONLY);
	if (fd_maps == -1)
		return adbg_oops(AdbgError.os);
	scope(exit) close(fd_maps);
	
	/*
	// Get proc exe path (e.g., /usr/bin/cat)
	enum PROC_EXE_LEN = 32;
	char[PROC_EXE_LEN] proc_exe = void;
	snprintf(proc_exe.ptr, PROC_EXE_LEN, "/proc/%u/exe", tracee.pid);
	
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
	
	// Allocate enough for maps buffer
	// For example: One Firefox process has around 149 KiB worth of
	// maps data with 1953 entries.
	enum READSZ = MiB!1;
	char *procbuf = cast(char*)malloc(READSZ);
	if (procbuf == null)
		return adbg_oops(AdbgError.crt);
	scope(exit) free(procbuf);
	
	// Read maps, as much as possible
	ssize_t readsz = read(fd_maps, procbuf, READSZ);
	if (readsz == -1)
		return adbg_oops(AdbgError.os);
	version (Trace) trace("flen=%zu", readsz);
	
	// Count number of newlines for number of items to allocate
	// Cut lines don't have newlines, so no worries here
	size_t itemcnt;
	for (size_t i; i < readsz; ++i)
		if (procbuf[i] == '\n') ++itemcnt;
	
	// Allocate map items
	version (Trace) trace("allocating %zu items", itemcnt);
	adbg_memory_map_t *map = *mmaps =
		cast(adbg_memory_map_t*)malloc(itemcnt * adbg_memory_map_t.sizeof);
	if (map == null)
		return adbg_oops(AdbgError.crt);
	
	// Go through each entry, which may look like this (without header):
	// Address range             Perm Offset   Dev   inode      Path
	// 55adaf007000-55adaf009000 r--p 00000000 08:02 1311130    /usr/bin/cat
	// Perms: r=read, w=write, x=execute, s=shared or p=private (CoW)
	// Path: Path or [stack], [stack:%id] (3.4 to 4.4), [heap]
	//       [vdso]: virtual dynamic shared object: https://lwn.net/Articles/615809/
	//       [vvar]: Stores a "mirror" of kernel variables required by virt syscalls
	//       [vsyscall]: Legacy user-kernel (jump?) tables for some syscalls
	enum LINE_LEN = 256;
	char[LINE_LEN] line = void;
	size_t linesz = void; /// line size
	size_t srcidx; /// maps source buffer index
	size_t i; /// maps index
	//TODO: use a variant with mutable string and actively cuts lines
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
		
		++i; ++map;
	}
	
	version (Trace) trace("finished");
	*mcount = i;
	return 0;
} else
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
	return adbg_oops(AdbgError.unimplemented);
}

/// Close the memory maps structure previously created by adbg_memory_maps.
/// Params: maps = Maps array.
void adbg_memory_maps_close(adbg_memory_map_t *maps) {
	if (maps) free(maps);
}

private bool adbg_mem_cmp_u8(void *v, void *c, size_t l) pure {
	return *cast(ubyte*)v != *cast(ubyte*)c;
}
private bool adbg_mem_cmp_u16(void *v, void *c, size_t l) pure {
	return *cast(ushort*)v != *cast(ushort*)c;
}
private bool adbg_mem_cmp_u32(void *v, void *c, size_t l) pure {
	return *cast(uint*)v != *cast(uint*)c;
}
private bool adbg_mem_cmp_u64(void *v, void *c, size_t l) pure {
	return *cast(ulong*)v != *cast(ulong*)c;
}
/*private bool adbg_mm_scan_u128(void *v, void *c, size_t l) {
	version (DigitalMars) {
		import core.simd : ubyte16, __simd, XMM, prefetch;
		ubyte16 v1 = void;
		ubyte16 v2 = void;
		prefetch!(false, 3)(v);
		prefetch!(false, 3)(c);
		v1 = *cast(ubyte16*)v;
		v2 = *cast(ubyte16*)c;
		return (cast(ubyte16)__simd(XMM.CMPSS, v1, v2, 0)).ptr[0] != 0;
	} else version (GNU) {
		
	} else version (LDC) {
		
	}
	version (D_SIMD) {
	} else {
		import core.stdc.string : memcmp;
		return memcmp(v, c, l) == 0;
	}
}*/
private bool adbg_mem_cmp_other(void *v, void *c, size_t l) pure {
	import core.stdc.string : memcmp;
	return memcmp(v, c, l) != 0;
}

/// Options for adbg_memory_scan.
enum AdbgScanOpt {
	/// Unaligned memory scans take a lot more time.
	/// Type: int
	/// Default: false
	unaligned	= 1,
	/// Set the initial capacity for results, other than the default.
	///
	/// Currently, the capacity does not increase dynamically.
	///
	/// Note: Currently, one entry is 24 Bytes.
	/// Type: int
	/// Default: 20_000
	capacity	= 3,
	// Report progress to callback.
	// Callback will report: stage name and a percentage on modules scanned.
	//progress_cb
	// Rescan this list instead. Don't forget to pass rescanListCount too.
	// Type: Internal
	//rescanList
	// Use this mmap list instead. Don't forget to pass customMMapCount too.
	//customMMap
	// To be used with customMMap.
	//customMMapCount
}

struct adbg_scan_t {
	adbg_process_t *process;
	adbg_scan_result_t *results;
	size_t result_count;
	
	adbg_memory_map_t *maps;
	size_t map_count;
}
struct adbg_scan_result_t {
	ulong address;
	adbg_memory_map_t *map; // base address
	union {
		ulong	value_u64;
		uint	value_u32;
		ushort	value_u16;
		ubyte	value_u8;
	}
}

//TODO: For future types, len(data) * capacity
//      Why? Data can be of any length (es. strings)
//      Bit of a à la Windows stragegy:
//      first buffer (uint.sizeof * capacity) is list of indexes
//      second buffer (len(str) * capacity) is list of strings
//      index points to list of strings
//      could/should make functions to help with that

/// Scan debuggee process memory for a specific value.
///
/// This function allocates the list to contain a list of 2000 items.
/// Memory allocated by this function can be freed using free(3).
/// This behavior may change in the future.
///
/// Example:
/// ---
/// adbg_scan_t scan;
/// int data = 42; // input
/// // Assume tracee is paused.
/// if (adbg_memory_scan(tracee, &scan, &data, int.sizeof, 0)) {
///     return; // Error
/// }
///
/// for (size_t i; i < count; ++i) {
///     printf("0x%llx", results[i]);
/// }
/// 
/// free(results);
/// ---
///
/// Params:
/// 	tracee = Tracee, in the ready or paused state.
/// 	data = Reference to user data.
/// 	datasize = Reference to user data size.
/// 	... = Options.
///
/// Returns: An instance of the scanner or null on error.
adbg_scan_t* adbg_memory_scan(adbg_process_t *tracee, void* data, size_t datasize, ...) {
	/// Until scanner gets better internals for variable-length
	/// data types. Don't want to scan gigabyte-sized types now.
	enum DATA_LIMIT = 4096;
	
	/// Default amount of items to allocate.
	enum DEFAULT_CAPACITY = 20_000;
	
	enum OPT_UNALIGNED = 1;
	
	// Initial check and setup
	if (tracee == null || data == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (datasize == 0) {
		adbg_oops(AdbgError.scannerDataEmpty);
		return null;
	}
	if (datasize > DATA_LIMIT) {
		adbg_oops(AdbgError.scannerDataLimit);
		return null;
	}
	
	// Check debugger status
	switch (tracee.status) with (AdbgProcStatus) {
	case standby, paused, running: break;
	default:
		adbg_oops(AdbgError.debuggerUnpaused);
		return null;
	}
	
	// Get options
	va_list list = void;
	va_start(list, datasize);
	int options;
	int capacity = DEFAULT_CAPACITY; // For results
L_OPT:
	switch (va_arg!int(list)) {
	case 0: break;
	case AdbgScanOpt.unaligned:
		if (va_arg!int(list)) options |= OPT_UNALIGNED;
		goto L_OPT;
	case AdbgScanOpt.capacity:
		capacity = va_arg!int(list);
		goto L_OPT;
	default:
		adbg_oops(AdbgError.invalidOption);
		return null;
	}
	
	// Initial setup
	adbg_scan_t *scanner = cast(adbg_scan_t*)malloc(adbg_scan_t.sizeof);
	if (scanner == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	scanner.process = tracee;
	
	// Get memory maps
	if (adbg_memory_maps(tracee, &scanner.maps, &scanner.map_count, 0))
		return null;
	
	// Get optimized compare func if able
	extern (C) bool function(void*, void*, size_t) cmp = void;
	switch (datasize) {
	case ulong.sizeof:	cmp = &adbg_mem_cmp_u64; break;
	case uint.sizeof:	cmp = &adbg_mem_cmp_u32; break;
	case ushort.sizeof:	cmp = &adbg_mem_cmp_u16; break;
	case ubyte.sizeof:	cmp = &adbg_mem_cmp_u8; break;
	default:		cmp = &adbg_mem_cmp_other;
	}
	
	// Make result list
	scanner.results = cast(adbg_scan_result_t*)malloc(capacity * adbg_scan_result_t.sizeof);
	if (scanner.results == null) {
		adbg_memory_scan_close(scanner);
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Make read buffer
	ubyte *read_buffer = cast(ubyte*)malloc(datasize);
	if (read_buffer == null) {
		adbg_memory_scan_close(scanner);
		adbg_oops(AdbgError.crt);
		return null;
	}
	scope(exit) free(read_buffer);
	
	version (Trace) trace("modules=%u", cast(uint)scanner.map_count);
	
	// New scan: Scan per memory region
	enum PERMS = AdbgMemPerm.readWrite; /// Minimum permission access
	uint read_size = cast(uint)datasize;
	size_t jmpsize = options & OPT_UNALIGNED ? 1 : datasize;
	size_t modcount = scanner.map_count;
	size_t i;
	scanner.result_count = 0;
	//TODO: Consider reading a page's worth instead of T.sizeof
	//TODO: Skip non-residential entries (waiting on Linux fix)
LENTRY:	for (size_t mi; mi < modcount; ++mi) {
		adbg_memory_map_t *map = &scanner.maps[mi];
		
		version (Trace) trace("perms=%x", map.access);
		
		//if ((map.access & PERMS) != PERMS)
		//	continue;
		
		void* start = map.base;
		void* end   = start + map.size;
		
		version (Trace) trace("start=%p end=%p", start, end);
		
		// Aligned reads for now
		for (; start + datasize < end; start += jmpsize) {
			// Read into buffer
			if (adbg_memory_read(tracee, cast(size_t)start, read_buffer, read_size)) {
				version (Trace)
					trace("read failed for %.512s", map.name.ptr);
				continue LENTRY;
			}
			
			// Different data
			if (cmp(read_buffer, data, datasize)) {
				continue;
			}
			
			// Add result
			adbg_scan_result_t *result = &scanner.results[i++];
			result.address = cast(ulong)start;
			result.map = map;
			memcpy(&result.value_u64, read_buffer, datasize);
			
			// No more entries can be inserted
			if (i >= capacity)
				break LENTRY;
		}
	}
	scanner.result_count = i;
	
	version (Trace) trace("results=%u", cast(uint)i);
	
	return scanner;
}

int adbg_memory_rescan(adbg_scan_t *scanner, void* data, size_t size) {
	// Initial check and setup
	if (scanner == null || data == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (size == 0)
		return adbg_oops(AdbgError.scannerDataEmpty);
	if (size > 8)
		return adbg_oops(AdbgError.scannerDataLimit);
	if (scanner.result_count == 0)
		return 0;
	// No prior scan performed
	if (scanner.process == null || scanner.map_count == 0) {
		scanner.result_count = 0;
		return 0;
	}
	
	// Make read buffer
	ubyte *read_buffer = cast(ubyte*)malloc(size);
	if (read_buffer == null)
		return adbg_oops(AdbgError.crt);
	
	// Get optimized compare func if able
	extern (C) bool function(void*, void*, size_t) cmp = void;
	switch (size) {
	case ulong.sizeof:	cmp = &adbg_mem_cmp_u64; break;
	case uint.sizeof:	cmp = &adbg_mem_cmp_u32; break;
	case ushort.sizeof:	cmp = &adbg_mem_cmp_u16; break;
	case ubyte.sizeof:	cmp = &adbg_mem_cmp_u8; break;
	default:		cmp = &adbg_mem_cmp_other;
	}
	
	uint read_size = cast(uint)size;
	// Strategy is to move items if we find a different value
	for (size_t i; i < scanner.result_count; ++i) {
		adbg_scan_result_t *result = &scanner.results[i];
		
		// Read into buffer
		// On fail: Could be that module was unloaded
		if (adbg_memory_read(scanner.process, cast(size_t)result.address, read_buffer, read_size)) {
			//TODO: trace()
			goto L_MOVE;
		}
		
		// Same data?
		if (cmp(read_buffer, &result.value_u64, size) == 0) {
			continue;
		}
		
	L_MOVE: // If data couldn't be read, or is different, then move results
		size_t c = --scanner.result_count;
		for (size_t ri = i; ri < c; ++ri) {
			memcpy(result, result + 1, adbg_scan_result_t.sizeof);
		}
	}
	
	return adbg_oops(AdbgError.unimplemented);
}

void adbg_memory_scan_close(adbg_scan_t *scanner) {
	if (scanner == null) return;
	if (scanner.maps) free(scanner.maps);
	if (scanner.results) free(scanner.results);
	free(scanner);
}