/// Utility function for reading and writing into a process' memory.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.debugger.memory;

import adbg.v2.debugger.process : adbg_process_t;
import adbg.include.c.stdlib : malloc, free, calloc;
import adbg.include.c.stdio;
import adbg.include.c.stdarg;
import core.stdc.string : memcpy;
import core.stdc.config : c_long;
import adbg.error;

version (Windows) {
	import core.sys.windows.windows;
	import adbg.include.windows.wow64;
	import adbg.include.windows.psapi_dyn;
} else version (Posix) {
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait : waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.signal : kill, SIGKILL, siginfo_t, raise;
	import core.sys.posix.sys.uio;
	import core.sys.posix.fcntl : open;
	import core.stdc.stdlib : exit, malloc, free;
	import adbg.include.posix.mann;
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd;
	import adbg.include.linux.user;
	private enum __WALL = 0x40000000;
}

extern (C):

/// Read memory from child tracee.
///
/// Params:
/// 	tracee = Reference to tracee instance.
/// 	addr = Memory address (within the children address space).
/// 	data = Pointer to data.
/// 	size = Size of data.
///
/// Returns: Error code.
int adbg_memory_read(adbg_process_t *tracee, size_t addr, void *data, uint size) {
	if (tracee == null || data == null) {
		return adbg_oops(AdbgError.nullArgument);
	}
	
	//TODO: FreeBSD/NetBSD/OpenBSD: PT_IO
	//      Linux 6.2 (include/uapi/linux/ptrace.h) still has no PT_IO
	version (Windows) {
		if (ReadProcessMemory(tracee.hpid, cast(void*)addr, data, size, null) == 0)
			return adbg_oops(AdbgError.os);
		return 0;
	} else version (linux) { // Based on https://www.linuxjournal.com/article/6100
		import core.stdc.errno : errno;
		
		c_long *dest = cast(c_long*)data;	/// target
		int r = size / c_long.sizeof;	/// number of "long"s to read
		
		for (; r > 0; --r, ++dest, addr += c_long.sizeof) {
			errno = 0; // As manpage wants
			*dest = ptrace(PT_PEEKDATA, tracee.pid, addr, null);
			if (errno)
				return adbg_oops(AdbgError.os);
		}
		
		r = size % c_long.sizeof;
		if (r) {
			errno = 0;
			c_long l = ptrace(PT_PEEKDATA, tracee.pid, addr, null);
			if (errno)
				return adbg_oops(AdbgError.os);
			ubyte* dest8 = cast(ubyte*)dest, src8 = cast(ubyte*)&l;
			for (; r; --r) *dest8++ = *src8++; // inlined memcpy
		}
		return 0;
	} else return adbg_oops(AdbgError.unimplemented);
}

/// Write memory to debuggee child.
///
/// Params:
/// 	tracee = Reference to tracee instance.
/// 	addr = Memory address (within the children address space).
/// 	data = Pointer to data.
/// 	size = Size of data.
///
/// Returns: Error code.
int adbg_memory_write(adbg_process_t *tracee, size_t addr, void *data, uint size) {
	if (tracee == null || data == null) {
		return adbg_oops(AdbgError.nullArgument);
	}
	
	//TODO: FreeBSD/NetBSD/OpenBSD: PT_IO
	version (Windows) {
		if (WriteProcessMemory(tracee.hpid, cast(void*)addr, data, size, null) == 0)
			return adbg_oops(AdbgError.os);
		return 0;
	} else version (linux) { // Based on https://www.linuxjournal.com/article/6100
		import core.stdc.errno : errno;
		
		c_long *user = cast(c_long*)data;	/// user data pointer
		int i;	/// offset index
		int j = size / c_long.sizeof;	/// number of "blocks" to process
		
		for (; i < j; ++i, ++user) {
			if (ptrace(PT_POKEDATA, tracee.pid,
				addr + (i * c_long.sizeof), user) < 0)
				return adbg_oops(AdbgError.os);
		}
		
		j = size % c_long.sizeof;
		if (j) {
			if (ptrace(PT_POKEDATA, tracee.pid,
				addr + (i * c_long.sizeof), user) < 0)
				return adbg_oops(AdbgError.os);
		}
		return 0;
	} else return adbg_oops(AdbgError.unimplemented);
}

/// Memory permission access bits.
enum AdbgMemPerm : ushort {
	read	= 1,	/// Read permission
	write	= 1 << 1,	/// Write permission
	exec	= 1 << 3,	/// Execute permission
	private_	= 1 << 8,	/// Process memory is private
	shared_	= 1 << 9,	/// Process memory is shared
	
	// Common access patterns
	readWrite	= read | write,	/// Read and write permissions
	readExec	= read | exec,	/// Read and execution permissions
	all	= read | write | exec,	/// Read, write, and execute permissions
}

private enum MEM_MAP_NAME_LEN = 512;
/// Represents a mapped memory region
struct adbg_memory_map_t {
	/// Base memory region address.
	void *base;
	/// Size of region.
	size_t size;
	/// Access permissions.
	/// 
	int access;
	/// 
	char[MEM_MAP_NAME_LEN] name;
}

/// Memory options for adbg_memory_maps.
enum AdbgMapOpt {
	reserved_
	// Only get the memory regions for this process.
	// Type: None
	//processOnly	= 1,
	// With given Process ID instead
	// Permission issues may be raised
	//pid = 2,
	// Get this maximum amount of maps.
	//count	= 3,
}

/// Obtain the memory map for the current process.
///
/// This function allocates the list of results.
/// Memory allocated by this function can be freed using free(3).
/// This behavior may change in the future.
///
/// Params:
/// 	tracee = Tracee, in the ready or paused state.
/// 	mmaps = Reference to map list.
/// 	mcount = Reference to map count.
/// 	... = Options.
///
/// Returns: Error code.
int adbg_memory_maps(adbg_process_t *tracee, adbg_memory_map_t **mmaps, size_t *mcount, ...) {
	if (tracee == null || mmaps == null || mcount == null) {
		return adbg_oops(AdbgError.nullArgument);
	}
	
	// Get options
	va_list list = void;
	va_start(list, mcount);
L_OPT:
	switch (va_arg!int(list)) {
	case 0: break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	version (Trace) trace("tracee=%p mmaps=%p mcount=%p", tracee, mmaps, mcount);
	
	// Failsafe
	*mcount = 0;
	
	if (tracee.pid == 0) {
		return adbg_oops(AdbgError.notAttached);
	}
	
	version (Windows) {
		if (__dynlib_psapi_load())
			return adbg_oops(AdbgError.libLoader);
		
		enum SIZE = 512 * HMODULE.sizeof;
		HMODULE *mods = cast(HMODULE*)malloc(SIZE);
		DWORD needed = void;
		if (EnumProcessModules(tracee.hpid, mods, SIZE, &needed) == FALSE) {
			free(mods);
			return adbg_oops(AdbgError.os);
		}
		
		DWORD modcount = needed / HMODULE.sizeof;
		adbg_memory_map_t *map = *mmaps = cast(adbg_memory_map_t*)malloc(modcount * adbg_memory_map_t.sizeof);
		if (map == null) {
			free(mods);
			return adbg_oops(AdbgError.os);
		}
		
		size_t i; /// (user) map index
		for (DWORD mod_i; mod_i < modcount; ++mod_i) {
			HMODULE mod = mods[mod_i];
			MODULEINFO minfo = void;
			if (GetModuleInformation(tracee.hpid, mod, &minfo, MODULEINFO.sizeof) == FALSE) {
				continue;
			}
			// \Device\HarddiskVolume5\xyz.dll
			if (GetMappedFileNameA(tracee.hpid, minfo.lpBaseOfDll, map.name.ptr, MEM_MAP_NAME_LEN)) {
				// xyz.dll
				map.name[GetModuleBaseNameA(tracee.hpid, mod, map.name.ptr, MEM_MAP_NAME_LEN)] = 0;
			} else {
				map.name[0] = 0;
			}
			
			MEMORY_BASIC_INFORMATION mem = void;
			VirtualQuery(minfo.lpBaseOfDll, &mem, MEMORY_BASIC_INFORMATION.sizeof);
			
			// Needs a bit for Copy-on-Write?
			if (mem.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
				map.access = AdbgMemPerm.readExec;
			else if (mem.AllocationProtect & PAGE_EXECUTE_READWRITE)
				map.access = AdbgMemPerm.all;
			else if (mem.AllocationProtect & PAGE_EXECUTE_READ)
				map.access = AdbgMemPerm.readExec;
			else if (mem.AllocationProtect & PAGE_EXECUTE)
				map.access = AdbgMemPerm.exec;
			else if (mem.AllocationProtect & PAGE_READONLY)
				map.access = AdbgMemPerm.read;
			else if (mem.AllocationProtect & PAGE_READWRITE)
				map.access = AdbgMemPerm.readWrite;
			else if (mem.AllocationProtect & PAGE_WRITECOPY)
				map.access = AdbgMemPerm.read;
			else
				map.access = 0;
			
			map.access |= mem.Type == MEM_PRIVATE ? AdbgMemPerm.private_ : AdbgMemPerm.shared_;
			
			map.base = minfo.lpBaseOfDll;
			map.size = minfo.SizeOfImage;
			
			++i; ++map;
		}
		
		free(mods);
		*mcount = i;
		return 0;
	} else version (linux) {
		// Inspired by libscanmem
		// https://github.com/scanmem/scanmem/blob/main/maps.c
		
		import core.stdc.stdlib : malloc, free;
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
		
		// Allocate 2 MiB for input maps buffer
		// WebKit has about 164K worth of maps, for example
		// And then read as much as possible (not possible with fread!)
		enum READSZ = 2 * 1024 * 1024;
		//TODO: Consider mmap(2)
		char *procbuf = cast(char*)malloc(READSZ);
		if (procbuf == null) {
			version (Trace) trace("malloc failed");
			close(fd_maps);
			return adbg_oops(AdbgError.crt);
		}
		ssize_t readsz = read(fd_maps, procbuf, READSZ);
		if (readsz == -1) {
			version (Trace) trace("read failed");
			free(procbuf);
			close(fd_maps);
			return adbg_oops(AdbgError.os);
		}
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
		if (map == null) {
			free(procbuf);
			close(fd_maps);
			return adbg_oops(AdbgError.crt);
		}
		
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
			char[4] perms      = void; // rwxp
			uint offset        = void;
			uint dev_major     = void;
			uint dev_minor     = void;
			uint inode         = void;
			
			if (sscanf(line.ptr, "%zx-%zx %4s %x %x:%x %u %512s",
				&range_start, &range_end,
				perms.ptr, &offset,
				&dev_major, &dev_minor,
				&inode, map.name.ptr) < 8) {
				continue;
			}
			
			// ELF load address regions
			//
			// When the ELF loader loads an executable or library image into
			// memory, there is one memory region per section created:
			// .text (r-x), .rodata (r--), .data (rw-), and .bss (rw-).
			//
			// The 'x' permission of .text is used to detect the load address
			// (start of memory region) and the end of the ELF file in memory.
			//
			// .bss section:
			// - Except for the .bss section, all memory sections typically
			//   have the same filename of the executable image.
			// - Empty filenames typically indicates .bss memory regions, and
			//   may be consecutive with .data memory regions.
			// - With some ELF images, .bss and .rodata may not be present.
			//
			// Resources:
			// http://en.wikipedia.org/wiki/Executable_and_Linkable_Format
			// http://wiki.osdev.org/ELF
			// http://lwn.net/Articles/531148/
			
			//TODO: Adjust memory region permissions like libscanmem does
			
			version (Trace) trace("entry: %zx %s", range_start, map.name.ptr);
			
			map.base = cast(void*)range_start;
			map.size = range_end - range_start;
			
			map.access = perms[3] == 'p' ? AdbgMemPerm.private_ : AdbgMemPerm.shared_;
			if (perms[0] == 'r') map.access |= AdbgMemPerm.read;
			if (perms[1] == 'w') map.access |= AdbgMemPerm.write;
			if (perms[2] == 'x') map.access |= AdbgMemPerm.exec;
			
			++i; ++map;
		}
		
		*mcount = i;
		free(procbuf);
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
		return adbg_oops(AdbgError.notImplemented);
}

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
	/// Unaligned memory scans take a lot more time
	/// Type: bool
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
		ulong value_u64;
		uint value_u32;
		ushort value_u16;
		ubyte value__u8;
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
/// 	size = Reference to user data size.
/// 	... = Options.
///
/// Returns: An instance of the scanner or null on error.
adbg_scan_t* adbg_memory_scan(adbg_process_t *tracee, void* data, size_t size, ...) {
	import adbg.v2.debugger.process : AdbgStatus;
	
	/// Until scanner gets better internals for variable-length
	/// data types.
	enum DATA_LIMIT = ulong.sizeof; 
	
	// Initial check and setup
	if (tracee == null || data == null) {
		adbg_oops(AdbgError.nullArgument);
		return null;
	}
	if (size == 0) {
		adbg_oops(AdbgError.scannerDataEmpty);
		return null;
	}
	if (size > DATA_LIMIT) {
		adbg_oops(AdbgError.scannerDataLimit);
		return null;
	}
	
	// Check debugger status
	switch (tracee.status) with (AdbgStatus) {
	case standby, paused, running: break;
	default:
		adbg_oops(AdbgError.notPaused);
		return null;
	}
	
	// Set options
	va_list list = void;
	va_start(list, size);
	int capacity = 20_000; /// Default amount of items to allocate.
L_OPT:
	switch (va_arg!int(list)) {
	case 0: break;
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
	switch (size) {
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
	ubyte *read_buffer = cast(ubyte*)malloc(size);
	if (read_buffer == null) {
		adbg_memory_scan_close(scanner);
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	version (Trace) trace("modules=%u", cast(uint)scanner.map_count);
	
	// New scan: Scan per memory region
	enum PERMS = AdbgMemPerm.readWrite; /// Minimum permission access
	uint read_size = cast(uint)size;
	size_t i;
	scanner.result_count = 0;
	L_MODULE: for (size_t mi; mi < scanner.map_count; ++mi) {
		adbg_memory_map_t *map = &scanner.maps[mi];
		
		version (Trace) trace("perms=%x", map.access);
		
		//if ((map.access & PERMS) != PERMS)
		//	continue;
		
		//TODO: Module detection
		//      Scan through read+write non-exec sections
		
		void* start = map.base;
		void* end   = start + map.size;
		
		version (Trace) trace("start=%p end=%p", start, end);
		
		// Aligned reads for now
		for (; start + size < end; start += size) {
			// Read into buffer
			if (adbg_memory_read(tracee, cast(size_t)start, read_buffer, read_size)) {
				version (Trace)
					trace("read failed for %.512s", map.name.ptr);
				continue L_MODULE;
			}
			
			// Different data
			if (cmp(read_buffer, data, size)) {
				continue;
			}
			
			adbg_scan_result_t *result = &scanner.results[i++];
			result.address = cast(ulong)start;
			result.map = map;
			memcpy(&result.value_u64, read_buffer, size);
			
			// No more entries can be inserted
			if (i >= capacity)
				break L_MODULE;
		}
	}
	scanner.result_count = i;
	
	version (Trace) trace("results=%u", cast(uint)i);
	
	free(read_buffer); // Clear read buffer
	return scanner;
}

int adbg_memory_rescan(adbg_scan_t *scanner, void* data, size_t size) {
	// Initial check and setup
	if (scanner == null || data == null)
		return adbg_oops(AdbgError.nullArgument);
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