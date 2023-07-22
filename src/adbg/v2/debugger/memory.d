module adbg.v2.debugger.memory;

import adbg.v2.debugger.process : adbg_tracee_t;
import adbg.include.c.stdlib : malloc, free;
import adbg.include.c.stdio;
import core.stdc.config : c_long;
import adbg.error;

version (Windows) {
	pragma(lib, "Psapi.lib"); // for core.sys.windows.psapi
	
	import core.sys.windows.windows;
	import adbg.include.windows.wow64;
	import core.sys.windows.psapi : GetProcessImageFileNameA,
		GetMappedFileNameA, GetModuleBaseNameA;
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
int adbg_memory_read(adbg_tracee_t *tracee, size_t addr, void *data, uint size) {
	//TODO: FreeBSD/NetBSD/OpenBSD: PT_IO
	//      Linux 6.2 (include/uapi/linux/ptrace.h) still has no PTRACE_IO
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
			*dest = ptrace(PTRACE_PEEKDATA, tracee.pid, addr, null);
			if (errno)
				return adbg_oops(AdbgError.os);
		}
		
		r = size % c_long.sizeof;
		if (r) {
			errno = 0;
			c_long l = ptrace(PTRACE_PEEKDATA, tracee.pid, addr, null);
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
int adbg_memory_write(adbg_tracee_t *tracee, size_t addr, void *data, uint size) {
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
			if (ptrace(PTRACE_POKEDATA, tracee.pid,
				addr + (i * c_long.sizeof), user) < 0)
				return adbg_oops(AdbgError.os);
		}
		
		j = size % c_long.sizeof;
		if (j) {
			if (ptrace(PTRACE_POKEDATA, tracee.pid,
				addr + (i * c_long.sizeof), user) < 0)
				return adbg_oops(AdbgError.os);
		}
		return 0;
	} else return adbg_oops(AdbgError.unimplemented);
}

/// Memory permission access bits.
enum AdbgMemPerm {
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
struct adbg_memory_map {
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
	// Override default list size.
	//listSize	= 3,
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
int adbg_memory_maps(adbg_tracee_t *tracee, adbg_memory_map **mmaps, size_t *mcount, ...) {
	version (Windows) {
		import core.sys.windows.psapi :
			GetModuleInformation,
			EnumProcessModules,
			MODULEINFO;
		
		if (tracee.pid == 0) {
			return adbg_oops(AdbgError.notAttached);
		}
		if (mmaps == null || mcount == null) {
			return adbg_oops(AdbgError.nullArgument);
		}
		
		enum SIZE = 512 * HMODULE.sizeof;
		HMODULE *mods = cast(HMODULE*)malloc(SIZE);
		DWORD needed = void;
		if (EnumProcessModules(tracee.hpid, mods, SIZE, &needed) == FALSE) {
			free(mods);
			return adbg_oops(AdbgError.os);
		}
		
		DWORD modcount = needed / HMODULE.sizeof;
		
		adbg_memory_map *map = *mmaps = cast(adbg_memory_map*)malloc(modcount * adbg_memory_map.sizeof);
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
			if (GetMappedFileNameA(tracee.hpid, minfo.lpBaseOfDll, map.name.ptr, MEM_MAP_NAME_LEN) == FALSE) {
				// xyz.dll
				if (GetModuleBaseNameA(tracee.hpid, mod, map.name.ptr, MEM_MAP_NAME_LEN) == FALSE) {
					map.name[0] = 0;
				}
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
		import core.stdc.config : c_long;
		import core.stdc.stdlib : malloc, free;
		import core.sys.linux.unistd : readlink;
		import adbg.utils.string : adbg_util_getline, adbg_util_getlinef;
		import core.sys.linux.unistd : read, close;
		import core.sys.linux.fcntl : open, O_RDONLY;
		
		if (tracee.pid == 0) {
			return adbg_oops(AdbgError.notAttached);
		}
		if (mmaps == null || mcount == null) {
			return adbg_oops(AdbgError.nullArgument);
		}
		
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
		
		// Formulate proc exe path
		enum PROC_EXE_LEN = 32;
		char[PROC_EXE_LEN] proc_exe = void;
		snprintf(proc_exe.ptr, PROC_EXE_LEN, "/proc/%u/exe", tracee.pid);
		
		// Read link from proc exe for process path (e.g., /usr/bin/cat)
		enum EXE_PATH_LEN = 256;
		char[EXE_PATH_LEN] exe_path = void;
		version (Trace) trace("exe: %s", proc_exe.ptr);
		ssize_t linksz = readlink(proc_exe.ptr, exe_path.ptr, EXE_PATH_LEN);
		if (linksz > 0) {
			exe_path[linksz] = 0;
		} else { // Fail or empty
			exe_path[0] = 0;
		}
		
		// Allocate 4 MiB for input maps buffer
		// WebKit has about 164K worth of maps, for example
		// And then read as much as possible (not possible with fread)
		enum READSZ = 4 * 1024 * 1024;
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
		adbg_memory_map *map = *mmaps = cast(adbg_memory_map*)malloc(itemcnt * adbg_memory_map.sizeof);
		if (map == null) {
			free(procbuf);
			close(fd_maps);
			return adbg_oops(AdbgError.crt);
		}
		
		// Go through each entry, which may look like this (without header):
		// Address                   Perm Offset   Dev   inode      Path
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
		while (adbg_util_getline(line.ptr, LINE_LEN, &linesz, procbuf, &srcidx)) {
			size_t range_start = void;
			size_t range_end   = void;
			char[4] perms      = void; // rwxp
			uint offset        = void;
			uint dev_major     = void;
			uint dev_minor     = void;
			uint inode         = void;
			//char[512] path     = void;
			
			if (sscanf(line.ptr, "%zx-%zx %4s %x %x:%x %u %512s",
				&range_start, &range_end,
				perms.ptr, &offset, &dev_major, &dev_minor, &inode, map.name.ptr) < 8) {
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
			
			version (Trace) trace("entry: %zx %s", range_start, path.ptr);
			
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
		// FreeBSD: procstat(1)
		// - https://man.freebsd.org/cgi/man.cgi?query=vm_map
		// - https://github.com/freebsd/freebsd-src/blob/main/lib/libutil/kinfo_getvmmap.c
		// - args[0] = CTL_KERN
		// - args[1] = KERN_PROC
		// - args[2] = KERN_PROC_VMMAP
		// - args[3] = pid
		// NetBSD: pmap(1)
		// OpenBSD: procmap(1)
		return adbg_oops(AdbgError.notImplemented);
}

private bool adbg_mem_scan_u8(void *v, void *c, size_t l) {
	return *cast(ubyte*)v == *cast(ubyte*)c;
}
private bool adbg_mem_scan_u16(void *v, void *c, size_t l) {
	return *cast(ushort*)v == *cast(ushort*)c;
}
private bool adbg_mem_scan_u32(void *v, void *c, size_t l) {
	return *cast(uint*)v == *cast(uint*)c;
}
private bool adbg_mem_scan_u64(void *v, void *c, size_t l) {
	return *cast(ulong*)v == *cast(ulong*)c;
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
private bool adbg_mem_scan_other(void *v, void *c, size_t l) {
	import core.stdc.string : memcmp;
	return memcmp(v, c, l) == 0;
}

/// Options for adbg_memory_scan.
enum AdbgScanOpt {
	/// 
	unaligned	= 1,
	// Report progress to callback.
	//
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

/// Scan debuggee process memory for a specific value.
///
/// This function allocates the list to contain a list of 2000 items.
/// Memory allocated by this function can be freed using free(3).
/// This behavior may change in the future.
///
/// Example:
/// ---
/// // Assume tracee is paused.
///
/// ulong *results = void; size_t count = void;
/// int data = 42;
/// if (adbg_memory_scan(tracee, &results, &count, &data, int.sizeof, 0)) {
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
/// 	list = Reference to result list.
/// 	count = Reference to result list item count;
/// 	data = Reference to user data.
/// 	size = Reference to user data size.
/// 	... = Options.
///
/// Returns: Error code.
int adbg_memory_scan(adbg_tracee_t *tracee,
	ulong **list, size_t *count,
	void* data, size_t size, ...) {
	import adbg.v2.debugger.process : AdbgStatus;
	
	if (tracee == null || data == null ||
		list == null || count == null)
		return adbg_oops(AdbgError.nullArgument);
	if (size == 0)
		return adbg_oops(AdbgError.scannerDataEmpty);
	
	switch (tracee.status) with (AdbgStatus) {
	case ready, paused: break;
	default:
		*count = 0;
		return adbg_oops(AdbgError.notPaused);
	}
	
	adbg_memory_map *mmaps = void; size_t mcount = void;
	int e = adbg_memory_maps(tracee, &mmaps, &mcount, 0);
	if (e) return e;
	
	extern (C)
	bool function(void*, void*, size_t) scan = void;
	
	// get optimized scan func
	switch (size) {
	case ulong.sizeof:	scan = &adbg_mem_scan_u64; break;
	case uint.sizeof:	scan = &adbg_mem_scan_u32; break;
	case ushort.sizeof:	scan = &adbg_mem_scan_u16; break;
	case ubyte.sizeof:	scan = &adbg_mem_scan_u8; break;
	default:		scan = &adbg_mem_scan_other;
	}
	
	ubyte *buffer = cast(ubyte*)malloc(size);
	if (buffer == null) {
		free(mmaps);
		return adbg_oops(AdbgError.os);
	}
	
	// temporary thing until we get something similar to vector<T>
	enum TEMP_BUFITEMS = 2000;
	
	ulong *list_ = *list;
	list_ = cast(ulong*)malloc(ulong.sizeof * TEMP_BUFITEMS);
	if (list_ == null) {
		free(mmaps);
		free(buffer);
		return adbg_oops(AdbgError.os);
	}
	
	size_t count_ = *count;
	size_t list_i;
	L_MODULE: for (size_t mi; mi < mcount; ++mi, ++mmaps) {
		enum ACC = AdbgMemPerm.read;
		if ((mmaps.access & ACC) != ACC)
			continue; //TODO: trace
		
		void* start = mmaps.base;
		void* end   = start + mmaps.size;
		
		for (; start + size < end; start += size) {
			// Read into buffer
			if (adbg_memory_read(tracee, cast(size_t)start, buffer, cast(uint)size)) {
				//TODO: trace()
				continue;
			}
			// Found a hit
			if (scan(buffer, data, size)) {
				//TODO: trace()
				list_[list_i++] = cast(ulong)start;
				// No more entries
				if (list_i >= TEMP_BUFITEMS)
					break L_MODULE;
			}
		}
	}
	
	*count = count_;
	free(mmaps);
	free(buffer);
	
	return 0;
}
