/// OS file handling.
///
/// No user code should be using this directly, as it is used internally.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.os.file;

version (Windows) {
	import core.sys.windows.winnt :
		LPVOID,
		MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
		PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_READWRITE,
		PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
		DWORD, HANDLE, LARGE_INTEGER, FALSE,
		GENERIC_ALL, GENERIC_READ, GENERIC_WRITE,
		FILE_SHARE_READ;
	import core.sys.windows.winbase :
		GetLastError,
		CreateFileA, CreateFileW,
		SetFilePointerEx, GetFileSizeEx,
		ReadFile, ReadFileEx, WriteFile, FlushFileBuffers, CloseHandle,
		OPEN_ALWAYS, OPEN_EXISTING, INVALID_HANDLE_VALUE,
		FILE_BEGIN, FILE_CURRENT, FILE_END,
		VirtualAlloc, VirtualFree;

	private alias OSHANDLE = HANDLE;
	private alias SEEK_SET = FILE_BEGIN;
	private alias SEEK_CUR = FILE_CURRENT;
	private alias SEEK_END = FILE_END;

	private enum OFLAG_OPENONLY = OPEN_EXISTING;
} else version (Posix) {
	import core.sys.posix.unistd;
	import core.sys.posix.sys.types;
	import core.sys.posix.sys.stat;
	import core.sys.posix.fcntl;
	import core.stdc.errno;
	import core.stdc.stdio : SEEK_SET, SEEK_CUR, SEEK_END;
	import core.stdc.stdlib : malloc, free;
	
	// BLKGETSIZE64 missing from dmd 2.098.1 and ldc 1.24.0
	// ldc 1.24 missing core.sys.linux.fs
	// source musl 1.2.0 and glibc 2.25 has roughly same settings.
	
	private enum _IOC_NRBITS = 8;
	private enum _IOC_TYPEBITS = 8;
	private enum _IOC_SIZEBITS = 14;
	private enum _IOC_NRSHIFT = 0;
	private enum _IOC_TYPESHIFT = _IOC_NRSHIFT+_IOC_NRBITS;
	private enum _IOC_SIZESHIFT = _IOC_TYPESHIFT+_IOC_TYPEBITS;
	private enum _IOC_DIRSHIFT = _IOC_SIZESHIFT+_IOC_SIZEBITS;
	private enum _IOC_READ = 2;
	private enum _IOC(int dir,int type,int nr,size_t size) =
		(dir  << _IOC_DIRSHIFT) |
		(type << _IOC_TYPESHIFT) |
		(nr   << _IOC_NRSHIFT) |
		(size << _IOC_SIZESHIFT);
	//TODO: _IOR!(0x12,114,size_t.sizeof) results in ulong.max
	//      I don't know why, so I'm casting it to int to let it compile.
	//      Fix later.
	private enum _IOR(int type,int nr,size_t size) =
		cast(int)_IOC!(_IOC_READ,type,nr,size);
	
	private enum BLKGETSIZE64 = cast(int)_IOR!(0x12,114,size_t.sizeof);
	private alias BLOCKSIZE = BLKGETSIZE64;
	
	private extern (C) int ioctl(int,long,...);
	
	private alias OSHANDLE = int;
}

import adbg.error;

/// File seek origin.
enum OSFileSeek {
	start	= SEEK_SET,	/// Seek from start of file.
	current	= SEEK_CUR,	/// Seek from current position.
	end	= SEEK_END,	/// Seek from end of file.
}

/// 
enum OSFileOFlags {
	read = 1,
	write = 2,
	readWrite = read | write,
}

struct OSFILE {
	OSHANDLE handle;
	int status;
}

OSFILE* osfopen(const(char) *path, int flags) {
version (Windows) {
	OSFILE* file = cast(OSFILE*)VirtualAlloc(null, OSFILE.sizeof, MEM_COMMIT, PAGE_READWRITE);
	if (file == null) {
		version (Trace) trace("VirtualAlloc=%#x", GetLastError());
		return null;
	}
	
	uint dwAccess;
	if (flags & OSFileOFlags.read)  dwAccess |= GENERIC_READ;
	if (flags & OSFileOFlags.write) dwAccess |= GENERIC_WRITE;
	
	file.handle = CreateFileA(path, // lpFileName
		dwAccess,        // dwDesiredAccess
		FILE_SHARE_READ, // dwShareMode
		null,            // lpSecurityAttributes
		OPEN_EXISTING,   // dwCreationDisposition
		0,               // dwFlagsAndAttributes
		null             // hTemplateFile
	);
	if (file.handle == INVALID_HANDLE_VALUE) {
		version (Trace) trace("CreateFileA=%#x", GetLastError());
		VirtualFree(cast(void*)file, OSFILE.sizeof, MEM_RELEASE);
		return null;
	}
} else version (Posix) {
	OSFILE* file = cast(OSFILE*)malloc(OSFILE.sizeof);
	if (file == null)
		return null;
	
	int oflags; // O_RDONLY == 0
	if ((flags & OSFileOFlags.readWrite) == OSFileOFlags.readWrite)
		oflags |= O_RDWR;
	else if (flags & OSFileOFlags.write)
		oflags |= O_WRONLY;
	file.handle = .open(path, oflags);
	if (file.handle == 0) {
		free(file);
		return null;
	}
}
	file.status = 0;
	return file;
}

long osfseek(OSFILE* file, long position, OSFileSeek origin) {
version (Windows) {
	LARGE_INTEGER i = void;
	i.QuadPart = position;
	if (SetFilePointerEx(file.handle, i, &i, origin) == FALSE)
		return -1;
	return i.QuadPart;
} else version (OSX) {
	// NOTE: Darwin has set off_t as long and doesn't have lseek64
	position = lseek(file.handle, position, origin);
	if (position < 0)
		return -1;
	return position;
} else version (Posix) {
	position = lseek64(file.handle, position, origin);
	if (position < 0)
		return -1;
	return position;
}
}

long osftell(OSFILE* file) {
version (Windows) {
	LARGE_INTEGER i;
	SetFilePointerEx(file.handle, i, &i, FILE_CURRENT);
	return i.QuadPart;
} else version (OSX) {
	return lseek(file.handle, 0, SEEK_CUR);
} else version (Posix) {
	return lseek64(file.handle, 0, SEEK_CUR);
}
}

long osfsize(OSFILE* file) {
version (Windows) {
	LARGE_INTEGER li = void;
	if (GetFileSizeEx(file.handle, &li) == FALSE)
		return -1;
	return li.QuadPart;
} else version (Posix) {
	stat_t stats = void;
	if (fstat(file.handle, &stats) < 0)
		return -1;
	// NOTE: fstat(2) sets st_size to 0 on block devices
	switch (stats.st_mode & S_IFMT) {
	case S_IFREG: // File
	case S_IFLNK: // Link
		return stats.st_size;
	case S_IFBLK: // Block devices (like a disk)
		//TODO: BSD variants
		long s = void;
		return ioctl(file.handle, BLOCKSIZE, &s) < 0 ? -1 : s;
	default:
		return -1;
	}
}
}

int osfread(OSFILE* file, void* buffer, int size) {
version (Windows) {
	if (ReadFile(file.handle, buffer, size, cast(uint*)&size, null) == FALSE)
		return -1;
	return size;
} else version (Posix) {
	ssize_t len = .read(file.handle, buffer, size);
	if (len < 0)
		return -1;
	return cast(int)len;
}
}

int osfwrite(OSFILE* file, void* buffer, int size) {
version (Windows) {
	if (WriteFile(file.handle, buffer, size, cast(uint*)&size, null) == FALSE)
		return -1;
	return size;
} else version (Posix) {
	ssize_t len = .write(file.handle, buffer, size);
	if (len < 0)
		return -1;
	return cast(int)len;
}
}

void osfflush(OSFILE* file) {
version (Windows) {
	FlushFileBuffers(file.handle);
} else version (Posix) {
	.fsync(file.handle);
}
}

void osfclose(OSFILE* file) {
version (Windows) {
	CloseHandle(file.handle);
	VirtualFree(cast(void*)file, OSFILE.sizeof, MEM_RELEASE);
} else version (Posix) {
	.close(file.handle);
	free(file);
}
}
