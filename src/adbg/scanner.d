/// Memory scanner.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.scanner;

import adbg.error;
import adbg.process.base;
import adbg.process.memory;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import adbg.utils.list;
import core.stdc.string;

extern (C):

/// Options for adbg_memory_scan.
enum AdbgScanOption {
	/// Unaligned memory scans take a lot more time.
	/// Type: int
	/// Default: 0 (false)
	unaligned	= 1,
	/// Include all process modules in the scan.
	/// Type: int
	/// Default: 0 (false)
	allModules	= 2,
	// TODO: result limit/maximum
	// TODO: comparison callback
	// TODO: progress callback
}

struct adbg_scanner_t {
	adbg_process_t *process;
	//void *pmaps;
	list_t *results;
	size_t datasize;	/// size of initial data
	int options;
}
struct adbg_scanner_result_t {
	ulong address;
	union {
		ulong u64;
	}
}

// new scan
adbg_scanner_t* adbg_scanner_scan(adbg_process_t *process, void* data, size_t datasize, ...) {
	if (process == null || data == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (datasize == 0) {
		adbg_oops(AdbgError.scannerDataEmpty);
		return null;
	}
	if (datasize > ulong.sizeof) {
		adbg_oops(AdbgError.scannerDataLimit);
		return null;
	}
	
	enum {
		OPTION_UNALIGNED = 1,
		OPTION_ALLMODULES = 2,
	}
	
	// Get options
	va_list list = void;
	va_start(list, datasize);
	int options;
Loption:
	switch (va_arg!int(list)) {
	case 0: break;
	case AdbgScanOption.unaligned:
		if (va_arg!int(list)) options |= OPTION_UNALIGNED;
		goto Loption;
	case AdbgScanOption.allModules:
		if (va_arg!int(list)) options |= OPTION_ALLMODULES;
		goto Loption;
	default:
		adbg_oops(AdbgError.invalidOption);
		return null;
	}
	
	// Allocate enough for struct instance
	adbg_scanner_t *scanner = cast(adbg_scanner_t*)calloc(1, adbg_scanner_t.sizeof);
	if (scanner == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Get memory mapping for process
	void *pmaps = adbg_memory_mapping(process,
		AdbgMappingOption.allModules, options & OPTION_ALLMODULES,
		0);
	if (pmaps == null) { // error already set
		free(scanner);
		return null;
	}
	
	// Setup
	scanner.results = adbg_list_new(adbg_scanner_result_t.sizeof, 128);
	if (scanner.results == null) { // error set
		free(scanner);
		return null;
	}
	scanner.process = process;
	
	// Buffer for reading from process memory
	void *mbuffer = malloc(datasize);
	if (mbuffer == null) {
		adbg_oops(AdbgError.crt);
		adbg_list_free(scanner.results);
		free(scanner);
		return null;
	}
	scanner.datasize = datasize;
	scanner.options = options;
	
	// TODO: Consider reading a page's worth instead of datasize
	// TODO: Consider performing aligned reads (LP32=4,LP64=8)
	// New scan: Scan per memory region
	size_t al = options & OPTION_UNALIGNED ? 1 : datasize; /// alignment
	adbg_memory_map_t *map = void;
	Lmap: for (size_t i; (map = adbg_memory_mapping_at(pmaps, i)) != null; ++i) {
		size_t mbase = cast(size_t)map.base;
		size_t msize = map.size;
		
		// while input fits memory range
		for (size_t pos = mbase; pos + datasize < mbase + msize; pos += al) {
			// can't read? move to next range
			if (adbg_memory_read(process, pos, mbuffer, datasize))
				continue Lmap;
			
			// data different than input? jump to next alignment
			if (memcmp(mbuffer, data, datasize))
				continue;
			
			// add result
			adbg_scanner_result_t result = void;
			result.address = pos;
			memcpy(&result.u64, mbuffer, datasize);
			with(scanner) results = adbg_list_add(results, &result);
			if (scanner.results == null) {
				adbg_scanner_close(scanner);
				return null;
			}
		}
	}
	
	return scanner;
}

// rescan/update entries by scanning results and removing entries that
// do not match the previous value
int adbg_scanner_rescan(adbg_scanner_t *scanner, void* data) {
	if (scanner == null || data == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (scanner.results == null || scanner.process == null || scanner.datasize == 0)
		return adbg_oops(AdbgError.uninitiated);
	
	size_t count = adbg_scanner_result_count(scanner);
	if (count == 0)
		return 0;
	
	//adbg_memory_mapping_close(scanner.pmaps);
	//scanner.pmaps = adbg_memory_mapping(scanner.process,
	
	// Buffer for reading from process memory
	void *mbuffer = malloc(scanner.datasize);
	if (mbuffer == null) {
		adbg_list_free(scanner.results);
		free(scanner);
		return adbg_oops(AdbgError.crt);
	}
	
	size_t i = count;
	do {
		adbg_scanner_result_t *result = adbg_scanner_result(scanner, --i);
		
		// unreadable, remove
		if (adbg_memory_read(scanner.process, cast(size_t)result.address, mbuffer, scanner.datasize)) {
			adbg_list_remove_at(scanner.results, i);
			continue;
		}
		
		// value changed, remove
		if (memcpy(mbuffer, data, scanner.datasize)) {
			adbg_list_remove_at(scanner.results, i);
			continue;
		}
	} while (i > 0);
	
	return 0;
}

size_t adbg_scanner_result_count(adbg_scanner_t *scanner) {
	if (scanner == null)
		return 0;
	return adbg_list_count(scanner.results);
}

// get address for result
adbg_scanner_result_t* adbg_scanner_result(adbg_scanner_t *scanner, size_t index) {
	if (scanner == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return cast(adbg_scanner_result_t*)adbg_list_get(scanner.results, index);
}

// get memory map for result
version (none)
adbg_memory_map_t* adbg_scanner_result_map(adbg_scanner_t *scanner, size_t index) {
	if (scanner == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return adbg_memory_mapping_at(scanner.pmaps, index);
}

void adbg_scanner_close(adbg_scanner_t *scanner) {
	if (scanner == null) return;
	adbg_list_free(scanner.results);
	//adbg_memory_mapping_close(scanner.pmaps);
	free(scanner);
}
