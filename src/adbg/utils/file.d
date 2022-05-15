/**
 * File utility functions.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.utils.file;

private import core.stdc.stdio;
private import core.stdc.stdlib;

/// Read entire file into memory.
/// To release buffer, call free(3).
/// Returns: Buffer pointer. Null on error.
ubyte *adbg_util_readall(size_t *size, const(char) *path) {
	//TODO: Check filesize before continuing for 2GiB limitation
	FILE *f = fopen(path, "rb");
	if (f == null)
		return null;
	
	if (fseek(f, 0, SEEK_END))
		return null;
	
	*size = cast(size_t)ftell(f);
	fseek(f, 0, SEEK_SET); // rewind binding is broken
	
	ubyte *buffer = cast(ubyte*)malloc(*size);
	if (buffer == null)
		return null;
	
	if (fread(buffer, *size, 1, f) == 0)
		return null;
	
	fclose(f);
	return buffer;
}