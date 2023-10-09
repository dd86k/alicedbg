/// Application utilities.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module utils;

/// Unformat text number.
/// Params:
///   result = Long pointer.
///   str = Input.
/// Returns: True if could not parse number.
bool unformat(int *result, const(char) *str) {
	import core.stdc.stdio : sscanf;
	return sscanf(str, "%i", result) != 1;
}

/// Unformat text number.
/// Params:
///   result = Long pointer.
///   str = Input.
/// Returns: True if could not parse number.
bool unformat64(long *result, const(char) *str) {
	import core.stdc.stdio : sscanf;
	return sscanf(str, "%lli", result) != 1;
}

/// Read entire file into memory. To release buffer, call free(3).
///
/// Limited to 2 GiB on some platforms, such as Windows.
///
/// Params:
///   path = File path.
///   size = Pointer to hold file size.
/// Returns: Buffer pointer. Null on CRT error.
ubyte *readall(const(char) *path, size_t *size) {
	import core.stdc.stdio : SEEK_SET, SEEK_END, FILE, fopen, ftell, fseek, fread, fclose;
	import core.stdc.stdlib : malloc;
	
	FILE *fd = fopen(path, "rb");
	if (fd == null)
		return null;
	
	scope(exit) fclose(fd);
	
	if (fseek(fd, 0, SEEK_END))
		return null;
	
	*size = cast(size_t)ftell(fd);
	fseek(fd, 0, SEEK_SET); // rewind binding is broken
	
	ubyte *buffer = cast(ubyte*)malloc(*size);
	if (buffer == null)
		return null;
	
	if (fread(buffer, *size, 1, fd) == 0)
		return null;
	
	return buffer;
}