/// Application utilities.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module utils;

import core.stdc.stdio : sscanf;

/// Unformat text number.
/// Params:
///   result = Long pointer.
///   str = Input.
/// Returns: True if could not parse number.
bool unformat(int *result, const(char) *str) {
	return sscanf(str, "%i", result) != 1;
}

/// Unformat text number.
/// Params:
///   result = Long pointer.
///   str = Input.
/// Returns: True if could not parse number.
bool unformat64(long *result, const(char) *str) {
	return sscanf(str, "%lli", result) != 1;
}

/// Read entire file into memory using the C FILE API.
///
/// To release its buffer, call free(3).
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

/// Return the pointer position at the file's basename.
///
/// On failure, returns original pointer.
/// Params: path = File path.
/// Returns: Non-null pointer
const(char)* basename(const(char) *path) {
	enum MAX = 4096;
	size_t last, i;
	char c = void;
	for (; (c = path[i]) != 0 && i < MAX; ++i) {
		switch (c) {
		case '/', '\\': last = i + 1; continue;
		default:
		}
	}
	// "test/" -> invalid
	return last >= i ? path : path + last;
}
unittest {
	import core.stdc.string : strcmp;
	const(char) *path = "test/file.lib";
	const(char) *base = basename(path);
	assert(base);
	assert(strcmp(base, "file.lib") == 0);
}