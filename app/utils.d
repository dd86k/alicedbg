/// Application utilities.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module utils;

import core.stdc.stdio : sscanf;
import core.stdc.ctype : isprint;

char hexc0(ubyte upper) {
	ubyte h = upper >> 4;
	return cast(char)(h >= 0xa ? h + ('a' - 0xa) : h + '0');
}
unittest {
	assert(hexc0(0x00) == '0');
	assert(hexc0(0x10) == '1');
	assert(hexc0(0x20) == '2');
	assert(hexc0(0x30) == '3');
	assert(hexc0(0x40) == '4');
	assert(hexc0(0x50) == '5');
	assert(hexc0(0x60) == '6');
	assert(hexc0(0x70) == '7');
	assert(hexc0(0x80) == '8');
	assert(hexc0(0x90) == '9');
	assert(hexc0(0xa0) == 'a');
	assert(hexc0(0xb0) == 'b');
	assert(hexc0(0xc0) == 'c');
	assert(hexc0(0xd0) == 'd');
	assert(hexc0(0xe0) == 'e');
	assert(hexc0(0xf0) == 'f');
}
char hexc1(ubyte lower) {
	ubyte l = lower & 15;
	return cast(char)(l >= 0xa ? l + ('a' - 0xa) : l + '0');
}
unittest {
	assert(hexc1(0) == '0');
	assert(hexc1(1) == '1');
	assert(hexc1(2) == '2');
	assert(hexc1(3) == '3');
	assert(hexc1(4) == '4');
	assert(hexc1(5) == '5');
	assert(hexc1(6) == '6');
	assert(hexc1(7) == '7');
	assert(hexc1(8) == '8');
	assert(hexc1(9) == '9');
	assert(hexc1(0xa) == 'a');
	assert(hexc1(0xb) == 'b');
	assert(hexc1(0xc) == 'c');
	assert(hexc1(0xd) == 'd');
	assert(hexc1(0xe) == 'e');
	assert(hexc1(0xf) == 'f');
}

int hexstr(char *buffer, size_t bsize, ubyte *data, size_t dsize, char sep = 0) {
	int min = sep ? 3 : 2;
	int len;
	for (size_t i; i < dsize; ++i) {
		if (len + min > bsize)
			return len;
		
		if (sep && len) buffer[len++] = sep;
		ubyte b = data[i];
		buffer[len++] = hexc0(b);
		buffer[len++] = hexc1(b);
	}
	return len;
}
unittest {
	ubyte[4] data = [ 0x12, 0x34, 0x56, 0x78 ];
	char[8] buf = void;
	int len = hexstr(buf.ptr, 8, data.ptr, 4);
	assert(len == 8);
	assert(buf[0] == '1');
	assert(buf[1] == '2');
	assert(buf[2] == '3');
	assert(buf[3] == '4');
	assert(buf[4] == '5');
	assert(buf[5] == '6');
	assert(buf[6] == '7');
	assert(buf[7] == '8');
}

int realchar(char *buffer, size_t bsize, char c) {
	int len;
	if (isprint(c)) {
		if (len >= bsize) goto end;
		buffer[len++] = c;
	} else {
		if (len + 4 >= bsize) goto end;
		buffer[len++] = '\\';
		buffer[len++] = 'x';
		buffer[len++] = hexc0(c);
		buffer[len++] = hexc1(c);
	}
	end: return len;
}

int realstring(char *buffer, size_t bsize, const(char)* str, size_t ssize,
	char pre = 0, char post = 0) {
	int len; // total length
	
	if (bsize == 0)
		return 0;
	
	if (pre && bsize)
		buffer[len++] = pre;
	
	for (size_t i; i < ssize && len < bsize; ++i) {
		char c = str[i];
		if (isprint(c)) {
			if (len >= bsize) break;
			buffer[len++] = c;
		} else {
			if (len + 4 >= bsize) break;
			buffer[len++] = '\\';
			buffer[len++] = 'x';
			buffer[len++] = hexc0(c);
			buffer[len++] = hexc1(c);
		}
	}
	
	if (post && len < bsize)
		buffer[len++] = post;
	
	return len;
}
unittest {
	char[2]  bi = "`\n";
	char[10] bo = void; // '`' '\\x0a'
	assert(realstring(bo.ptr, 10, bi.ptr, 2) == 5);
	assert(bo[0] == '`');
	assert(bo[1] == '\\');
	assert(bo[2] == 'x');
	assert(bo[3] == '0');
	assert(bo[4] == 'a');
}

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

/// Returns default character if given character is outside ASCII range.
/// Params:
///   c = Character to evaluate.
///   d = Default character, fallback.
/// Returns: Character.
int asciichar(int c, int d) {
	return c < 32 || c > 126 ? d : c;
}