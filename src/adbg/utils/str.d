/**
 * String helper functions. Simple string functions to aid redundant typing.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.utils.str;

import core.stdc.stdio;
import core.stdc.stdarg;
import core.stdc.string;

extern (C):

/// An empty string in case compilers does not support pool strings.
__gshared char *empty_string = cast(char*)"";

//TODO: Rewrite as adbg_util_flatten without snprintf
//      Internal loop
size_t adbg_util_argv_flatten(char *buf, int buflen, const(char) **argv) {
	import core.stdc.stdio : snprintf;
	if (argv == null)
		return 0;

	ptrdiff_t ai, bi, t;
	while (argv[ai]) {
		t = snprintf(buf + bi, buflen, "%s ", argv[ai]);
		if (t < 0)
			return 0;
		bi += t;
		++ai;
	}

	return bi;
}

/// Expand a command-line string into an array of items.
/// The input string is copied into the internal buffer.
/// Params:
/// 	str = Input string
/// 	argc = Pointer that will receive the argument count, can be null
/// Returns:
/// 	Internal buffer with seperated items, otherwise null if no items were
/// 	processed.
/// Note: The internal buffer is 2048 characters and processes up to 32 items.
char** adbg_util_expand(const(char) *str, int *argc) {
	import core.stdc.ctype : isalnum, ispunct;
	enum BUFFER_LEN   = 2048;
	enum BUFFER_ITEMS = 32;
	__gshared char[BUFFER_LEN] _buffer;	/// internal string buffer
	__gshared char*[BUFFER_ITEMS] _argv;	/// internal argv buffer
	
	if (str == null)
		return null;

	strncpy(_buffer.ptr, str, BUFFER_LEN);
	
	size_t index;	/// string character index
	int _argc;	/// argument counter
	
L_ARG:
	// maximum number of items reached
	if (_argc >= BUFFER_ITEMS)
		goto L_RETURN;
	
	// move pointer to first non-white character
	A: while (index < BUFFER_LEN) {
		const char c = _buffer[index];
		
		switch (c) {
		case 0: goto L_RETURN;
		case '\n', '\r':
			_buffer[index] = 0;
			goto L_RETURN;
		case ' ', '\t':
			++index;
			continue;
		default: break A;
		}
	}
	
	// set argument at position
	_argv[_argc++] = cast(char*)_buffer + index;
	
	// get how long the parameter length is
	while (index < BUFFER_LEN) {
		const char c = _buffer[index];
		
		switch (c) {
		case 0: goto L_RETURN;
		case'\n', '\r':
			_buffer[index] = 0;
			goto L_RETURN;
		case ' ', '\t':
			_buffer[index++] = 0;
			goto L_ARG;
		default: ++index; continue;
		}
	}
	
	// reached the end before we knew it
L_RETURN:
	_argv[_argc] = null;
	if (argc) *argc = _argc;
	return _argc ? cast(char**)_argv : null;
}

/// Process a comma-seperated list of key=value pairs into an internal buffer.
/// Params:
/// 	str = String buffer
/// Returns:
/// 	Internal buffer with seperated items, otherwise null if no items were
/// 	processed.
/// Note: The internal buffer is 2048 characters and processes up to 32 items.
char** adbg_util_env(const(char) *str) {
	enum BUFFER_LEN   = 2048;
	enum BUFFER_ITEMS = 32;
	__gshared char[BUFFER_LEN] _buffer;	/// internal string buffer
	__gshared char*[BUFFER_ITEMS] _envp;	/// internal envp buffer
	
	char *last = cast(char*)_buffer; /// last item position
	
	strncpy(last, str, BUFFER_LEN);
	
	_envp[0] = last;
	
	size_t bindex, eindex; // buffer and env indexes
	
	while (bindex < BUFFER_LEN) {
		char c = _buffer[bindex];
		
		switch (c) {
		case 0: goto L_RETURN;
		case ',':
			_buffer[bindex++] = 0;
			last = cast(char*)_buffer + bindex;
			_envp[++eindex] = last;
			continue;
		default:
		}
		
		++bindex;
	}
	
L_RETURN:
	return eindex ? cast(char**)_envp : null;
}

/// Move (copy) the pointers of two arrays.
/// Params:
/// 	dst = Destination pointer
/// 	dstsz = Destination buffer size, typically how many items it can hold
/// 	src = Source pointer
/// 	srcsz = Source buffer size, typically how many items to transfer
/// Returns:
/// 	Number of items copied
int adbg_util_move(void **dst, int dstsz, void **src, int srcsz) {
	int r;
	
	while (r < dstsz && r < srcsz) {
		dst[r] = src[r];
		++r;
	}
	
	return r;
}

//
// Fast hexadecimal formatting
//

/// Hexadecimal map for strx0* functions to provide much faster %x parsing
private immutable char [16]hexmaplow = "0123456789abcdef";
/// Hexadecimal map for strx0* functions to provide much faster %X parsing
private immutable char [16]hexmapupp = "0123456789ABCDEF";

/**
 * Quick and dirty conversion function to convert an ubyte value to a
 * '0'-padded hexadecimal string. Faster than using vsnprintf.
 * Params:
 * 	v = 8-bit value
 * 	upper = Use upper hexadecimal character
 * Returns: Null-terminated hexadecimal string
 */
const(char) *adbg_util_strx02(ubyte v, bool upper = false) {
	__gshared char [3]b = void;

	const(char) *h = cast(char*)(upper ? hexmapupp : hexmaplow);

	b[0] = h[v >> 4];
	b[1] = h[v & 0xF];
	b[2] = 0;

	return cast(char*)b;
}

/**
 * Quick and dirty conversion function to convert an ushort value to a
 * '0'-padded hexadecimal string. Faster than using vsnprintf.
 * Params:
 * 	v = 8-bit value
 * 	upper = Use upper hexadecimal character
 * Returns: Null-terminated hexadecimal string
 */
const(char) *adbg_util_strx04(ushort v, bool upper = false) {
	__gshared char [5]b = void;

	const(char) *h = cast(char*)(upper ? hexmapupp : hexmaplow);

	b[4] = 0;
	b[3] = h[v & 0xF];
	b[2] = h[(v >>= 4) & 0xF];
	b[1] = h[(v >>= 4) & 0xF];
	b[0] = h[(v >>= 4) & 0xF];

	return cast(char*)b;
}

/**
 * Quick and dirty conversion function to convert an uint value to a
 * '0'-padded hexadecimal string. Faster than using vsnprintf.
 * Params:
 * 	v = 8-bit value
 * 	upper = Use upper hexadecimal character
 * Returns: Null-terminated hexadecimal string
 */
const(char) *adbg_util_strx08(uint v, bool upper = false) {
	__gshared char [9]b = void;

	const(char) *h = cast(char*)(upper ? hexmapupp : hexmaplow);

	b[8] = 0;
	b[7] = h[v & 0xF];
	b[6] = h[(v >>= 4) & 0xF];
	b[5] = h[(v >>= 4) & 0xF];
	b[4] = h[(v >>= 4) & 0xF];
	b[3] = h[(v >>= 4) & 0xF];
	b[2] = h[(v >>= 4) & 0xF];
	b[1] = h[(v >>= 4) & 0xF];
	b[0] = h[(v >>= 4) & 0xF];

	return cast(char*)b;
}

/**
 * Quick and dirty conversion function to convert an ulong value to a
 * '0'-padded hexadecimal string. Faster than using vsnprintf.
 * Params:
 * 	v = 8-bit value
 * 	upper = Use upper hexadecimal character
 * Returns: Null-terminated hexadecimal string
 */
const(char) *adbg_util_strx016(ulong v, bool upper = false) {
	__gshared char [17]b = void;

	const(char) *h = cast(char*)(upper ? hexmapupp : hexmaplow);

	b[16] = 0;
	b[15] = h[v & 0xF];
	b[14] = h[(v >>= 4) & 0xF];
	b[13] = h[(v >>= 4) & 0xF];
	b[12] = h[(v >>= 4) & 0xF];
	b[11] = h[(v >>= 4) & 0xF];
	b[10] = h[(v >>= 4) & 0xF];
	b[9]  = h[(v >>= 4) & 0xF];
	b[8]  = h[(v >>= 4) & 0xF];
	b[7]  = h[(v >>= 4) & 0xF];
	b[6]  = h[(v >>= 4) & 0xF];
	b[5]  = h[(v >>= 4) & 0xF];
	b[4]  = h[(v >>= 4) & 0xF];
	b[3]  = h[(v >>= 4) & 0xF];
	b[2]  = h[(v >>= 4) & 0xF];
	b[1]  = h[(v >>= 4) & 0xF];
	b[0]  = h[(v >>= 4) & 0xF];

	return cast(char*)b;
}

//
// Generic string manipulation
//

/**
 * Lower case string buffer ('A' to 'Z' only).
 * Params:
 * 	buf  = String buffer
 * 	size = Buffer size
 */
void adbg_util_str_lowercase(char *buf, size_t size) {
	for (size_t i; buf[i] && i < size; ++i)
		if (buf[i] >= 'A' && buf[i] <= 'Z')
			buf[i] += 32;
}

size_t adbg_util_str_appendc(char *buffer, size_t size, char c) {
	*buffer = c;
	*(buffer + 1) = 0;
	return 1;
}
size_t adbg_util_str_appends(char *buffer, size_t size, const(char) *str) {
	size_t pos;
	size_t sz = size - 1;
	for (; pos < sz && str[pos]; ++pos)
		buffer[pos] = str[pos];
	buffer[pos] = 0;
	return pos;
}
//TODO: Consider adbg_util_str_append_s(char *buffer, size_t size, const(char) *str, size_t size2)
size_t adbg_util_str_appendf(char *buffer, size_t size, const(char) *fmt, ...) {
	va_list va = void;
	va_start(va, fmt);
	return adbg_util_str_appendv(buffer, size, fmt, va);
}
size_t adbg_util_str_appendv(char *buffer, size_t size, const(char) *fmt, va_list va) {
	return vsnprintf(buffer, size, fmt, va);
}

/// String structure to ease development.
/// Used in the disassembler.
//TODO: Consider just returning number of characters written to buffer
//      So doing add('a') == 0 is the same as returning true if full
struct adbg_string_t {
	char  *str;	/// String pointer
	size_t size;	/// Buffer size, capacity
	size_t pos;	/// Position, count
	
	/// Inits a string position tracker with a buffer and its size.
	/// This does not create a string.
	/// Params:
	/// 	buffer = Buffer pointer.
	/// 	buffersz = Buffer capacity.
	this(char *buffer, size_t buffersz) {
		str  = buffer;
		size = buffersz;
		pos  = 0;
	}
	/// Reset counters and optionally zero-fill the buffer.
	/// Params: zero = If true, fills the buffer of zeros.
	void reset(bool zero = false) {
		if (zero)
			for (size_t p; p < size; ++p)
				str[p] = 0;
		pos = 0;
	}
	/// Add character to buffer.
	/// Params: c = Character
	/// Returns: True if buffer exhausted.
	bool addc(char c) {
		if (pos >= size)
			return true;
		char *s = str + pos;
		*s = c;
		*(s + 1) = 0;
		++pos;
		return false;
	}
	/// Add a constant string to buffer.
	/// Params: s = String
	/// Returns: True if buffer exhausted.
	bool adds(const(char) *s) {
		for (size_t si; pos < size && s[si]; ++pos, ++si)
			str[pos] = s[si];
		str[pos] = 0;
		return pos >= size;
	}
	//TODO: adbg_string_t.add_s
	/// Add multiple items to buffer.
	/// Params:
	/// 	fmt = Format specifier.
	/// 	... = Parameters.
	/// Returns: True if buffer exhausted.
	bool addf(const(char) *fmt, ...) {
		va_list va = void;
		va_start(va, fmt);
		return addv(fmt, va);
	}
	/// Add a list of items to buffer.
	/// Params:
	/// 	fmt = Format specifier.
	/// 	va = va_list object.
	/// Returns: True if buffer exhausted.
	bool addv(const(char) *fmt, va_list va) {
		pos += vsnprintf(str + pos, size - pos, fmt,va);
		return pos >= size;
	}
	bool addx8(ubyte v, bool pad = false) {
		if (pos + 3 >= size) return true;
		ubyte vh = v >> 4;
		ubyte vl = v & 15;
		if (vh || pad) str[pos++] = hexmaplow[vh];
		str[pos++] = hexmaplow[vl];
		str[pos] = 0;
		return pos >= size;
	}
	bool addx16(ushort v, bool pad = false) {
		for (int shift = 12; pos < size && shift >= 0; shift -= 4) {
			ushort h = (v >> shift) & 15;
			if (h == 0 && pad == false) continue;
			str[pos++] = hexmaplow[h];
			if (h) pad = true;
		}
		str[pos] = 0;
		return pos >= size;
	}
	bool addx32(uint v, bool pad = false) {
		for (int shift = 28; pos < size && shift >= 0; shift -= 4) {
			uint h = (v >> shift) & 15;
			if (h == 0 && pad == false) continue;
			str[pos++] = hexmaplow[h];
			if (h) pad = true;
		}
		str[pos] = 0;
		return pos >= size;
	}
	bool addx64(ulong v, bool pad = false) {
		for (int shift = 60; pos < size && shift >= 0; shift -= 4) {
			ulong h = (v >> shift) & 15;
			if (h == 0 && pad == false) continue;
			version (D_LP64)
				str[pos++] = hexmaplow[h];
			else
				str[pos++] = hexmaplow[cast(uint)h]; // for 32-bit systems
			if (h) pad = true;
		}
		str[pos] = 0;
		return pos >= size;
	}
}
