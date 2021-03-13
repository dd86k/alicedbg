/**
 * String helper functions. Simple string functions to aid redundant typing.
 *
 * License: BSD-3-Clause
 */
module adbg.utils.str;

import core.stdc.stdio;
import core.stdc.stdarg;
import core.stdc.string;

extern (C):
__gshared:

/// An empty string in case compilers cannot pool strings
const(char) *empty_string = "";

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
private char [16]hexmaplow = "0123456789abcdef";
/// Hexadecimal map for strx0* functions to provide much faster %X parsing
private char [16]hexmapupp = "0123456789ABCDEF";

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
// Generic string formatting
//

/**
 * Append a constant string to an existing buffer.
 * Params:
 * 	buf  = Existing character buffer
 * 	size = Buffer size
 * 	bufi = Buffer index
 * 	str  = String data
 * Returns: Updated buffer index
 */
size_t adbg_util_stradd(char *buf, size_t size, size_t bufi, const(char) *str) {
	size_t stri;
	while (str[stri] && bufi < size) {
		buf[bufi] = str[stri];
		++stri; ++bufi;
	}
	buf[bufi] = 0;
	return bufi;
}

/**
 * Append a formatted string to an existing buffer, calls adbg_util_straddva and adbg_util_stradd.
 * Params:
 * 	buf  = Existing character buffer
 * 	size = Buffer size
 * 	bufi = Buffer index
 * 	f = String format, respects printf format
 * 	... = Additional objects to be formatted
 * Returns: Updated buffer index
 */
size_t adbg_util_straddf(char *buf, size_t size, size_t bufi, const(char) *f, ...) {
	va_list va = void;
	va_start(va, f);
	return adbg_util_straddva(buf, size, bufi, f, va);
}

/**
 * Append va_list to buffer. Uses an internal 128-character buffer for vsnprintf.
 * Params:
 * 	buf  = Existing character buffer
 * 	size = Buffer size
 * 	bufi = Buffer index
 * 	f = String format, respects printf format
 * 	va = Argument list
 * Returns: Updated buffer index
 */
size_t adbg_util_straddva(char *buf, size_t size, size_t bufi, const(char) *f, va_list va) {
	char [128]b = void;
	vsnprintf(cast(char*)b, 128, f, va);
	return adbg_util_stradd(buf, size, bufi, cast(char*)b);
}

/**
 * Lower case string buffer ('A' to 'Z' only).
 * Params:
 * 	buf  = String buffer
 * 	size = Buffer size
 */
void adbg_util_strlcase(char *buf, size_t size) {
	for (size_t i; buf[i] && i < size; ++i) {
		if (buf[i] >= 0x41 && buf[i] <= 0x5A)
			buf[i] += 32;
	}
}

/// Quick Format stack size (characters)
private enum STR_QUICK_STACK_SIZE = 128;
/// Quick Format stacks count
private enum STR_QUICK_STACKS_COUNT = 16;
/// Quick Format stack limit (count - 1) for index comparason
private enum STR_QUICK_STACKS_LIMIT = STR_QUICK_STACKS_COUNT - 1;

/**
 * Quick format.
 *
 * Quick and very dirty string formatting utility. This serves the purposes to
 * avoid allocating new buffers before appending to (other) existing buffers.
 * Cycles through 16 128-byte internal static buffers (2048 bytes).
 *
 * Params:
 * 	f = Format string
 * 	... = Arguments
 *
 * Returns: String
 */
const(char) *adbg_util_strf(const(char) *f, ...) {
	va_list va = void;
	va_start(va, f);
	return adbg_util_strfva(f, va);
}
/**
 * Quick format.
 *
 * Quick and very dirty string formatting utility. This serves as pushing an
 * existing list to an internal buffer.
 *
 * Params:
 * 	f = Format string
 * 	va = va_list
 *
 * Returns: String
 */
const(char) *adbg_util_strfva(const(char) *f, va_list va) {
	__gshared size_t strfc; /// buffer selection index
	__gshared char [STR_QUICK_STACK_SIZE][STR_QUICK_STACKS_COUNT]b = void;

	char *sb = cast(char*)b[strfc];
	vsnprintf(sb, STR_QUICK_STACK_SIZE, f, va);
	if (++strfc >= STR_QUICK_STACKS_LIMIT) strfc = 0;

	return sb;
}