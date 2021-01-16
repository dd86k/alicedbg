/**
 * String helper functions. Simple string functions to aid redundant typing.
 *
 * License: BSD 3-clause
 */
module adbg.utils.str;

import core.stdc.stdio;
import core.stdc.stdarg;
import core.stdc.string;

extern (C):
__gshared:

size_t adbg_util_argv_flatten(char *b, int bs, const(char) **argv) {
	import core.stdc.stdio : snprintf;
	if (argv == null)
		return 0;

	ptrdiff_t ai, bi, t;
	while (argv[ai]) {
		t = snprintf(b + bi, bs, "%s ", argv[ai]);
		if (t < 0)
			return 0;
		bi += t;
		++ai;
	}

	return bi;
}

int adbg_util_argv_expand(char *buf, size_t buflen, char **argv) {
	import core.stdc.ctype : isalnum, ispunct;
	
	size_t index;
	int argc;
	
	if (buflen == 0) return 0;
	
L_WORD:
	// move pointer to first non-white character
	A: while (index < buflen) {
		const char c = buf[index];
		switch (c) {
		case 0, '\n', '\r': return argc;
		case ' ', '\t':
			++index;
			continue;
		default: break A;
		}
	}
	
	argv[argc] = buf + index;
	
	// get how long the parameter length is
	while (index < buflen) {
		const char c = buf[index];
		
		switch (c) {
		case 0, '\n', '\r':
			buf[index] = 0;
			return ++argc;
		default:
			if (isalnum(c) || ispunct(c)) {
				++index;
				continue;
			}
		}
		
		++argc;
		buf[index++] = 0;
		goto L_WORD;
	}
	
	// reached the end before we knew it
	return argc;
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
enum STR_QUICK_STACK_SIZE = 128;
/// Quick Format stacks count
enum STR_QUICK_STACKS_COUNT = 16;
/// Quick Format stack limit (count - 1) for index comparason
enum STR_QUICK_STACKS_LIMIT = STR_QUICK_STACKS_COUNT - 1;

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