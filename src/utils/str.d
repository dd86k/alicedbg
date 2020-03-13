/**
 * String helper functions. Simple string functions to aid redundant typing.
 *
 * License: BSD 3-Clause
 */
module utils.str;

private import core.stdc.stdio;
private import core.stdc.stdarg;

extern (C):

/// Hexadecimal map for strx0* functions to provide much faster %X parsing
private __gshared char [16]hexmaplow = "0123456789abcdef";
/// Hexadecimal map for strx0* functions to provide much faster %X parsing
private __gshared char [16]hexmapupp = "0123456789ABCDEF";

/**
 * Quick and dirty conversion function to convert an ubyte value to a
 * '0'-padded hexadecimal string. Faster than using vsnprintf.
 * Params:
 * 	v = 8-bit value
 * 	upper = Use upper hexadecimal character
 * Returns: Null-terminated hexadecimal string
 */
const(char) *strx02(ubyte v, bool upper = false) {
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
const(char) *strx04(ushort v, bool upper = false) {
	__gshared char [5]b = void;

	const(char) *h = cast(char*)(upper ? hexmapupp : hexmaplow);

	b[3] = h[v & 0xF];
	b[2] = h[(v >>= 4) & 0xF];
	b[1] = h[(v >>= 4) & 0xF];
	b[0] = h[(v >>= 4) & 0xF];
	b[4] = 0;

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
const(char) *strx08(uint v, bool upper = false) {
	__gshared char [9]b = void;

	const(char) *h = cast(char*)(upper ? hexmapupp : hexmaplow);

	b[7] = h[v & 0xF];
	b[6] = h[(v >>= 4) & 0xF];
	b[5] = h[(v >>= 4) & 0xF];
	b[4] = h[(v >>= 4) & 0xF];
	b[3] = h[(v >>= 4) & 0xF];
	b[2] = h[(v >>= 4) & 0xF];
	b[1] = h[(v >>= 4) & 0xF];
	b[0] = h[(v >>= 4) & 0xF];
	b[8] = 0;

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
const(char) *strx016(ulong v, bool upper = false) {
	__gshared char [17]b = void;

	const(char) *h = cast(char*)(upper ? hexmapupp : hexmaplow);

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
	b[16] = 0;

	return cast(char*)b;
}

/**
 * Append a constant string to an existing buffer.
 * Params:
 * 	buf  = Existing character buffer
 * 	size = Buffer size
 * 	bufi = Buffer index
 * 	str  = String data
 * Returns: Updated buffer index
 */
size_t stradd(char *buf, size_t size, size_t bufi, const(char) *str) {
	size_t stri;
	while (str[stri] && bufi < size) {
		buf[bufi] = str[stri];
		++stri; ++bufi;
	}
	return bufi;
}

/**
 * Append a formatted string to an existing buffer, calls straddva and stradd.
 * Params:
 * 	buf  = Existing character buffer
 * 	size = Buffer size
 * 	bufi = Buffer index
 * 	f = String format, respects printf format
 * 	... = Additional objects to be formatted
 * Returns: Updated buffer index
 */
size_t straddf(char *buf, size_t size, size_t bufi, const(char) *f, ...) {
	va_list va;
	va_start(va, f);
	return straddva(buf, size, bufi, f, va);
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
size_t straddva(char *buf, size_t size, size_t bufi, const(char) *f, ref va_list va) {
	char [128]b = void;
	vsnprintf(cast(char*)b, 128, f, va);
	return stradd(buf, size, bufi, cast(char*)b);
}

/**
 * Lower case string buffer ('A' to 'Z' only).
 * Params:
 * 	buf  = String buffer
 * 	size = Buffer size
 */
void strlcase(char *buf, size_t size) {
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
const(char) *strf(const(char) *f, ...) {
	va_list va;
	va_start(va, f);
	return strfva(f, va);
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
const(char) *strfva(const(char) *f, va_list va) {
	__gshared size_t strfc; /// buffer selection index
	__gshared char [STR_QUICK_STACK_SIZE][STR_QUICK_STACKS_COUNT]b = void;

	char *sb = cast(char*)b[strfc];
	vsnprintf(sb, STR_QUICK_STACK_SIZE, f, va);
	if (++strfc >= STR_QUICK_STACKS_LIMIT) strfc = 0;

	return sb;
}