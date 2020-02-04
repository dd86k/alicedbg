/**
 * String helper functions. Simple string functions to aid redundant typing.
 */
module utils.str;

private import core.stdc.stdio;
private import core.stdc.stdarg;

extern (C):

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

private __gshared size_t strfc = 0;
/**
 * Quick format.
 *
 * Quick and very dirty string formatting utility. This serves the purposes to
 * avoid allocating new buffers before appending to (other) existing buffers.
 * Cycles through 16 128-byte internal static buffers (2048 bytes).
 *
 * Params: f = Format string
 *
 * Returns: String
 */
const(char) *strf(const(char) *f, ...) {
	__gshared char [128][16]b = void;

	char *sb = cast(char*)b[strfc];

	va_list va;
	va_start(va, f);
	vsnprintf(sb, 128, f, va);

	if (++strfc > 15) strfc = 0;

	return sb;
}