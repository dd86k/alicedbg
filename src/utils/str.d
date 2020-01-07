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