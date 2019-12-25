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
 * 	a = Existing character buffer
 * 	b = String constant to add
 * 	ia = Buffer index
 * 	s = Buffer size
 * Returns: New buffer index
 */
size_t stradd(char *a, const(char) *b, size_t ia, size_t s) {
	size_t ib;
	while (b[ib] && ia < s) {
		a[ia] = b[ib];
		++ib; ++ia;
	}
	return ia;
}

/**
 * Append a formatted string to an existing buffer, calls vsnprintf and then
 * stradd.
 * Params:
 * 	a = Existing character buffer
 * 	ia = Buffer index
 * 	s = Buffer size
 * 	f = String format, respects printf format
 * 	... = Additional objects to be formatted
 * Returns: New buffer index
 */
size_t straddf(char *a, size_t ia, size_t s, const(char) *f, ...) {
	char [128]b = void;
	va_list va;
	va_start(va, f);
	vsnprintf(cast(char*)b, 128, f, va);
	return stradd(a, cast(char*)b, ia, s);
}