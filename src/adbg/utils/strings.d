/// String helper functions. Simple string functions to aid redundant typing.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.utils.strings;

import adbg.include.c.stdio;
import core.stdc.stdarg;
import core.stdc.string;

extern (C):

/// An empty string in case compilers does not support pool strings.
__gshared char *empty_string = cast(char*)"";

/// Gets the next line out of a file stream.
/// This skips empty lines.
/// The extracted line is null-terminated.
/// Params:
///   bf = Line buffer input.
///   bfsz = Line buffer input size.
///   lnsz = Line length reference.
///   file = File handle.
/// Returns: Line length.
size_t adbg_util_getlinef(char *bf, size_t bfsz, size_t *lnsz, FILE *file) {
	if (bf == null || bfsz == 0 || lnsz == null || file == null)
		return 0;
	
	import core.stdc.ctype : isprint;
	
	size_t i; /// Line buffer index
	
	// If fgetc return EOF, it is non-printable
	for ( ; i < bfsz ; ++i) {
		int c = fgetc(file);
		
		//TODO: Include tab as accepted character
		if (isprint(c) == false)
			break;
		
		bf[i] = cast(char)c;
	}
	
	bf[i] = 0;
	*lnsz = i;
	return i;
}

unittest {
	import std.stdio : writefln;
	import std.file : write, tempDir, remove;
	import std.path : buildPath;
	import std.string : toStringz;
	
	string tmppath = buildPath(tempDir, "alicedbg_unittest");
	write(tmppath, "123\n\nabc");
	FILE *fd = fopen(tmppath.toStringz, "r");
	
	char[16] line = void;
	size_t linesz = void;
	size_t i;
	while (adbg_util_getlinef(line.ptr, 16, &linesz, fd)) {
		final switch (++i) {
		case 1: assert(strncmp(line.ptr, "123", linesz) == 0); break;
		case 2: assert(strncmp(line.ptr, "abc", linesz) == 0); break;
		}
	}
	
	fclose(fd);
	remove(tmppath);
}

/// Gets the next line out of a file stream.
/// This skips empty lines.
/// The extracted line is null-terminated.
/// Params:
///   bf = Line buffer input.
///   bfsz = Line buffer input size.
///   lnsz = Line length reference.
///   src = Null-terminated buffer source.
///   srcidx = Index reminder. It's best advised you don't touch this variable between calls.
/// Returns: Line length.
size_t adbg_util_getline(char *bf, size_t bfsz, size_t *lnsz, const(char) *src, size_t *srcidx) {
	if (bf == null || bfsz == 0 || lnsz == null || src == null || srcidx == null)
		return 0;
	
	import core.stdc.ctype : isprint;
	
	size_t i; /// Line buffer index
	size_t s = *srcidx; /// Source buffer index
	
	// checking 0 in for-loop is important because somehow isprint might let it pass?
	for (; src[s] && i < bfsz; ++i) {
		int c = src[s++]; // unconditionally prep next pos
		
		//TODO: Include tab as accepted character
		if (isprint(c) == false)
			break;
		
		bf[i] = cast(char)c;
	}
	
	bf[i] = 0;
	*srcidx = s;
	*lnsz = i;
	return i;
}

unittest {
	const(char) *src = "123\n\nabc";
	char[16] line = void;
	size_t linesz = void;
	size_t idx;
	size_t i;
	while (adbg_util_getline(line.ptr, 16, &linesz, src, &idx)) {
		final switch (++i) {
		case 1: assert(line[0..linesz] == "123"); break;
		case 2: assert(line[0..linesz] == "abc"); break;
		}
	}
}

//TODO: adbg_util_getline2: version without copying line to buffer, but modifies it

/// Convert a hex string into a byte array.
/// Params:
/// 	dst = Destination buffer.
/// 	sz = Destination buffer capacity in bytes.
/// 	src = Source string buffer.
/// 	newsz = New destination size in bytes.
/// Returns: Error code if non-zero.
int adbg_util_hex_array(ubyte *dst, size_t sz, const(char) *src, ref size_t newsz) {
	bool upper = true;
	ubyte b = void, bh = void;
	size_t di, si;
	for (; di < sz; ++si) {
		char c = src[si];
		if (c == 0) break;
		
		if (c >= '0' && c <= '9') {
			b = cast(ubyte)(c - '0');
		} else if (c >= 'a' && c <= 'f') {
			b = cast(ubyte)(c - 87);
		} else if (c >= 'A' && c <= 'F') {
			b = cast(ubyte)(c - 55);
		} else continue;
		
		if (upper) {
			bh = cast(ubyte)(b << 4);
		} else {
			b |= bh;
			dst[di++] = b;
		}
		upper = !upper;
	}
	newsz = di;
	return di >= sz;
}

/// adbg_util_hex_array
@system unittest {
	ubyte[8] buf = void;
	size_t sz = void;
	assert(adbg_util_hex_array(buf.ptr, 8, "12AAcc", sz) == 0);
	assert(sz == 3);
	assert(buf[0] == 0x12);
	assert(buf[1] == 0xaa);
	assert(buf[2] == 0xcc);
}

size_t adbg_util_argv_flatten(char *buf, int buflen, const(char) **argv) {
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

// NOTE: Kind would have preferred returning as int (argc)...
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

unittest {
	struct Test {
		string input;
		const(char)*[] output;
	}
	immutable Test[] tests = [
		{ null, [] },
		{ "", [] },
		{ "test", [ "test" ] },
		{ "command test", [ "command", "test" ] },
		{ "readline\n", [ "readline" ] },
		{ "readline param\n", [ "readline", "param" ] },
		{ "decent day, isn't it?", [ "decent", "day,", "isn't", "it?" ] },
		{ "1 2 3 4 5 6 7 8 9", [ "1", "2", "3", "4", "5", "6", "7", "8", "9" ] },
		{ "abc\ndef", [ "abc", "def" ] },
	];
	
	foreach (test; tests) {
		int argc = void;
		char** argv = adbg_util_expand(test.input.ptr, &argc);
		
		// Part of user code
		if (argv == null) continue;
		
		for (uint i; i < argc; ++i) {
			assert(strcmp(argv[i], cast(char*)test.output[i]) == 0, test.input);
		}
	}
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
private immutable char [16]hexMapLower = "0123456789abcdef";
/// Hexadecimal map for strx0* functions to provide much faster %X parsing
private immutable char [16]hexMapUpper = "0123456789ABCDEF";

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

	const(char) *h = cast(char*)(upper ? hexMapUpper : hexMapLower);

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

	const(char) *h = cast(char*)(upper ? hexMapUpper : hexMapLower);

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

	const(char) *h = cast(char*)(upper ? hexMapUpper : hexMapLower);

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

	const(char) *h = cast(char*)(upper ? hexMapUpper : hexMapLower);

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

/// Internal structure used to append an existing buffer new typed elements.
/// 
/// Should look more like MFC's CString.
// NOTE: Was used for disassembler v1 but that's getting removed soon.
//TODO: Consider adbg_string_t.add_s for +length
//      Why? This has literally no use
//TODO: Consider adbg_string_t.addm(T...)(T args)
//      Test in godbolt first
//      char -> addc
//      const(char)* -> adds
//      ubyte -> addx8
//      etc
//TODO: Add decimal
//      addu8/addu16/addu32/addu64(T v, bool signed)
//TODO: Consider having settings instead of arguments
//      bool pad    = false;
//      bool signed = false;
//TODO: bool positive parameter
//      Adds '+' if >=0
struct adbg_string_t {
	char  *str;	/// String pointer
	size_t size;	/// Buffer capacity
	size_t length;	/// Position, count
	
	/// Inits a string position tracker with a buffer and its size.
	/// This does not create a string.
	/// Params:
	/// 	buffer = Buffer pointer.
	/// 	buffersz = Buffer capacity.
	this(char *buffer, size_t buffersz) {
		str  = buffer;
		size = buffersz;
		length  = 0;
	}
	/// Reset counters and optionally zero-fill the buffer.
	/// Params: zero = If true, fills the buffer of zeros.
	void reset(bool zero = false) {
		str[0] = 0;
		if (zero)
			for (size_t p = 1; p < size; ++p)
				str[p] = 0;
		length = 0;
	}
	/// Add character to buffer.
	/// Params: c = Character
	/// Returns: True if buffer exhausted.
	bool addc(char c) {
		if (length >= size)
			return true;
		char *s = str + length++;
		*s = c;
		*(s + 1) = 0;
		return false;
	}
	/// Add a constant string to buffer.
	/// Params: s = String
	/// Returns: True if buffer exhausted.
	bool adds(const(char) *s) {
		size_t sz = size - 1;
		if (s == null)
			goto L_RET;
		for (size_t si; length < sz && s[si]; ++length, ++si)
			str[length] = s[si];
		str[length] = 0;
	L_RET:
		return length >= sz;
	}
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
		length += vsnprintf(str + length, size - length, fmt,va);
		return length >= size;
	}
	/// Add a hexadecimal byte to buffer.
	/// Params:
	/// 	v = ubyte value.
	/// 	pad = If set, pads with zero.
	/// Returns: True if buffer exhausted.
	bool addx8(ubyte v, bool pad = false) {
		if (length + 4 >= size) return true;
		ubyte vh = v >> 4;
		ubyte vl = v & 15;
		if (vh || pad) str[length++] = hexMapLower[vh];
		str[length++] = hexMapLower[vl];
		str[length] = 0;
		return length >= size;
	}
	/// Add a hexadecimal 16-bit value to buffer.
	/// Params:
	/// 	v = ushort value.
	/// 	pad = If set, pads with zero.
	/// Returns: True if buffer exhausted.
	bool addx16(ushort v, bool pad = false) {
		for (int shift = 12; length < size && shift >= 0; shift -= 4) {
			ushort h = (v >> shift) & 15;
			if (h == 0 && pad == false && shift > 0) continue;
			str[length++] = hexMapLower[h];
			if (h) pad = true;
		}
		str[length] = 0;
		return length >= size;
	}
	/// Add a hexadecimal 32-bit value to buffer.
	/// Params:
	/// 	v = uint value.
	/// 	pad = If set, pads with zero.
	/// Returns: True if buffer exhausted.
	bool addx32(uint v, bool pad = false) {
		for (int shift = 28; length < size && shift >= 0; shift -= 4) {
			uint h = (v >> shift) & 15;
			if (h == 0 && pad == false && shift > 0) continue;
			str[length++] = hexMapLower[h];
			if (h) pad = true;
		}
		str[length] = 0;
		return length >= size;
	}
	/// Add a hexadecimal 64-bit value to buffer.
	/// Params:
	/// 	v = ulong value.
	/// 	pad = If set, pads with zero.
	/// Returns: True if buffer exhausted.
	bool addx64(ulong v, bool pad = false) {
		for (int shift = 60; length < size && shift >= 0; shift -= 4) {
			ulong h = (v >> shift) & 15;
			if (h == 0 && pad == false && shift > 0) continue;
			version (D_LP64)
				str[length++] = hexMapLower[h];
			else // for 32-bit systems
				str[length++] = hexMapLower[cast(uint)h];
			if (h) pad = true;
		}
		str[length] = 0;
		return length >= size;
	}
}

unittest {
	import adbg.utils.strings : adbg_string_t;
	
	enum BUFFER_SIZE = 80;
	enum LAST_ITEM = BUFFER_SIZE - 1;
	
	char[BUFFER_SIZE] buffer = void;
	
	// init
	
	adbg_string_t s = adbg_string_t(buffer.ptr, BUFFER_SIZE);
	assert(s.size == BUFFER_SIZE);
	assert(s.length  == 0);
	assert(s.str  == &buffer[0]);
	
	// reset
	
	s.length = 3;
	s.reset(true);
	assert(buffer[0] == 0);
	assert(buffer[1] == 0);
	assert(buffer[LAST_ITEM] == 0);
	assert(s.length == 0);
	
	// add(char)
	
	s.reset();
	assert(s.addc('a') == false);
	assert(buffer[0] == 'a');
	assert(buffer[1] == 0);
	
	s.reset();
	assert(s.addc('a') == false);
	assert(s.addc('b') == false);
	assert(s.addc('c') == false);
	assert(strcmp(s.str, "abc") == 0);
	
	// add(string)
	
	s.reset();
	assert(s.adds("hello") == false);
	assert(buffer[0] == 'h');
	assert(buffer[1] == 'e');
	assert(buffer[2] == 'l');
	assert(buffer[3] == 'l');
	assert(buffer[4] == 'o');
	assert(buffer[5] == 0);
	assert(buffer[6] == 0);
	assert(buffer[7] == 0);
	assert(buffer[8] == 0);
	
	s.reset();
	immutable string lorem =
		`Lorem ipsum dolor sit amet, consectetur adipiscing elit. `~
		`Etiam dignissim iaculis lectus. Aliquam volutpat rhoncus dignissim. `~
		`Donec maximus diam eros, a euismod quam consectetur sit amet. `~
		`Morbi vel ante viverra, condimentum elit porttitor, tempus metus. `~
		`Cras eget interdum turpis, vitae egestas ipsum. `~
		`Nam accumsan aliquam enim, id sodales tellus hendrerit id. `~
		`Proin vulputate hendrerit accumsan. Etiam vitae tempor libero.`;
	assert(lorem.length > s.size);
	assert(s.adds(lorem.ptr));
	assert(buffer[0] == 'L');
	
	s.reset(true);
	s.adds("123");
	s.adds("abc");
	assert(strcmp(s.str, "123abc") == 0);
	
	// addx8
	
	s.reset();
	assert(s.addx8(0xe0) == false);
	assert(buffer[0] == 'e');
	assert(buffer[1] == '0');
	assert(buffer[2] == 0);
	
	s.reset();
	assert(s.addx8(0) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == 0);
	
	s.reset();
	assert(s.addx8(0, true) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == '0');
	assert(buffer[2] == 0);
	
	s.reset();
	assert(s.addx8(0xe) == false);
	assert(buffer[0]  == 'e');
	assert(buffer[1] == 0);
	
	s.reset();
	assert(s.addx8(0xe, true) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == 'e');
	assert(buffer[2] == 0);
	
	s.reset();
	assert(s.addx8(0x80) == false);
	assert(s.addx8(0x86) == false);
	assert(buffer[0] == '8');
	assert(buffer[1] == '0');
	assert(buffer[2] == '8');
	assert(buffer[3] == '6');
	assert(buffer[4] == 0);
	
	// addx16
	
	s.reset();
	assert(s.addx16(0xabcd) == false);
	assert(buffer[0] == 'a');
	assert(buffer[1] == 'b');
	assert(buffer[2] == 'c');
	assert(buffer[3] == 'd');
	assert(buffer[4] == 0);
	
	s.reset();
	assert(s.addx16(0xff) == false);
	assert(buffer[0] == 'f');
	assert(buffer[1] == 'f');
	assert(buffer[2] == 0);
	
	s.reset();
	assert(s.addx16(0xee, true) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == '0');
	assert(buffer[2] == 'e');
	assert(buffer[3] == 'e');
	assert(buffer[4] == 0);
	
	s.reset();
	assert(s.addx16(0) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == 0);
	
	s.reset();
	assert(s.addx16(0, true) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == '0');
	assert(buffer[2] == '0');
	assert(buffer[3] == '0');
	assert(buffer[4] == 0);
	
	s.reset();
	assert(s.addx16(0x8086) == false);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '8');
	assert(buffer[3]  == '6');
	assert(buffer[4] == 0);
	
	s.reset();
	assert(s.addx16(0x80) == false);
	assert(s.addx16(0x86) == false);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '8');
	assert(buffer[3]  == '6');
	assert(buffer[4] == 0);
	
	// addx32
	
	s.reset();
	assert(s.addx32(0x1234_abcd) == false);
	assert(buffer[0]  == '1');
	assert(buffer[1]  == '2');
	assert(buffer[2]  == '3');
	assert(buffer[3]  == '4');
	assert(buffer[4]  == 'a');
	assert(buffer[5]  == 'b');
	assert(buffer[6]  == 'c');
	assert(buffer[7]  == 'd');
	assert(buffer[8] == 0);
	
	s.reset();
	assert(s.addx32(0xed) == false);
	assert(buffer[0]  == 'e');
	assert(buffer[1]  == 'd');
	assert(buffer[2] == 0);
	
	s.reset();
	assert(s.addx32(0xcc, true) == false);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '0');
	assert(buffer[3]  == '0');
	assert(buffer[4]  == '0');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == 'c');
	assert(buffer[7]  == 'c');
	assert(buffer[8] == 0);
	
	s.reset();
	assert(s.addx32(0) == false);
	assert(buffer[0]  == '0');
	assert(buffer[1] == 0);
	
	s.reset();
	assert(s.addx32(0, true) == false);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '0');
	assert(buffer[3]  == '0');
	assert(buffer[4]  == '0');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == '0');
	assert(buffer[7]  == '0');
	assert(buffer[8] == 0);
	
	s.reset();
	assert(s.addx32(0x80486) == false);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '4');
	assert(buffer[3]  == '8');
	assert(buffer[4]  == '6');
	assert(buffer[5] == 0);
	
	// addx64
	
	s.reset();
	assert(s.addx64(0xdd86_c0ff_ee08_0486) == false);
	assert(buffer[0]  == 'd');
	assert(buffer[1]  == 'd');
	assert(buffer[2]  == '8');
	assert(buffer[3]  == '6');
	assert(buffer[4]  == 'c');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == 'f');
	assert(buffer[7]  == 'f');
	assert(buffer[8]  == 'e');
	assert(buffer[9]  == 'e');
	assert(buffer[10] == '0');
	assert(buffer[11] == '8');
	assert(buffer[12] == '0');
	assert(buffer[13] == '4');
	assert(buffer[14] == '8');
	assert(buffer[15] == '6');
	assert(buffer[16] == 0);
	
	s.reset();
	assert(s.addx64(0xbb) == false);
	assert(buffer[0]  == 'b');
	assert(buffer[1]  == 'b');
	assert(buffer[2]  == 0);
	
	s.reset();
	assert(s.addx64(0xdd, true) == false);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '0');
	assert(buffer[3]  == '0');
	assert(buffer[4]  == '0');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == '0');
	assert(buffer[7]  == '0');
	assert(buffer[8]  == '0');
	assert(buffer[9]  == '0');
	assert(buffer[10] == '0');
	assert(buffer[11] == '0');
	assert(buffer[12] == '0');
	assert(buffer[13] == '0');
	assert(buffer[14] == 'd');
	assert(buffer[15] == 'd');
	assert(buffer[16] == 0);
	
	s.reset();
	assert(s.addx64(0) == false);
	assert(buffer[0]  == '0');
	assert(buffer[1] == 0);
	
	s.reset();
	assert(s.addx64(0, true) == false);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '0');
	assert(buffer[3]  == '0');
	assert(buffer[4]  == '0');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == '0');
	assert(buffer[7]  == '0');
	assert(buffer[8]  == '0');
	assert(buffer[9]  == '0');
	assert(buffer[10] == '0');
	assert(buffer[11] == '0');
	assert(buffer[12] == '0');
	assert(buffer[13] == '0');
	assert(buffer[14] == '0');
	assert(buffer[15] == '0');
	assert(buffer[16] == 0);
	
	s.reset();
	assert(s.addx64(0x80960) == false);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '9');
	assert(buffer[3]  == '6');
	assert(buffer[4]  == '0');
	assert(buffer[5] == 0);
}
