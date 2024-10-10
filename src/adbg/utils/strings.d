/// String helper functions. Simple string functions to aid redundant typing.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.utils.strings;

import adbg.include.c.stdio;
import core.stdc.stdarg;
import core.stdc.string;
import core.stdc.ctype;

// TODO: adbg_str_readline: version without copying line to buffer, but modifies it
// TODO: adbg_path_basename: Get filename from path.
// TODO: adbg_path_basenamen: Get filename from path buffer with length.

extern (C):

/// Get the length of a narrow null-terminated string with a given maximum length.
/// Params:
/// 	s = String pointer.
/// 	max = Maximum length.
/// Returns: Size.
size_t adbg_nstrlen(const(char) *s, size_t max) {
	size_t l;
	while (s[l] && l < max) ++l;
	return l;
}
extern (D) unittest {
	assert(adbg_nstrlen("", 10) == 0);
	assert(adbg_nstrlen("", 0) == 0);
	assert(adbg_nstrlen("hello", 0) == 0);
	assert(adbg_nstrlen("hello", 10) == 5);
}

/// Get the length of a wide null-terminated string with a given maximum length.
/// Params:
/// 	s = String pointer.
/// 	max = Maximum length.
/// Returns: Size.
size_t adbg_nstrlenw(const(wchar) *s, size_t max) {
	size_t l;
	while (s[l] && l < max) ++l;
	return l;
}
extern (D) unittest {
	assert(adbg_nstrlenw(""w.ptr, 10) == 0);
	assert(adbg_nstrlenw(""w.ptr, 0) == 0);
	assert(adbg_nstrlenw("hello"w.ptr, 0) == 0);
	assert(adbg_nstrlenw("hello"w.ptr, 10) == 5);
}

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
		
		if (isprint(c) || c == '\t')
			bf[i] = cast(char)c;
	}
	
	bf[i] = 0;
	*lnsz = i;
	return i;
}
extern (D) unittest {
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
		
		if (isprint(c) || c == '\t')
			bf[i] = cast(char)c;
	}
	
	bf[i] = 0;
	*srcidx = s;
	*lnsz = i;
	return i;
}
extern (D) unittest {
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

/// Flatten a multi-vector string into a singular buffer. Like an Array.join() function.
/// Params:
/// 	buf = Destination buffer.
/// 	buflen = Destination buffer size.
/// 	argc = Number of input arguments.
/// 	argv = Argument vector.
/// 	spaces = Number of spaces in-between items.
/// Returns: Number of characters written, excluding null.
int adbg_strings_flatten(char *buf, int buflen, int argc, const(char) **argv, int spaces) {
	if (argv == null)
		return 0;

	int bufidx;
	for (int i; i < argc; ++i) {
		const(char) *arg = argv[i];
		int len = cast(int)strlen(arg);
		
		// Copy rest
		if (bufidx + len >= buflen) {
			size_t rem = buflen - bufidx;
			if (rem == 0) return bufidx;
			
			memcpy(buf + bufidx, arg, rem);
			bufidx += rem - 1;
			buf[bufidx] = 0;
			return bufidx;
		}
		
		// Copy buffer
		memcpy(buf + bufidx, arg, len);
		bufidx += len;
		
		if (i + 1 >= argc) continue;
		if (bufidx + spaces >= buflen)
			spaces = buflen - bufidx;
		
		memset(buf + bufidx, ' ', spaces);
		bufidx += spaces;
	}

	buf[bufidx] = 0;
	return bufidx;
}
extern (D) unittest {
	static int argc = 3;
	static const(char)** argv = ["one", "two", "three"];
	
	// Buffer OK
	enum B1LEN = 128;
	char[B1LEN] b1 = void;
	int r1 = adbg_strings_flatten(b1.ptr, B1LEN, argc, argv, 1);
	assert(r1 == 13); // Chars written
	assert(b1[0..r1] == "one two three"); // Chars written
	
	// Buffer too small
	enum B2LEN = 10;
	char[B2LEN] b2 = void;
	int r2 = adbg_strings_flatten(b2.ptr, B2LEN, argc, argv, 1);
	assert(r2 == B2LEN - 1); // Chars written, excluding null
	assert(b2[0..r2] == "one two t"); // Chars written
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
extern (D) unittest {
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
