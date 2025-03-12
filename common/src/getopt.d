/// Provides an interface to interpreting command-line options.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module getopt;

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;

private enum : ubyte {
	ARG_NONE,
	ARG_STRING,
	//ARG_NUMBER, // %i
	//ARG_LARGENUMBER, // %lli
}

/// Represents one command-line option switch
struct option_t { align(1):
	/// Make an option without arguments
	this (char oshort, string olong, string desc, int function() ufunc) {
		shortname = oshort;
		longname = olong;
		description = desc;
		argtype = ARG_NONE;
		f = ufunc;
	}
	/// Make an option with string argument
	this (char oshort, string olong, string desc, int function(const(char)*) ufunc) {
		shortname = oshort;
		longname = olong;
		description = desc;
		argtype = ARG_STRING;
		fa = ufunc;
	}
	string longname;	/// Long switch name
	string description;	/// Option description
	char shortname;	/// Short switch name
	ubyte argtype;	/// Argument type
	union {
		int function() f; /// User callback
		int function(const(char)*) fa; /// Ditto
	}
}

private
immutable(option_t)* getoptlong(const(char)* arg, immutable(option_t)[] options) {
	foreach (ref o; options) {
		if (strncmp(arg, o.longname.ptr, o.longname.length) == 0)
			return &o;
	}
	return null;
}
private
immutable(option_t)* getoptshort(char arg, immutable(option_t)[] options) {
	foreach (ref o; options) {
		if (arg == o.shortname)
			return &o;
	}
	return null;
}
private
int getoptexec(immutable(option_t)* option, const(char)* value) {
	final switch (option.argtype) {
	case ARG_NONE:
		return option.f();
	case ARG_STRING: // with argument
		if (value == null)
			return getoptEmissingLong(option.longname.ptr);
		return option.fa(value);
	}
}

// Returns the position of the first occurence of the specified character,
// or -1 if not found.
private
ptrdiff_t strsrch(const(char) *hay, int needle) {
	for (ptrdiff_t i; hay[i]; ++i)
		if (hay[i] == needle)
			return i;
	return -1;
}
extern (D) unittest {
	assert(strsrch("hello", 'q')  < 0); // not found
	assert(strsrch("hello", 'h') == 0);
	assert(strsrch("hello", 'e') == 1);
	assert(strsrch("hello", 'l') == 2);
	assert(strsrch("hello", 'o') == 4);
}

/// Interpret options
/// Process options.
/// Params:
/// 	argc = Argument count.
/// 	argv = Argument vector.
/// 	options = Option list.
/// Returns: If negative: Error. Otherwise, number of arguments left.
int getoptions(int argc, const(char) **argv, immutable(option_t)[] options) {
	// On re-entry, clear extras and error buffers
	getoptreset();
	
	int i = 1;
	for (; i < argc; ++i) {
		const(char) *arg = argv[i]; // Current argument
		
		const(char) *value;
		immutable(option_t) *option = void;
		if (arg[1] == '-') { // "--" -> Long option
			const(char) *argLong = arg + 2; // start after "--"
			
			// Test for "--" (do not process options anymore)
			if (argLong[0] == 0)
				goto Lstop;
			
			// Get value in advance, if possible
			ptrdiff_t optpos = strsrch(argLong, '=');
			if (optpos == 0) // "--=example" is invalid
				return getoptEmalformatted(argLong);
			else if (optpos > 0) // "--e=a" means "e" is switch and "a" is value
				value = argLong + 1 + optpos; // skip '=' char
			
			// Get corresponding option
			option = getoptlong(argLong, options);
		} else if (arg[0] == '-') { // "-" Short option
			char argShort = arg[1];
			
			// Test for "-" (often for a stdin option)
			if (argShort == 0) {
				getoptaddextra(argc, arg);
				continue;
			}
			
			// Get corresponding option
			option = getoptshort(argShort, options);
			
			// Option wants an argument
			if (option && option.argtype) {
				if (++i >= argc)
					return getoptEmissingLong(option.longname.ptr);
				value = argv[i];
			}
		} else { // Not a switch, add to "extras" list
			getoptaddextra(argc, arg);
			continue;
		}
		
		// Option was not found
		if (option == null)
			return getoptEunknown(arg);
		
		// Execute option handler
		if (getoptexec(option, value))
			return getoptEfailed(arg, value);
	}
	
	return getoptleftcount();
	
Lstop:	// When '--' is given, add the rest of arguments as "extras"
	for (++i; i < argc; ++i)
		getoptaddextra(argc, argv[i]);
	return getoptleftcount();
}
extern (D) unittest {
	__gshared int hit;
	static int opttest() {
		++hit;
		return 0;
	}
	static immutable(option_t)[] options = [
		option_t('t', "test", "testing switch", &opttest),
	];
	static const(char) **argv = [
		"program", "argument", "--test", "--", "--test"
	];
	static int argc = 5;
	
	int e = getoptions(argc, argv, options);
	assert(e == 2);   // Two leftover argument
	assert(hit == 1); // --test switch hit once
	
	const(char) **leftovers = getoptleftovers();
	assert(leftovers);
	assert(strcmp(*leftovers, "argument") == 0);
	assert(strcmp(*(leftovers + 1), "--test") == 0);
}
extern (D) unittest {
	__gshared int hit;
	static int opttest() {
		++hit;
		return 0;
	}
	static immutable(option_t)[] options = [
		option_t('t', "test", "testing switch", &opttest),
	];
	static const(char) **argv = [
		"alicedbg", "--", "alicedbg.exe", "--version"
	];
	static int argc = 4;
	
	int e = getoptions(argc, argv, options);
	assert(e == 2);   // Two leftover argument
	assert(hit == 0); // --test switch never hit
	
	const(char) **leftovers = getoptleftovers();
	assert(leftovers);
	assert(strcmp(*leftovers, "alicedbg.exe") == 0);
	assert(strcmp(*(leftovers + 1), "--version") == 0);
}
extern (D) unittest {
	__gshared const(char)* hit;
	static int opttest(const(char)* arg) {
		hit = arg;
		return 0;
	}
	static immutable(option_t)[] options = [
		option_t('t', "test", "testing switch", &opttest),
	];
	static const(char) **argv = [
		"alicedbg", "--test=value"
	];
	static int argc = 2;
	
	int e = getoptions(argc, argv, options);
	assert(e == 0);   // No leftover argument
	assert(hit); // 
	assert(strcmp(hit, "value") == 0); // 
	
	const(char) **leftovers = getoptleftovers();
	assert(leftovers == null);
}
extern (D) unittest {
	__gshared bool hit;
	static int opttest() {
		return 0;
	}
	static immutable(option_t)[] options = [
		option_t('t', "test", "testing switch", &opttest),
	];
	static const(char) **argv = [
		"alicedbg", "-E", "alicedbg.exe"
	];
	static int argc = 3;
	
	int e = getoptions(argc, argv, options);
	assert(e < 0);   // Option -E not found
	assert(hit == false); // 
}
extern (D) unittest {
	__gshared bool hit;
	static int opttest() {
		return 0;
	}
	static immutable(option_t)[] options = [
		option_t('t', "test", "testing switch", &opttest),
	];
	static const(char) **argv = [
		"alicedbg", "alicedbg.exe"
	];
	static int argc = 2;
	
	int e = getoptions(argc, argv, options);
	assert(e == 1);
	assert(hit == false); // 
	
	const(char) **leftovers = getoptleftovers();
	assert(strcmp(*leftovers, "alicedbg.exe") == 0);
	assert(*(leftovers + 1) == null);
}
/// Test similar switch names
extern (D) unittest {
	__gshared bool dotest;
	static int opttests() {
		dotest = true;
		return 0;
	}
	__gshared const(char)* name;
	static int opttest(const(char)* v) {
		dotest = true;
		name = v;
		return 0;
	}
	static immutable(option_t)[] options = [
		option_t('T', "tests", "all tests", &opttests),
		option_t('t', "test",  "select test", &opttest),
	];
	static const(char) **argv = [
		"alicedbg", "--tests"
	];
	static int argc = 2;
	
	int e = getoptions(argc, argv, options);
	assert(e == 0); // No leftovers
	assert(dotest); // 
	
	const(char) **leftovers = getoptleftovers();
	assert(leftovers == null);
}
extern (D) unittest {
	__gshared bool dotest;
	static int opttests() {
		dotest = true;
		return 0;
	}
	__gshared const(char)* name;
	static int opttest(const(char)* v) {
		dotest = true;
		name = v;
		return 0;
	}
	static immutable(option_t)[] options = [
		option_t('T', "tests", "all tests", &opttest),
		option_t('t', "test",  "select test", &opttest),
	];
	static const(char) **argv = [
		"alicedbg", "--test=amazing"
	];
	static int argc = 2;
	
	int e = getoptions(argc, argv, options);
	assert(e == 0); // No leftovers
	assert(dotest); // 
	assert(strcmp(name, "amazing") == 0);
	
	const(char) **leftovers = getoptleftovers();
	assert(leftovers == null);
}

/// Print options
/// Params: options = CLI options.
void getoptprinter(immutable(option_t)[] options) {
	static immutable int padding = -17;
	foreach (ref option; options) { with (option)
		if (shortname)
			printf(" -%c, --%*s %s\n", shortname, padding, longname.ptr, description.ptr);
		else
			printf("     --%*s %s\n", padding, longname.ptr, description.ptr);
	}
}

// Reset getopt internals
private void getoptreset() {
	if (getoptextras) {
		free(getoptextras);
		getoptextras = null;
	}
	if (getopterrbuf) {
		free(getopterrbuf);
		getopterrbuf = null;
	}
	getoptextrascnt = 0;
}

// CLI "extra" argument handling

private __gshared const(char)** getoptextras;
private __gshared int getoptextrascnt;
private void getoptaddextra(int argc, const(char)* extra) {
	if (getoptextrascnt >= argc)
		return;
	if (getoptextras == null)
		getoptextras = cast(const(char)**)malloc(argc * size_t.sizeof);
	if (getoptextras == null)
		assert(false, "Allocation failure");
	getoptextras[getoptextrascnt++] = extra;
	getoptextras[getoptextrascnt] = null;
}
/// Get remaining arguments
/// Returns: Extra arguments.
const(char)** getoptleftovers() {
	return getoptextras;
}
/// Get remaining argument count
/// Returns: Extra argument count.
int getoptleftcount() {
	return getoptextrascnt;
}

// CLI error handling

private enum GETOPTBFSZ = 256;
private __gshared char* getopterrbuf;

/// Get getopt error message
/// Returns: Error message.
const(char)* getopterror() {
	return getopterrbuf ? getopterrbuf : "No errors occured";
}

private int getopt_prepbuf() {
	if (getopterrbuf == null) {
		getopterrbuf = cast(char*)malloc(GETOPTBFSZ);
		if (getopterrbuf == null) {
			getopterrbuf = cast(char*)"why";
			return 1;
		}
	}
	return 0;
}
private int getoptEunknown(const(char)* opt) {
	if (getopt_prepbuf()) return -100;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: unknown option '%s'.", opt);
	return -1;
}
private int getoptEinvValLong(const(char)* opt, const(char)* val) {
	if (getopt_prepbuf()) return -100;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: '%s' is an invalid value for --%s.", val, opt);
	return -1;
}
private int getoptEinvValShort(char opt, const(char)* val) {
	if (getopt_prepbuf()) return -100;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: '%s' is an invalid value for -%c.", val, opt);
	return -1;
}
private int getoptEmissingLong(const(char)* opt) {
	if (getopt_prepbuf()) return -100;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: missing argument for --%s.", opt);
	return -1;
}
private int getoptEmissingShort(char opt) {
	if (getopt_prepbuf()) return -100;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: missing argument for -%c.", opt);
	return -1;
}
private int getoptEmalformatted(const(char)* opt) {
	if (getopt_prepbuf()) return -100;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: argument switch '--%s' is malformatted.", opt);
	return -1;
}
private int getoptEfailed(const(char) *arg, const(char) *value) {
	if (getopt_prepbuf()) return -100;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: value '%s' failed option '%s'.", value, arg);
	return -1;
}