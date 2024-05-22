/// Common command-line options
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module common.cli;

import adbg.platform;
import adbg.machines : AdbgMachine;
import adbg.disassembler : AdbgDisSyntax;
import adbg.include.capstone : libcapstone_dynload, cs_version;
import adbg.include.c.stdlib : exit;
import adbg.include.d.config : GDC_VERSION, GDC_EXCEPTION_MODE, LLVM_VERSION;
import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;

//TODO: Consider separating getopt impl. to common.getopt,
//      and leave common CLI options here

/// Copyright string
enum COPYRIGHT = "Copyright (c) 2019-2024 dd86k <dd@dax.moe>";

/// License string
immutable char *page_license =
COPYRIGHT~`
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`;

debug enum FULL_VERSION = ADBG_VERSION~"+"~__BUILDTYPE__; /// Full version string
else  enum FULL_VERSION = ADBG_VERSION; /// Ditto

/// Turns a __VERSION__ number into a string constant
template DSTRVER(uint ver) {
	enum DSTRVER =
		cast(char)((ver / 1000) + '0') ~ "." ~
		cast(char)(((ver % 1000) / 100) + '0') ~
		cast(char)(((ver % 100) / 10) + '0') ~
		cast(char)((ver % 10) + '0');
}
/// Compiler version string
enum __D_VERSION__ = DSTRVER!__VERSION__;

__gshared {
	/// Machine option
	AdbgMachine opt_machine;
	/// Disassembler syntax option
	AdbgDisSyntax opt_syntax;
}

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

/// Default option for --machine
enum option_arch       = option_t('m', "machine",	"Select machine for disassembler (default=platform)", &cli_march);
/// Default option for --syntax
enum option_syntax     = option_t('s', "syntax",	"Select syntax for disassembler (default=platform)", &cli_syntax);
/// Default option for --version
enum option_version    = option_t(0,   "version",	"Show the version screen and exit", &cli_version);
/// Default option for --build-info
enum option_build_info = option_t(0,   "build-info",	"Show the build and debug information and exit", &cli_build_info);
/// Default option for --ver
enum option_ver        = option_t(0,   "ver",	"Show only the version string and exit", &cli_ver);
/// Default option for --license
enum option_license    = option_t(0,   "license",	"Show the license page and exit", &cli_license);

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

// Returns the position of the first occurence of the specified character.
private
ptrdiff_t strsrch(const(char) *hay, int needle) {
	for (ptrdiff_t i; hay[i]; ++i)
		if (hay[i] == needle)
			return i;
	return -1;
}
unittest {
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
int getopt(int argc, const(char) **argv, immutable(option_t)[] options) {
	// On re-entry, clear extras and error buffers
	getoptreset();
	
	int i = 1;
	for (; i < argc; ++i) {
		const(char) *arg = argv[i]; // Current argument
		
		const(char) *value;
		immutable(option_t) *option = void;
		if (arg[1] == '-') { // "--" -> Long option
			const(char) *argLong = arg + 2;
			
			// Test for "--" (do not process options anymore)
			if (argLong[0] == 0)
				goto Lskip;
			
			// Get value in advance, if possible
			ptrdiff_t vp = strsrch(argLong, '=');
			if (vp == 0) { // --=example is invalid
				return getoptEmalformatted(argLong);
			} else if (vp >= 0) { // --e=example means "example" is value
				value = argLong + 1 + vp;
			}
			
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
		int e = getoptexec(option, value);
		if (e < 0)
			return e;
	}
	
	goto Lret;
	
Lskip:	// When '--' is given, add the rest of arguments as "extras"
	for (++i; i < argc; ++i)
		getoptaddextra(argc, argv[i]);
Lret:	return getoptleftcount();
}
unittest {
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
	
	int e = getopt(argc, argv, options);
	assert(e == 2);   // Two leftover argument
	assert(hit == 1); // --test switch hit once
	
	const(char) **leftovers = getoptleftovers();
	assert(leftovers);
	assert(strcmp(*leftovers, "argument") == 0);
	assert(strcmp(*(leftovers + 1), "--test") == 0);
}
unittest {
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
	
	int e = getopt(argc, argv, options);
	assert(e == 2);   // Two leftover argument
	assert(hit == 0); // --test switch never hit
	
	const(char) **leftovers = getoptleftovers();
	assert(leftovers);
	assert(strcmp(*leftovers, "alicedbg.exe") == 0);
	assert(strcmp(*(leftovers + 1), "--version") == 0);
}
unittest {
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
	
	int e = getopt(argc, argv, options);
	assert(e == 0);   // No leftover argument
	assert(hit); // 
	assert(strcmp(hit, "value") == 0); // 
	
	const(char) **leftovers = getoptleftovers();
	assert(leftovers == null);
}
unittest {
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
	
	int e = getopt(argc, argv, options);
	assert(e < 0);   // Option -E not found
	assert(hit == false); // 
}
unittest {
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
	
	int e = getopt(argc, argv, options);
	assert(e == 1);
	assert(hit == false); // 
	
	const(char) **leftovers = getoptleftovers();
	assert(strcmp(*leftovers, "alicedbg.exe") == 0);
	assert(*(leftovers + 1) == null);
}
/// Test similar switch names
/*unittest {
	__gshared bool hit;
	static int opttests() {
		hit = true;
		return 0;
	}
	__gshared const(char)* name;
	static int opttest(const(char)* v) {
		name = v;
		return 0;
	}
	static immutable(option_t)[] options = [
		option_t('T', "tests", "all tests", &opttest),
		option_t('t', "test",  "select test", &opttest),
	];
	static const(char) **argv = [
		"alicedbg", "--tests"
	];
	static int argc = 2;
	
	int e = getopt(argc, argv, options);
	assert(e == 0); // No leftovers
	assert(hit == true); // 
	
	const(char) **leftovers = getoptleftovers();
	assert(leftovers == null);
}*/

/// Print options
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
	getoptextrascnt = 0;
	if (getopterrbuf) {
		free(getopterrbuf);
		getopterrbuf = null;
	}
}

// CLI "extra" argument handling

private __gshared const(char)** getoptextras;
private __gshared int getoptextrascnt;
//TODO: This should error out
private void getoptaddextra(int argc, const(char)* extra) {
	if (getoptextrascnt >= argc)
		return;
	if (getoptextras == null) {
		getoptextras = cast(const(char)**)malloc(argc * size_t.sizeof);
		if (getoptextras == null)
			return;
	}
	getoptextras[getoptextrascnt++] = extra;
	getoptextras[getoptextrascnt] = null;
}
/// Get remaining arguments
const(char)** getoptleftovers() {
	return getoptextras;
}
/// Get remaining argument count
int getoptleftcount() {
	return getoptextrascnt;
}

// CLI error handling

private enum GETOPTBFSZ = 2048;
private __gshared char* getopterrbuf;

/// Get getopt error message
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

/// Is user asking for help with this option?
bool wantsHelp(const(char) *query) {
	return strcmp(query, "help") == 0;
}

private:

//
// --march
//

//TODO: Interface with machine module instead
//      Needs a filter at the disassembler level: adbg_dasm_machine_available()

struct setting_platform_t {
	AdbgMachine val;
	const(char)* opt, alt, desc;
}
immutable setting_platform_t[] platforms = [
	{ AdbgMachine.i8086,	"x86_16",  "8086",  "x86 16-bit (real mode)" },
	{ AdbgMachine.i386,	"x86",     "i386",  "x86 32-bit (extended mode)" },
	{ AdbgMachine.amd64,	"x86_64",  "amd64", "x86 64-bit (long mode)" },
	{ AdbgMachine.thumb,	"t16",  "thumb",    "Thumb" },
	{ AdbgMachine.thumb32,	"t32",  "thumb32",  "Thumb (32-bit)" },
	{ AdbgMachine.arm,	"a32",  "arm",      "Armv8 (32-bit)" },
	{ AdbgMachine.aarch64,	"a64",  "aarch64",  "Armv8 (64-bit)" },
];

int cli_march(const(char) *val) {
	if (wantsHelp(val)) {
		puts("Available machine architectures:");
		foreach (setting_platform_t p; platforms) {
			with (p)
			printf("%8s, %-10s  %s\n", opt, alt, desc);
		}
		exit(0);
	}
	foreach (setting_platform_t p; platforms) {
		if (strcmp(val, p.opt) == 0 || strcmp(val, p.alt) == 0) {
			opt_machine = p.val;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

//
// --syntax
//

struct setting_syntax_t {
	AdbgDisSyntax val;
	const(char)* opt, desc;
}
immutable setting_syntax_t[] syntaxes = [
	{ AdbgDisSyntax.att,   "att",   "AT&T syntax" },
	{ AdbgDisSyntax.intel, "intel", "Intel syntax" },
];

int cli_syntax(const(char) *val) {
	if (wantsHelp(val)) {
		puts("Available disassembler syntaxes:");
		foreach (setting_syntax_t syntax; syntaxes) {
			with (syntax)
			printf("%-10s  %s\n", opt, desc);
		}
		exit(0);
	}
	foreach (setting_syntax_t syntax; syntaxes) {
		if (strcmp(val, syntax.opt) == 0) {
			opt_syntax = syntax.val;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

int cli_build_info() {
	static immutable char *page =
	"Compiler    "~__VENDOR__~" "~__D_VERSION__~"\n"~
	"Target      "~TARGET_TRIPLE~"\n"~
	"Object      "~TARGET_OBJFMT~"\n"~
	"FPU         "~TARGET_FLTABI~"\n"~
	"CppRT       "~TARGET_CPPRT~"\n"~
	"Config     "~D_FEATURES;
	puts(page);
	
	static if (GDC_VERSION) {
		printf("GCC         %d\n", GDC_VERSION);
		printf("GDC-EH      %s\n", GDC_EXCEPTION_MODE);
	}
	
	version (CRuntime_Glibc) {
		import adbg.include.c.config : gnu_get_libc_version;
		printf("Glibc       %s\n", gnu_get_libc_version());
	}
	
	static if (LLVM_VERSION)
		printf("LLVM        %d\n", LLVM_VERSION);
	
	printf("Capstone    ");
	if (libcapstone_dynload()) {
		puts("error");
	} else {
		int major = void, minor = void;
		cs_version(&major, &minor);
		printf("%d.%d\n", major, minor);
	}
	
	exit(0);
	return 0;
}

//
// --version
//

int cli_version() {
	__gshared immutable(char) *page_version =
	"alicedbg    "~FULL_VERSION~"\n"~
	"            Built "~__TIMESTAMP__~"\n"~
	"            "~COPYRIGHT~"\n"~
	"License     BSD-3-Clause-Clear\n"~
	"            <https://opensource.org/licenses/BSD-3-Clause-Clear>\n"~
	"Homepage    https://git.dd86k.space/dd86k/alicedbg";
	
	puts(page_version);
	
	exit(0);
	return 0;
}

//
// --ver
//

int cli_ver() {
	puts(FULL_VERSION);
	exit(0);
	return 0;
}

//
// --license
//

int cli_license() {
	puts(page_license);
	exit(0);
	return 0;
}