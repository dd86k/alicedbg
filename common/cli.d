/// Common command-line options
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module common.cli;

import adbg.platform;
import adbg.debugger.exception : adbg_exception_t, adbg_exception_name;
import adbg.machines : AdbgMachine;
import adbg.disassembler : AdbgDisSyntax;
import adbg.include.capstone : libcapstone_dynload, cs_version;
import adbg.include.c.stdlib : exit;
import adbg.include.d.config : GDC_VERSION, GDC_EXCEPTION_MODE, LLVM_VERSION;
import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;
import core.stdc.errno;

enum COPYRIGHT = "Copyright (c) 2019-2024 dd86k <dd@dax.moe>";

immutable(char) *page_license =
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

debug enum FULL_VERSION = ADBG_VERSION~"+"~__BUILDTYPE__;
else  enum FULL_VERSION = ADBG_VERSION;

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

struct option_t { align(1):
	this (char oshort, string olong, string desc, int function() ufunc) {
		shortname = oshort;
		longname = olong;
		description = desc;
		argtype = ARG_NONE;
		f = ufunc;
	}
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
		int function() f;
		int function(const(char)*) fa;
	}
}

//NOTE: Can't make a template and pass a function pointer

enum option_arch       = option_t('a', "arch",	"Select machine for disassembler (default=platform)", &cli_march);
enum option_syntax     = option_t('s', "syntax",	"Select syntax for disassembler (default=platform)", &cli_syntax);
enum option_version    = option_t(0,   "version",	"Show the version screen and exit", &cli_version);
enum option_build_info = option_t(0,   "build-info",	"Show the build and debug information and exit", &cli_build_info);
enum option_ver        = option_t(0,   "ver",	"Show only the version string and exit", &cli_ver);
enum option_license    = option_t(0,   "license",	"Show the license page and exit", &cli_license);

//TODO: Return error
// <0 -> error
//  0 -> no args left
// >0 -> args left
//TODO: Make option functions return <0=error >0=ok, consumed arg(s)
int getopt(int argc, const(char) **argv, immutable(option_t)[] options) {
	const(char) *arg = void;
	const(char) *val = void;
	CLI: for (int argi = 1; argi < argc; ++argi) {
		arg = argv[argi];
		
		if (arg[1] == '-') { // Long options
			const(char) *argLong = arg + 2;
			
			// test for "--" (extra args)
			/*if (argLong[0] == 0) {
				if (cli_args_stop(++argi, argc, argv))
					return -1;
				break CLI;
			}*/
			
			// Check options
			L_LONG: foreach (ref opt; options) {
				//TODO: test for '='
				//      --example=value
				
				if (strncmp(argLong, opt.longname.ptr, opt.longname.length))
					continue L_LONG;
				
				// no argument expected
				if (opt.argtype == ARG_NONE) {
					if (opt.f())
						return -1;
					continue CLI;
				}
				
				// with argument
				if (++argi >= argc) {
					getoptEmissingLong(opt.longname.ptr);
					return -1;
				}
				val = argv[argi];
				if (opt.fa(val)) {
					getoptEinvValLong(opt.longname.ptr, val);
					return -1;
				}
				continue CLI;
			}
			
			getoptEunknown(arg);
			return -1;
		} else if (arg[0] == '-') { // Short options
			// test for "-" (stdin)
			char argShort = arg[1];
			if (argShort == 0) { // "-"
				getopterrbuf = cast(char*)"main: standard input not supported";
				return -1;
			}
			
			L_SHORT: foreach (ref opt; options) {
				if (argShort != opt.shortname)
					continue L_SHORT;
				
				// no argument
				if (opt.argtype == ARG_NONE) {
					if (opt.f())
						return -1;
					continue CLI;
				}
				
				// with argument
				if (++argi >= argc) {
					getoptEmissingShort(argShort);
					return -1;
				}
				val = argv[argi];
				if (opt.fa(val)) {
					getoptEinvValShort(opt.shortname, val);
					return -1;
				}
				continue CLI;
			}
			
			getoptEunknown(arg);
			return -1;
		} else {
			getoptaddextra(argc, arg);
			//*entry = arg;
			continue CLI;
		}
	}
	
	return 0;
}
//TODO: These unittests!
unittest {
}

void getoptprinter(immutable(option_t)[] options, int skip = 0) {
	static immutable int padding = -17;
	foreach (ref option; options[skip..$]) { with (option)
		if (shortname)
			printf(" -%c, --%*s %s\n", shortname, padding, longname.ptr, description.ptr);
		else
			printf("     --%*s %s\n", padding, longname.ptr, description.ptr);
	}
}

// CLI "extra" argument handling

private __gshared const(char)** getoptextras;
private __gshared int getoptextrascnt;
private void getoptaddextra(int argc, const(char)* extra) {
	if (getoptextrascnt >= argc)
		return;
	if (getoptextras == null) {
		getoptextras = cast(const(char)**)malloc(argc * size_t.sizeof);
		if (getoptextras == null)
			return;
	}
	getoptextras[getoptextrascnt++] = extra;
}
const(char)** getoptrem() {
	return getoptextras;
}
int getoptremcnt() {
	return getoptextrascnt;
}

// CLI error handling

private enum GETOPTBFSZ = 2048;
private __gshared char* getopterrbuf;

const(char)* getopterrstring() {
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
private void getoptEunknown(const(char)* opt) {
	if (getopt_prepbuf()) return;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: unknown option '%s'\n", opt);
}
private void getoptEinvValLong(const(char)* opt, const(char)* val) {
	if (getopt_prepbuf()) return;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: '%s' is an invalid value for --%s\n", val, opt);
}
private void getoptEinvValShort(char opt, const(char)* val) {
	if (getopt_prepbuf()) return;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: '%s' is an invalid value for -%c\n", val, opt);
}
private void getoptEmissingLong(const(char)* opt) {
	if (getopt_prepbuf()) return;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: missing argument for --%s\n", opt);
}
private void getoptEmissingShort(char opt) {
	if (getopt_prepbuf()) return;
	snprintf(getopterrbuf, GETOPTBFSZ,
		"main: missing argument for -%c\n", opt);
}


bool wantsHelp(const(char) *query) {
	return (query[0] == 'h' && query[1] == 0) ||
		strcmp(query, "help") == 0;
}

//
// --march
//

struct setting_platform_t {
	AdbgMachine val;
	const(char)* opt, alt, desc;
}
immutable setting_platform_t[] platforms = [
	{ AdbgMachine.i8086,	"x86_16",  "8086",  "x86 16-bit (real mode)" },
	{ AdbgMachine.x86,	"x86",     "i386",  "x86 32-bit (extended mode)" },
	{ AdbgMachine.amd64,	"x86_64",  "amd64", "x86 64-bit (long mode)" },
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
	__gshared immutable(char) *page =
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