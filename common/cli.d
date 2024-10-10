/// Common command-line options
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module common.cli;

import adbg.platform;
import adbg.machines;
import adbg.disassembler : AdbgDisSyntax, adbg_dis_machines;
import adbg.include.capstone : libcapstone_dynload, cs_version;
import adbg.include.c.stdlib : exit;
import adbg.include.d.config : GDC_VERSION, GDC_EXCEPTION_MODE, LLVM_VERSION;
import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;
public import getopt;

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
/// Params: ver = version value
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

/// Is user asking for help with this option?
/// Params: query = Value input.
/// Returns: true on "help".
bool wantsHelp(const(char) *query) {
	return strcmp(query, "help") == 0;
}

private:

//
// -m|--machine
//

int cli_march(const(char) *val) {
	if (wantsHelp(val)) {
		puts("Available machine architectures:");
		immutable(AdbgMachine)* mach = void;
		for (size_t i; (mach = adbg_dis_machines(i++)) != null;) {
			immutable(adbg_machine_t)* m = adbg_machine(*mach);
			printf("- %*s", -8, m.alias1);
			if (m.alias2) printf(" (%s)", m.alias2);
			else          putchar('\t');
			printf("\t%s\n", m.name);
		}
		exit(0);
	}
	immutable(adbg_machine_t)* m = adbg_machine_select(val);
	if (m) {
		opt_machine = m.machine;
		return EXIT_SUCCESS;
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
	__gshared immutable(char) *page_version = // avoid TLS
	"Version     "~FULL_VERSION~"\n"~
	"            Built "~__TIMESTAMP__~"\n"~
	"            "~COPYRIGHT~"\n"~
	"License     BSD-3-Clause-Clear\n"~
	"            <https://opensource.org/licenses/BSD-3-Clause-Clear>\n"~
	"Homepage    https://github.com/dd86k/alicedbg";
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