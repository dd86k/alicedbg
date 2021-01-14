/**
 * License: BSD 3-clause
 */
module adbg.error;

extern (C):

// NOTE: Work in progress

private enum modshift = 16;

enum AdbgErrorModule : ushort {
	Application,
	System, /// CRT/OS
	Debugger,
	Disassembler,
	Object,
	Utilities,
}

struct adbg_err_t {
	ushort mod;
	int code;
}
