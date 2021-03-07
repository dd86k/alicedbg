/**
 * MS-DOS MZ file dumper
 *
 * License: BSD-3-Clause
 */
module dumper.dump.mz;

import core.stdc.stdio;
import core.stdc.config : c_long;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, realloc;
import core.stdc.time : time_t, tm, localtime, strftime;
import adbg.obj.server;
import adbg.disasm.disasm : adbg_disasm_t, adbg_disasm, AdbgDisasmMode;
import adbg.obj.pe;

extern (C):

/// Print MZ info to stdout, a file_info_t structure must be loaded before
/// calling this function.
/// Params:
/// 	fi = File information
/// 	dp = Disassembler parameters
/// 	flags = Show X flags
/// Returns: Non-zero on error
int dump_mz(adbg_object_t *obj, adbg_disasm_t *dp, int flags) {
	//TODO: MZ
	assert(0, "dump_mz: todo");
}