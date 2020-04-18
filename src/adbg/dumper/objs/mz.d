/**
 * MS-DOS MZ file dumper
 *
 * License: BSD 3-Clause
 */
module adbg.dumper.objs.mz;

import core.stdc.stdio;
import core.stdc.config : c_long;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, realloc;
import core.stdc.time : time_t, tm, localtime, strftime;
import adbg.debugger.obj.loader : obj_info_t;
import adbg.debugger.disasm.disasm : disasm_params_t, adbg_dasm_line, DisasmMode;
import adbg.debugger.file.objs.pe;

extern (C):

/// Print MZ info to stdout, a file_info_t structure must be loaded before
/// calling this function.
/// Params:
/// 	fi = File information
/// 	dp = Disassembler parameters
/// 	flags = Show X flags
/// Returns: Non-zero on error
int adbg_dmpr_mz_print(obj_info_t *fi, disasm_params_t *dp, int flags) {
	//TODO: MZ
	
	return EXIT_SUCCESS;
}