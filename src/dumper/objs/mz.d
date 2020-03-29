/**
 * MS-DOS MZ file dumper
 *
 * License: BSD 3-Clause
 */
module dumper.objs.mz;

import core.stdc.stdio;
import core.stdc.config : c_long;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, realloc;
import core.stdc.time : time_t, tm, localtime, strftime;
import debugger.file.loader : file_info_t;
import debugger.disasm.core : disasm_params_t, disasm_line, DisasmMode;
import debugger.file.objs.pe;

extern (C):

/// Print MZ info to stdout, a file_info_t structure must be loaded before
/// calling this function.
/// Params:
/// 	fi = File information
/// 	dp = Disassembler parameters
/// 	flags = Show X flags
/// Returns: Non-zero on error
int dumper_print_mz(file_info_t *fi, disasm_params_t *dp, int flags) {
	//TODO: MZ
	
	return EXIT_SUCCESS;
}