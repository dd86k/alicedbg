/// Logging interface.
///
/// Useful for applications debugging alicedbg when compiled as a library.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © 2019-2023 dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.logger;

import adbg.etc.c.stdarg;
import adbg.etc.c.stdio;
import adbg.etc.c.stdlib : malloc;

//TODO: Make this thread-safe
//TODO: Variadic functions
//      lazy if possible, but that's only with type-safe parameters

enum AdbgLogLevel {
	silent,
	critical,
	error,
	warning,
	info,
	verbose,
	trace,
}

private __gshared {
	void function(const(char)* msg) adbg_log_receiver;
	AdbgLogLevel current_level;
	
	enum buffer_size = 1024;
	char *buffer;
}

void adbg_log_connect(AdbgLogLevel level, void function(const(char)* msg) func) {
	if (level == AdbgLogLevel.silent)
		return;
	
	current_level = level;
	adbg_log_receiver = func;
	buffer = cast(char*)malloc(buffer_size);
}

void adbg_log(AdbgLogLevel level, const(char)* msg) {
	if (current_level == AdbgLogLevel.silent)
		return;
	
	const(char) *mlevel = void;
	
	switch (level) with (AdbgLogLevel) {
	case critical:	mlevel = "fatal"; break;
	case error:	mlevel = "error"; break;
	case warning:	mlevel = "warning"; break;
	case info:	mlevel = "info"; break;
	case verbose:	mlevel = "verbose"; break;
	case trace:	mlevel = "trace"; break;
	default: assert(0, "Missing level in adbg_log");
	}
	
	snprintf(buffer, buffer_size, "%s: %s\n", mlevel, msg);
	adbg_log_receiver(buffer);
}

void adbg_log_crit(const(char)* msg) {
	if (current_level == AdbgLogLevel.silent)
		return;
	
	adbg_log(AdbgLogLevel.critical, msg);
}

void adbg_log_err(const(char)* msg) {
	if (current_level < AdbgLogLevel.error)
		return;
	
	adbg_log(AdbgLogLevel.error, msg);
}

void adbg_log_warn(const(char)* msg) {
	if (current_level < AdbgLogLevel.warning)
		return;
	
	adbg_log(AdbgLogLevel.warning, msg);
}

void adbg_log_info(const(char)* msg) {
	if (current_level < AdbgLogLevel.info)
		return;
	
	adbg_log(AdbgLogLevel.info, msg);
}

void adbg_log_verbose(const(char)* msg) {
	if (current_level < AdbgLogLevel.verbose)
		return;
	
	adbg_log(AdbgLogLevel.verbose, msg);
}

void adbg_log_trace(const(char)* msg) {
	if (current_level < AdbgLogLevel.trace)
		return;
	
	adbg_log(AdbgLogLevel.trace, msg);
}