/// Warning reporting for non-fatal conditions.
///
/// Warn when a call succeeds but its result is incomplete, and the caller
/// cannot tell from the return value. For example, a malformed record ended
/// an iteration early.
///
/// Do not warn when:
/// - The call fails. Use adbg_oops.
/// - The result is complete but took another path, like reading memory with
///   ptrace after /proc/PID/mem failed. Use trace.
/// - The caller is already told, like a failed pairing returning its code.
///
/// Each code needs a call site. The message belongs to the code. Context is
/// the name, index, or offset involved.
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.warning;

import adbg.include.d.config : D_FEATURE_PRAGMA_PRINTF;
import core.stdc.stdarg;
import core.stdc.stdio : vsnprintf;

extern (C):

/// Warning codes.
enum AdbgWarning {
	none	= 0,
	//
	// 300-399: Object server
	//
	objectMalformedRecord	= 300,	/// Malformed record ended iteration early
}

/// Reported warning.
struct adbg_warning_t {
	int code;	/// Warning code (AdbgWarning)
	const(char) *message;	/// Message for code
	const(char) *context;	/// Name, index, or offset involved, or null
	const(char) *func;	/// Source function
	int line;	/// Source line
}

/// Warning handler, called with the user data given at registration.
alias adbg_warning_handler_t = void function(void *udata, const(adbg_warning_t) *warning);

/// Registered warning handler, or null.
private __gshared adbg_warning_handler_t handler;
/// User data passed to the handler.
private __gshared void *handler_udata;

/// Set the warning handler and its user data, or null to disable warnings.
/// NOTE: Not thread-safe, set it before using the library. The handler runs
///       on the thread that hit the condition.
void adbg_warning_set_handler(adbg_warning_handler_t h, void *udata) {
	handler = h;
	handler_udata = udata;
}

private struct adbg_warning_msg_t {
	int code;
	string msg;
}
/// Messages for warning codes.
private immutable adbg_warning_msg_t[] warnings_msg = [
	{ AdbgWarning.objectMalformedRecord,	"Malformed record, stopped reading." },
	{ AdbgWarning.none,	"No warning." },
];

/// Message for warning code, or a default message if unknown.
const(char)* adbg_warning_message(int code) {
	foreach (ref w; warnings_msg)
		if (w.code == code)
			return w.msg.ptr;
	return "Unknown warning.";
}

/// Format context from fmt and args, then call the handler with warning w.
private
void adbg_warning_emit(AdbgWarning w, const(char) *func, int line, const(char) *fmt, va_list *args) {
	if (handler == null)
		return;
	char[256] context = void;
	adbg_warning_t warning;
	warning.code = w;
	warning.message = adbg_warning_message(w);
	warning.func = func;
	warning.line = line;
	if (fmt) {
		vsnprintf(context.ptr, context.length, fmt, *args);
		warning.context = context.ptr;
	}
	handler(handler_udata, &warning);
}

static if (D_FEATURE_PRAGMA_PRINTF) {
	/// Internal: Report warning w to the handler. fmt is a printf-like
	/// context string, or null.
	pragma(printf)
	void adbg_warn(string func = __FUNCTION__, int line = __LINE__)(AdbgWarning w, const(char) *fmt, ...) {
		va_list va = void;
		va_start(va, fmt);
		adbg_warning_emit(w, func.ptr, line, fmt, &va);
	}
} else {
	/// Ditto
	void adbg_warn(string func = __FUNCTION__, int line = __LINE__)(AdbgWarning w, const(char) *fmt, ...) {
		va_list va = void;
		va_start(va, fmt);
		adbg_warning_emit(w, func.ptr, line, fmt, &va);
	}
}

unittest {
	import core.stdc.string : strcmp;

	static struct Seen {
		int count;
		int code;
		char[64] context;
	}
	static extern (C) void on_warning(void *udata, const(adbg_warning_t) *w) {
		import core.stdc.string : strncpy;
		Seen *seen = cast(Seen*)udata;
		++seen.count;
		seen.code = w.code;
		if (w.context)
			strncpy(seen.context.ptr, w.context, seen.context.length - 1);
	}

	Seen seen;
	adbg_warn(AdbgWarning.objectMalformedRecord, "offset %#x", 0x40);
	assert(seen.count == 0);

	adbg_warning_set_handler(&on_warning, &seen);
	scope(exit) adbg_warning_set_handler(null, null);

	adbg_warn(AdbgWarning.objectMalformedRecord, "offset %#x", 0x40);
	assert(seen.count == 1);
	assert(seen.code == AdbgWarning.objectMalformedRecord);
	assert(strcmp(seen.context.ptr, "offset 0x40") == 0);
	assert(strcmp(adbg_warning_message(AdbgWarning.objectMalformedRecord),
		"Malformed record, stopped reading.") == 0);
}
