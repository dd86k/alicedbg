/**
 * Text UI
 *
 * License: BSD-3-Clause
 */
module debugger.ui.tui;

import core.stdc.stdio, core.stdc.string : memcpy;
import adbg.error;
import adbg.sys.term;
import adbg.debugger;
import adbg.disasm;
import debugger.common;

extern (C):
__gshared:

/// Initiate TUI and enter input loop
/// Return: Error code
int adbg_ui_tui() {
	adbg_term_init;
	adbg_term_size(&tui_size);
	if (tui_size.width < 80 || tui_size.height < 24) {
		puts("80x24 terminal minimum size required");
		return 1;
	}
	int e = adbg_term_tui_init();
	if (e) {
		printf("Could not initiate terminal buffer (%d)\n", e);
		return e;
	}
	g_disparams.options |= AdbgDisasmOption.spaceSep;
	adbg_event_exception(&adbg_ui_tui_handler);
	return adbg_run;
}

private:

enum TUIPanel {
	disasm,
	memory,
	watcher,
	locals,
	registers,
	stack,
	notepad,
	processes,	// and threads
	info,	// os/cpu/console/debug/settings info
	about,
}

struct tuiopt_t {
	TUIPanel currentpane;
}

tuiopt_t TUIOptions;
/// Last windows (console/terminal) size
WindowSize tui_size;

int adbg_ui_tui_loop() {
	// Input loop
	InputInfo input = void;
L_READKEY:
	adbg_term_read(&input);
	
	switch (input.type) {
	case InputType.Key:
		with (Key)
		switch (input.key.keyCode) {
		case Q: return AdbgAction.exit;
		case Escape:
			
			goto L_READKEY;
		case S:
			adbg_ui_tui_status("Proceeding...");
			adbg_term_tui_flush;
			return AdbgAction.step;
		case C:
			adbg_ui_tui_status("Proceeding...");
			adbg_term_tui_flush;
			return AdbgAction.proceed;
		default: goto L_READKEY;
		}
	default: goto L_READKEY;
	}
}

/// Handle exception
/// Params: e = Exception structure
int adbg_ui_tui_handler(exception_t *e) {
	adbg_term_clear;
	g_disparams.a = e.faultaddr;
	// locals
	const uint h = tui_size.height / 2;
	const uint ihmax = tui_size.height - 2;
	// On-point
	adbg_term_curpos(0, h);
	if (adbg_disasm(&g_disparams, AdbgDisasmMode.file) == AdbgError.none)
		adbg_term_tui_writef("> %zX %-20s %s",
			g_disparams.la, &g_disparams.mcbuf, &g_disparams.mnbuf);
	// forward
	for (uint hi = h + 1; hi < ihmax; ++hi) {
		adbg_term_curpos(0, hi);
		adbg_disasm(&g_disparams, AdbgDisasmMode.file);
		adbg_term_tui_writef("  %zX %-20s %s",
			g_disparams.la, &g_disparams.mcbuf, &g_disparams.mnbuf);
	}
	// backward
	//for (uint ih = h - 1; ih >= 0; ih) {
	// status
	adbg_ui_tui_status(adbg_ex_typestr(e.type));
	adbg_term_tui_flush;
	return adbg_ui_tui_loop();
}

/// Handle a UI resize event
void adbg_ui_tui_event_resize(ushort x, ushort y) {
	
}

/// Draw into display buffer
void adbg_ui_tui_render(TUIPanel page) {
	with (TUIPanel)
	switch (page) {
	case disasm:
		break;
	case memory: break;
	case watcher: break;
	case locals: break;
	case registers: break;
	case stack: break;
	case notepad: break;
	case processes: break;
	case info: break;
	case about: break;
	default: assert(0);
	}
}

/// Clear display buffer
void adbg_ui_tui_clear() {
}

/// 
void adbg_ui_tui_status(const(char)* msg) {
	adbg_term_curpos(0, tui_size.height - 1);
	adbg_term_tui_write(msg);
}