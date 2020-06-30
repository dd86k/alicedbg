/**
 * Text UI
 *
 * License: BSD 3-clause
 */
module ui.tui;

import adbg.os.term;
import adbg.debugger;
import adbg.disasm;
import core.stdc.stdio, core.stdc.string : memcpy;
import ui.common;

extern (C):
__gshared:

/// Initiate TUI and enter input loop
/// Return: Error code
int adbg_ui_tui_enter(disasm_params_t *p) {
	adbg_term_init;
	adbg_term_size(&tui_size);
	if (tui_size.width < 80 || tui_size.height < 24) {
		puts("80x24 terminal minimum size required");
		return 1;
	}
	int e = adbg_term_setup(TermType.Screen);
	if (e) {
		printf("Could not initiate terminal buffer (%d)\n", e);
		return e;
	}
	p.options |= DISASM_O_SPACE;
	memcpy(&g_disparams, p, disasm_params_t.sizeof);
	adbg_userfunc(&adbg_ui_tui_handler);
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
		case Q: return DebuggerAction.exit;
		case Escape:
			
			goto L_READKEY;
		case S:
			adbg_ui_tui_status("Proceeding...");
			adbg_term_flush;
			return DebuggerAction.step;
		case C:
			adbg_ui_tui_status("Proceeding...");
			adbg_term_flush;
			return DebuggerAction.proceed;
		default: goto L_READKEY;
		}
	default: goto L_READKEY;
	}
}

/// Handle exception
/// Params: e = Exception structure
int adbg_ui_tui_handler(exception_t *e) {
	adbg_term_clear;
	g_disparams.a = e.addr;
	// locals
	const uint h = tui_size.height / 2;
	const uint ihmax = tui_size.height - 2;
	// On-point
	adbg_term_curpos(0, h);
	if (adbg_dasm_line(&g_disparams, DisasmMode.File) == DisasmError.None)
		adbg_term_writef("> %zX %-20s %s",
			g_disparams.la, &g_disparams.mcbuf, &g_disparams.mnbuf);
	// forward
	for (uint hi = h + 1; hi < ihmax; ++hi) {
		adbg_term_curpos(0, hi);
		adbg_dasm_line(&g_disparams, DisasmMode.File);
		adbg_term_writef("  %zX %-20s %s",
			g_disparams.la, &g_disparams.mcbuf, &g_disparams.mnbuf);
	}
	// backward
	//for (uint ih = h - 1; ih >= 0; ih) {
	// status
	adbg_ui_tui_status(adbg_ex_typestr(e.type));
	adbg_term_flush;
	return adbg_ui_tui_loop();
}

/// Handle a UI resize event
void adbg_ui_tui_event_resize(ushort x, ushort y) {
	
}

/// Draw into display buffer
void adbg_ui_tui_render(TUIPanel page) {
	with (TUIPanel)
	final switch (page) {
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
	}
}

/// Clear display buffer
void adbg_ui_tui_clear() {
}

/// 
void adbg_ui_tui_status(const(char)* msg) {
	adbg_term_curpos(0, tui_size.height - 1);
	adbg_term_write(msg);
}