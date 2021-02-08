/**
 * Text UI
 *
 * License: BSD-3-Clause
 */
module app.debugger.ui.tui;

import core.stdc.stdio, core.stdc.string : memcpy;
import adbg.error;
import adbg.debugger;
import adbg.disasm;
import app.term;
import app.common;

extern (C):
__gshared:

/// Initiate TUI and enter input loop
/// Return: Error code
int tui() {
	term_init;
	term_size(&tui_size);
	if (tui_size.width < 80 || tui_size.height < 24) {
		puts("80x24 terminal minimum size required");
		return 1;
	}
	int e = term_tui_init();
	if (e) {
		printf("Could not initiate terminal buffer (%d)\n", e);
		return e;
	}
	common_settings.disasm.options |= AdbgDisasmOption.spaceSep;
	return adbg_run(&tui_handler);
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

int tui_loop() {
	// Input loop
	InputInfo input = void;
L_READKEY:
	term_read(&input);
	
	switch (input.type) {
	case InputType.Key:
		with (Key)
		switch (input.key.keyCode) {
		case Q: return AdbgAction.exit;
		case Escape:
			
			goto L_READKEY;
		case S:
			tui_status("Proceeding...");
			term_tui_flush;
			return AdbgAction.step;
		case C:
			tui_status("Proceeding...");
			term_tui_flush;
			return AdbgAction.proceed;
		default: goto L_READKEY;
		}
	default: goto L_READKEY;
	}
}

/// Handle exception
/// Params: e = Exception structure
int tui_handler(exception_t *e) {
	term_clear;
	common_settings.disasm.a = e.faultaddr;
	// locals
	const uint h = tui_size.height / 2;
	const uint ihmax = tui_size.height - 2;
	// On-point
	term_curpos(0, h);
	if (adbg_disasm(&common_settings.disasm, AdbgDisasmMode.file) == AdbgError.none)
		term_tui_writef("> %zX %-20s %s",
			common_settings.disasm.la,
			&common_settings.disasm.mcbuf,
			&common_settings.disasm.mnbuf);
	// forward
	for (uint hi = h + 1; hi < ihmax; ++hi) {
		term_curpos(0, hi);
		adbg_disasm(&common_settings.disasm, AdbgDisasmMode.file);
		term_tui_writef("  %zX %-20s %s",
			common_settings.disasm.la, &common_settings.disasm.mcbuf, &common_settings.disasm.mnbuf);
	}
	// backward
	//for (uint ih = h - 1; ih >= 0; ih) {
	// status
	tui_status(adbg_exception_string(e.type));
	term_tui_flush;
	return tui_loop();
}

/// Handle a UI resize event
void tui_event_resize(ushort x, ushort y) {
	
}

/// Draw into display buffer
void tui_render(TUIPanel page) {
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
void tui_clear() {
}

/// 
void tui_status(const(char)* msg) {
	term_curpos(0, tui_size.height - 1);
	term_tui_write(msg);
}