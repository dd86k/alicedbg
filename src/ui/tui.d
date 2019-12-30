module ui.tui;

//import misc.ddc;
import core.stdc.stdio;
import os.term;
import debugger;

extern (C):
__gshared:

/// Initiate TUI and enter input loop
/// Return: Error code
int ui_tui() {
	term_init;
	term_wsize(tui_size);
	if (tui_size.width < 80 || tui_size.height < 24) {
		puts("80x24 terminal minimum size required");
		return 1;
	}
	int e = term_setup(TermType.Screen);
	if (e) {
		printf("Could not initiate terminal buffer (%d)\n", e);
		return e;
	}
	dbg_sethandle(&tui_event_ex);
	return dbg_loop;
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

int tui_loop() {
	// Input loop
	InputInfo input = void;
L_READKEY:
	term_read(input);
	
	switch (input.type) {
	case InputType.Key:
		with (Key)
		switch (input.key.keyCode) {
		case Q: return DebuggerAction.exit;
		case Escape:
			
			goto L_READKEY;
		case S:
			tui_status("Proceeding...");
			term_flush;
			return DebuggerAction.step;
		case C:
			tui_status("Proceeding...");
			term_flush;
			return DebuggerAction.proceed;
		default: goto L_READKEY;
		}
	default: goto L_READKEY;
	}
}

/// Handle exception
/// Params: e = Exception structure
int tui_event_ex(exception_t *e) {
	term_clear;
	// disasm settings
	disasm_params_t params;
	params.include |= DISASM_I_MACHINECODE | DISASM_I_MNEMONICS;
	params.addrv = e.addrv;
	// locals
	const uint h = tui_size.height / 2;
	const uint ihmax = tui_size.height - 2;
	// On-point
	term_pos(0, h);
	if (disasm_line(params) == DisasmError.None)
		term_writef("> %zX %-20s %s",
			params.thisaddr, &params.mcbuf, &params.mnbuf);
	// forward
	for (uint hi = h + 1; hi < ihmax; ++hi) {
		term_pos(0, hi);
		if (disasm_line(params) == DisasmError.None)
			term_writef("  %zX %-20s %s",
				params.thisaddr, &params.mcbuf, &params.mnbuf);
	}
	// backward
	//for (uint ih = h - 1; ih >= 0; ih) {
	// status
	tui_status(e.type.typestr);
	term_flush;
	return tui_loop();
}

/// Handle a UI resize event
void tui_event_resize(ushort x, ushort y) {
	
}

/// Draw into display buffer
void tui_render(TUIPanel page) {
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
void tui_clear() {
}

/// 
void tui_status(const(char)* msg) {
	term_pos(0, tui_size.height - 1);
	term_write(msg);
}