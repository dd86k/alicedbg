/**
 * In-house console/terminal library
 *
 * License: BSD 3-clause
 */
module adbg.sys.term;

private import core.stdc.stdio;
private import core.stdc.stdlib;
public import adbg.etc.c : putchar;
private alias sys = core.stdc.stdlib.system;

//TODO: Consider using PDCurses instead

extern (C):
__gshared:

version (Windows) {
	private import core.sys.windows.windows;
	private enum ALT_PRESSED =  RIGHT_ALT_PRESSED  | LEFT_ALT_PRESSED;
	private enum CTRL_PRESSED = RIGHT_CTRL_PRESSED | LEFT_CTRL_PRESSED;
	private HANDLE handleIn, handleOut, handleOld;
	// Internal buffer
	//TODO: structure
	private ushort ibuf_x, ibuf_y, ibuf_w, ibuf_h;
	private CHAR_INFO *ibuf;
	private COORD ibuf_size, ibuf_pos;
	private SMALL_RECT ibuf_rect;
} else
version (Posix) {
	private import core.sys.posix.sys.ioctl;
	private import core.sys.posix.unistd;
	private import core.sys.posix.termios;
	private import core.sys.posix.signal;
	private import core.sys.posix.ucontext;
	version (CRuntime_Musl) {
		alias uint tcflag_t;
		alias uint speed_t;
		alias char cc_t;
		private enum TCSANOW	= 0;
		private enum NCCS	= 32;
		private enum ICANON	= 2;
		private enum ECHO	= 10;
		private enum TIOCGWINSZ	= 0x5413;
		private struct termios {
			tcflag_t c_iflag;
			tcflag_t c_oflag;
			tcflag_t c_cflag;
			tcflag_t c_lflag;
			cc_t c_line;
			cc_t[NCCS] c_cc;
			speed_t __c_ispeed;
			speed_t __c_ospeed;
		}
		private struct winsize {
			ushort ws_row;
			ushort ws_col;
			ushort ws_xpixel;
			ushort ws_ypixel;
		}
		private int tcgetattr(int fd, termios *termios_p);
		private int tcsetattr(int fd, int a, termios *termios_p);
		private int ioctl(int fd, ulong request, ...);
	}
	private enum TERM_ATTR = ~ICANON & ~ECHO;
	private termios old_tio = void, new_tio = void;
	private enum SIGWINCH = 28;
//	alias CONCHAR = char;
}

/// User defined function for resize events
private
void function(ushort,ushort) adbg_term_resize_handler;

enum TermConfig {
	ReadlineNoReturn = 1 << 0,
}

private int term_config; // default to 0

//
// ANCHOR Initiation
//

/// Initiates terminal basics
/// Returns: Error code, non-zero on error
int adbg_term_init() {
	version (Posix) {
		tcgetattr(STDIN_FILENO, &old_tio);
		new_tio = old_tio;
		new_tio.c_lflag &= TERM_ATTR;

		//TODO: See flags we can put
		// tty_ioctl TIOCSETD
	} else {
		handleOut = GetStdHandle(STD_OUTPUT_HANDLE);
		handleIn  = GetStdHandle(STD_INPUT_HANDLE);
	}
	return 0;
}

int adbg_term_tui_init() {
	version (Windows) {
		handleOld = handleOut;
		handleOut = CreateConsoleScreenBuffer(
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			CONSOLE_TEXTMODE_BUFFER,
			NULL);
		if (handleOut == INVALID_HANDLE_VALUE || handleOut == NULL)
			return 1;
		if (SetConsoleMode(handleOut, 0) == FALSE)
			return 2;
		if (SetConsoleActiveScreenBuffer(handleOut) == FALSE)
			return 3;
		WindowSize ws = void;
		adbg_term_size(&ws);
		if (adbg_term_init_buffer(&ws))
			return 4;
	}
	return 0;
}

void adbg_term_config(int flags) {
	term_config = flags;
}

/// Restore console buffer
/*void adbg_term_restore() {
	version (Windows) {
		SetConsoleActiveScreenBuffer(hOld);
	}
}*/

/// Set terminal window resize event handler
/// Params: f = Handler function
void adbg_term_event_resize(void function(ushort,ushort) f) {
	version (Windows) {
		adbg_term_resize_handler = f;
	} else
	version (Posix) {
		//TODO: SIGWINCH : Signal Window change
		sigaction_t sa;
		sa.sa_handler = &adbg_term_event_resize_posix;
		sigaction(SIGWINCH, &sa, cast(sigaction_t*)0);
	}
}

/// Internal Posix function for handling initial resize signal
version (Posix) private
void adbg_term_event_resize_posix(int) {
	WindowSize ws = void;
	adbg_term_size(&ws);
	adbg_term_resize_handler(ws.width, ws.height);
}

/**
 * Initiate terminal intermediate screen buffer. (Windows) This can be used
 * after a resive event, but it's done automatically. (Posix) No-op
 * Params:
 * 	s = Terminal window size
 */
private
int adbg_term_init_buffer(WindowSize *s) {
	import core.stdc.stdlib : realloc, malloc;
	version (Windows) {
		const size_t bsize = s.height * s.width;
		// lpBuffer
		ibuf = cast(CHAR_INFO*)realloc(ibuf,
			CHAR_INFO.sizeof * bsize);
		// dwBufferSize
		ibuf_size.X = s.width;
		ibuf_size.Y = s.height;
		// dwBufferCoord
		//cbuffer_coord.X =
		//cbuffer_coord.Y = 0;
		// lpWriteRegion
		//ibuf_rect.Top = ibuf_rect.Left = 0;
		ibuf_rect.Right  = cast(short)(s.width - 1);
		ibuf_rect.Bottom = cast(short)(s.height - 1);
		// init
		CONSOLE_SCREEN_BUFFER_INFO csbi = void;
		GetConsoleScreenBufferInfo(handleOut, &csbi);
		for (size_t i; i < bsize; ++i) {
			ibuf[i].AsciiChar = ' ';
			ibuf[i].Attributes = csbi.wAttributes;
			/*	BACKGROUND_BLUE |
				FOREGROUND_INTENSITY |
				FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;*/
		}
	}
	return 0;
}

/// Invert console color with defaultColor
/*void adbg_term_color_invert() {
	version (Windows)
		SetConsoleTextAttribute(hOut, COMMON_LVB_REVERSE_VIDEO | defaultColor);
	version (Posix)
		fputs("\033[7m", stdout);
}

/// Reset console color to defaultColor
void adbg_term_color_reset() {
	version (Windows)
		SetConsoleTextAttribute(hOut, defaultColor);
	version (Posix)
		fputs("\033[0m", stdout);
}*/

/// Clear screen
void adbg_term_clear() {
	version (Windows) {
		CONSOLE_SCREEN_BUFFER_INFO csbi = void;
		COORD c; // 0, 0
		GetConsoleScreenBufferInfo(handleOut, &csbi);
		//const int size = csbi.dwSize.X * csbi.dwSize.Y; buffer size
		const int size = // window size
			(csbi.srWindow.Right - csbi.srWindow.Left + 1)* // width
			(csbi.srWindow.Bottom - csbi.srWindow.Top + 1); // height
		DWORD num = void; // kind of ala .NET
		FillConsoleOutputCharacterA(handleOut, ' ', size, c, &num);
		FillConsoleOutputAttribute(handleOut, csbi.wAttributes, size, c, &num);
		adbg_term_curpos(0, 0);
	} else version (Posix) {
		WindowSize ws = void;
		adbg_term_size(&ws);
		//TODO: write term's 'default' attribute character
		immutable const(char) *empty = "";
		printf("\033[0;0H%*s\033[0;0H", ws.height * ws.width, empty);
	}
	else static assert(0, "Clear: Not implemented");
}

/**
 * Get current window size
 * Params: ws = Pointer to a WindowSize structure
 *
 * Note: A COORD uses SHORT (short) and Linux uses unsigned shorts.
 */
void adbg_term_size(WindowSize *ws) {
	version (Windows) {
		CONSOLE_SCREEN_BUFFER_INFO c = void;
		GetConsoleScreenBufferInfo(handleOut, &c);
		ibuf_w = ws.width =
			cast(ushort)(c.srWindow.Right - c.srWindow.Left + 1);
		ibuf_h = ws.height =
			cast(ushort)(c.srWindow.Bottom - c.srWindow.Top + 1);
	} else
	version (Posix) {
		winsize w = void;
		ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
		ws.width  = w.ws_col;
		ws.height = w.ws_row;
	}
}

/**
 * Set cursor position x and y position respectively from the top left corner,
 * 0-based.
 * Params:
 *   x = X position (horizontal)
 *   y = Y position (vertical)
 */
void adbg_term_curpos(int x, int y) {
	version (Windows) { // 0-based
		COORD c = { cast(SHORT)x, cast(SHORT)y };
		SetConsoleCursorPosition(handleOut, c);
	} else
	version (Posix) { // 1-based
		printf("\033[u;%uH", y + 1, x + 1);
	}
}

void adbg_term_get_curpos(int *x, int *y) {
	version (Windows) { // 0-based
		CONSOLE_SCREEN_BUFFER_INFO csbi = void;
		GetConsoleScreenBufferInfo(handleOut, &csbi);
		*x = csbi.dwCursorPosition.X;
		*y = csbi.dwCursorPosition.Y;
	} else
	version (Posix) { // 1-based
		printf("\033[6n");
		fscanf(stdin, "\033[%d;%dmR", y, x);
		--*y; --*x;
	}
}


//
// ANCHOR TUI specifics
//

void adbg_term_tui_curpos(int x, int y) {
	version (Windows) { // 0-based
		ibuf_x = cast(ushort)x;
		ibuf_y = cast(ushort)y;
	} else
	version (Posix) { // 1-based
		printf("\033[u;%uH", y + 1, x + 1);
	}
}

void adbg_term_tui_get_curpos(int *x, int *y) {
	version (Windows) { // 0-based
		*x = ibuf_x;
		*y = ibuf_y;
	} else
	version (Posix) { // 1-based
		adbg_term_get_curpos(x, y);
	}
}

/**
 *
 *
 */
void adbg_term_tui_write(const(char) *s) {
	version (Windows) {
		size_t si, bi = (ibuf_w * ibuf_y) + ibuf_x;
		while (s[si]) {
			ibuf[bi].AsciiChar = s[si];
			++bi; ++si;
		}
	} else {
		fputs(s, stdout);
	}
}

/**
 *
 *
 */
void adbg_term_tui_writef(const(char) *f, ...) {
	import core.stdc.stdarg : va_list, va_start;
	char [1024]buf = void;
	va_list va = void;
	va_start(va, f);
	vsnprintf(cast(char*)buf, 1024, f, va);
	adbg_term_tui_write(cast(char*)buf);
}

/**
 *
 */
void adbg_term_tui_flush() {
	version (Windows) {
		WriteConsoleOutputA(handleOut,
			ibuf, ibuf_size, ibuf_pos, &ibuf_rect);
	} else fflush(stdout);
}

void adbg_term_tui_clear() {
	version (Windows) {
		size_t m = ibuf_w * ibuf_h;
		for (size_t i; i < m; ++i) {
			ibuf[i].AsciiChar = ' ';
		}
	} else version (Posix) {
		adbg_term_clear;
	}
	else static assert(0, "Clear: Not implemented");
}

//
// ANCHOR Terminal input
//

/**
 * Read a single terminal event (keyboard or mouse). Window resize events
 * are handled externally. (Windows) If the EventType is WINDOW_BUFFER_SIZE_EVENT:
 * this calls the user's handler function. (Posix) Entirely handled externally
 * via the SIGWINCH signal.
 * Params: ii = InputInfo structure
 */
void adbg_term_read(InputInfo *ii) {
	//TODO: consider memset
	ii.type = InputType.None;
	version (Windows) {
		INPUT_RECORD ir = void;
		DWORD dum = void;

		if (ReadConsoleInput(handleIn, &ir, 1, &dum) == FALSE)
			return;

		switch (ir.EventType) {
		case KEY_EVENT:
			with (ii)
			if (ir.KeyEvent.bKeyDown) {
				type = InputType.Key;
				key.keyChar  = ir.KeyEvent.AsciiChar;
				key.keyCode  = cast(Key)ir.KeyEvent.wVirtualKeyCode;
				const DWORD state = ir.KeyEvent.dwControlKeyState;
				key.alt   = (state & ALT_PRESSED)   != 0;
				key.ctrl  = (state & CTRL_PRESSED)  != 0;
				key.shift = (state & SHIFT_PRESSED) != 0;
			}
			break;
		case MOUSE_EVENT: //TODO: MOUSE_EVENT
			
			break;
		case WINDOW_BUFFER_SIZE_EVENT:
			with (ir)
			if (adbg_term_resize_handler)
				adbg_term_resize_handler(
					WindowBufferSizeEvent.dwSize.X,
					WindowBufferSizeEvent.dwSize.Y);
			FlushConsoleInputBuffer(handleIn);
			break;
		default:
		}
	} else
	version (Posix) {
		//TODO: Get modifier keys states
		// or better yet
		//TODO: See console_ioctl for KDGETKEYCODE
		// https://linux.die.net/man/4/console_ioctl

		ii.type = InputType.Key;

		tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);

		uint c = getchar;

		with (ii.key)
		switch (c) {
		case '\n', 'M': // \n (RETURN) or M (ENTER)
			keyCode = Key.Enter;
			goto L_END;
		case 27: // ESC
			switch (c = getchar) {
			case '[':
				switch (c = getchar) {
				case 'A': keyCode = Key.UpArrow; goto L_END;
				case 'B': keyCode = Key.DownArrow; goto L_END;
				case 'C': keyCode = Key.RightArrow; goto L_END;
				case 'D': keyCode = Key.LeftArrow; goto L_END;
				case 'F': keyCode = Key.End; goto L_END;
				case 'H': keyCode = Key.Home; goto L_END;
				// There is an additional getchar due to the pending '~'
				case '2': keyCode = Key.Insert; getchar; goto L_END;
				case '3': keyCode = Key.Delete; getchar; goto L_END;
				case '5': keyCode = Key.PageUp; getchar; goto L_END;
				case '6': keyCode = Key.PageDown; getchar; goto L_END;
				default: goto L_DEFAULT;
				} // [
			default: goto L_DEFAULT;
			} // ESC
		case 0x08, 0x7F: // backspace
			keyCode = Key.Backspace;
			goto L_END;
		case 23: // #
			keyCode = Key.NoName;
			keyChar = '#';
			goto L_END;
		default:
			if (c >= 'a' && c <= 'z') {
				keyCode = cast(Key)(c - 32);
				keyChar = cast(char)c;
				goto L_END;
			} else if (c >= 20 && c <= 126) {
				keyCode = cast(Key)c;
				keyChar = cast(char)c;
				goto L_END;
			}
		}

L_DEFAULT:
		ii.key.keyCode = cast(Key)c;

L_END:
		tcsetattr(STDIN_FILENO,TCSANOW, &old_tio);
	}
}

size_t adbg_term_readline(char *buffer, const size_t size) {
	size_t index, len;
	InputInfo input = void;
	int curx, cury;
	adbg_term_get_curpos(&curx, &cury);
L_READKEY:
	adbg_term_read(&input);
	if (input.type != InputType.Key) goto L_READKEY;
	with (Key)
	switch (input.key.keyCode) {
	case LeftArrow:
	
		break;
	case RightArrow:
	
		break;
	case Backspace:
		if (index > 0) {
			buffer[index--] = 0;
			--len;
		}
		break;
	case Enter:
		if (term_config & TermConfig.ReadlineNoReturn) {
			buffer[len] = 0;
		} else {
			putchar('\n');
			buffer[++len] = '\n';
			buffer[len+1] = 0;
		}
		return len;
	default:
		char c = input.key.keyChar;
		if (c >= 20 && c <= 126) {
			if (index + 1 < size) {
				buffer[index++] = c;
				++len;
				putchar(c);
			}
		}
	}
	
	goto L_READKEY;
}

/// Key information structure
struct KeyInfo {
	Key   keyCode;	/// Key code.
	char  keyChar;	/// Character.
	ubyte ctrl;	/// If either CTRL was held down.
	ubyte alt;	/// If either ALT was held down.
	ubyte shift;	/// If SHIFT was held down.
}
/// Mouse input event structure
struct MouseInfo {
	ushort x, y;
}
/// Global input event structure
struct InputInfo {
	InputType type;	/// Input event type, can only be mouse or key
	union {
		KeyInfo key;	/// Keyboard event structure
		MouseInfo mouse;	/// Mouse event structure
	}
}

/// Window structure
struct WindowSize {
	ushort width;	/// Width in characters
	ushort height;	/// Height in characters
}

/// Input type for InputInfo structure
enum InputType : ushort {
	None, Key, Mouse
}
/*
enum MouseButton : ushort { // Windows compilant
	Left = 1, Right = 2, Middle = 4, Mouse4 = 8, Mouse5 = 16
}

enum MouseState : ushort { // Windows compilant
	RightAlt = 1, LeftAlt = 2, RightCtrl = 4,
	LeftCtrl = 8, Shift = 0x10, NumLock = 0x20,
	ScrollLock = 0x40, CapsLock = 0x80, EnhancedKey = 0x100
}

enum MouseEventType { // Windows compilant
	Moved = 1, DoubleClick = 2, Wheel = 4, HorizontalWheel = 8
}
*/
/// Key codes mapping.
enum Key : ushort {
	Backspace = 8,
	Tab = 9,
	Clear = 12,
	Enter = 13,
	Pause = 19,
	Escape = 27,
	Spacebar = 32,
	PageUp = 33,
	PageDown = 34,
	End = 35,
	Home = 36,
	LeftArrow = 37,
	UpArrow = 38,
	RightArrow = 39,
	DownArrow = 40,
	Select = 41,
	Print = 42,
	Execute = 43,
	PrintScreen = 44,
	Insert = 45,
	Delete = 46,
	Help = 47,
	D0 = 48,
	D1 = 49,
	D2 = 50,
	D3 = 51,
	D4 = 52,
	D5 = 53,
	D6 = 54,
	D7 = 55,
	D8 = 56,
	D9 = 57,
	A = 65,
	B = 66,
	C = 67,
	D = 68,
	E = 69,
	F = 70,
	G = 71,
	H = 72,
	I = 73,
	J = 74,
	K = 75,
	L = 76,
	M = 77,
	N = 78,
	O = 79,
	P = 80,
	Q = 81,
	R = 82,
	S = 83,
	T = 84,
	U = 85,
	V = 86,
	W = 87,
	X = 88,
	Y = 89,
	Z = 90,
	LeftMeta = 91,
	RightMeta = 92,
	Applications = 93,
	Sleep = 95,
	NumPad0 = 96,
	NumPad1 = 97,
	NumPad2 = 98,
	NumPad3 = 99,
	NumPad4 = 100,
	NumPad5 = 101,
	NumPad6 = 102,
	NumPad7 = 103,
	NumPad8 = 104,
	NumPad9 = 105,
	Multiply = 106,
	Add = 107,
	Separator = 108,
	Subtract = 109,
	Decimal = 110,
	Divide = 111,
	F1 = 112,
	F2 = 113,
	F3 = 114,
	F4 = 115,
	F5 = 116,
	F6 = 117,
	F7 = 118,
	F8 = 119,
	F9 = 120,
	F10 = 121,
	F11 = 122,
	F12 = 123,
	F13 = 124,
	F14 = 125,
	F15 = 126,
	F16 = 127,
	F17 = 128,
	F18 = 129,
	F19 = 130,
	F20 = 131,
	F21 = 132,
	F22 = 133,
	F23 = 134,
	F24 = 135,
	BrowserBack = 166,
	BrowserForward = 167,
	BrowserRefresh = 168,
	BrowserStop = 169,
	BrowserSearch = 170,
	BrowserFavorites = 171,
	BrowserHome = 172,
	VolumeMute = 173,
	VolumeDown = 174,
	VolumeUp = 175,
	MediaNext = 176,
	MediaPrevious = 177,
	MediaStop = 178,
	MediaPlay = 179,
	LaunchMail = 180,
	LaunchMediaSelect = 181,
	LaunchApp1 = 182,
	LaunchApp2 = 183,
	Oem1 = 186,
	OemPlus = 187,
	OemComma = 188,
	OemMinus = 189,
	OemPeriod = 190,
	Oem2 = 191,
	Oem3 = 192,
	Oem4 = 219,
	Oem5 = 220,
	Oem6 = 221,
	Oem7 = 222,
	Oem8 = 223,
	Oem102 = 226,
	Process = 229,
	Packet = 231,
	Attention = 246,
	CrSel = 247,
	ExSel = 248,
	EraseEndOfFile = 249,
	Play = 250,
	Zoom = 251,
	NoName = 252,
	Pa1 = 253,
	OemClear = 254
}