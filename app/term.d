/// In-house console/terminal library
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module term;

import core.stdc.stdlib;
import core.stdc.stdio;

//TODO: Consider using PDCurses instead

// NOTE: Functions prefixed with "con" to avoid clashing with the "tc" POSIX stuff

extern (C):

private int putchar(int);
private int getchar();

version (Windows) {
	private import core.sys.windows.windows;
	private enum ALT_PRESSED =  RIGHT_ALT_PRESSED  | LEFT_ALT_PRESSED;
	private enum CTRL_PRESSED = RIGHT_CTRL_PRESSED | LEFT_CTRL_PRESSED;
	private __gshared HANDLE handleIn, handleOut, handleOld;
} else version (Posix) {
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
	version (CRuntime_Bionic) {
		private int tcgetattr(int __fd, termios* __t);
		private int tcsetattr(int __fd, int __optional_actions, termios* __t);
	}
	
	private enum TERM_ATTR = ~(ICANON | ECHO);
	private enum SIGWINCH = 28;
	private __gshared termios old_tio = void, new_tio = void;
}

// Flags: CONFxyz

private __gshared {
	/// User defined function for resize events
	void function(ushort,ushort) term_resize_handler;
	int term_opts; // default to 0
}

//
// ANCHOR Initiation
//

/// Initiates terminal basics
/// Returns: Error keyCode, non-zero on error
int coninit(int flags = 0) {
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

// Invert console color with defaultColor
/*void thcolin() {
	version (Windows)
		SetConsoleTextAttribute(hOut, COMMON_LVB_REVERSE_VIDEO | defaultColor);
	version (Posix)
		fputs("\033[7m", stdout);
}

// Reset console color to defaultColor
void thcolrst() {
	version (Windows)
		SetConsoleTextAttribute(hOut, defaultColor);
	version (Posix)
		fputs("\033[0m", stdout);
}*/

/// Clear screen
void conclear() {
version (Windows) {
	CONSOLE_SCREEN_BUFFER_INFO csbi = void;
	COORD c; // 0, 0
	GetConsoleScreenBufferInfo(handleOut, &csbi);
	//const int buflen = csbi.dwSize.X * csbi.dwSize.Y; buf buflen
	const int buflen = // window buflen
		(csbi.srWindow.Right - csbi.srWindow.Left + 1)* // width
		(csbi.srWindow.Bottom - csbi.srWindow.Top + 1); // height
	DWORD num = void; // kind of ala .NET
	FillConsoleOutputCharacterA(handleOut, ' ', buflen, c, &num);
	FillConsoleOutputAttribute(handleOut, csbi.wAttributes, buflen, c, &num);
	conmvcur(0, 0);
} else version (Posix) {
	// "ESC [ 2 J" acts like clear(1)
	// "ESC c" is a full reset ala cls (Windows)
	printf("\033c");
}
else static assert(false, "Not implemented");
}

/// Get host console screen size.
/// Params:
///   w = Width (columns) pointer.
///   h = Height (rows) pointer.
void consize(int *w, int *h) {
	/// NOTE: A COORD uses SHORT (short) and Linux uses unsigned shorts.
version (Windows) {
	CONSOLE_SCREEN_BUFFER_INFO c = void;
	GetConsoleScreenBufferInfo(handleOut, &c);
	*w = c.srWindow.Right - c.srWindow.Left + 1;
	*h = c.srWindow.Bottom - c.srWindow.Top + 1;
} else version (Posix) {
	winsize w = void;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	*w = w.ws_col;
	*h = w.ws_row;
}
}

/// Set cursor position.
///
/// Coordonates start at zero.
/// Params:
///   x = X position (horizontal, columns)
///   y = Y position (vertical, rows)
void conmvcur(int x, int y) {
version (Windows) { // 0-based
	COORD c = { cast(SHORT)x, cast(SHORT)y };
	SetConsoleCursorPosition(handleOut, c);
} else version (Posix) { // 1-based
	printf("\033[%d;%dH", y + 1, x + 1);
}
}

/// Get cursor position.
///
/// Coordonates start at zero.
/// Params:
///   x = X position (horizontal, columns)
///   y = Y position (vertical, rows)
void congetxy(int *x, int *y) {
version (Windows) { // 0-based
	CONSOLE_SCREEN_BUFFER_INFO csbi = void;
	GetConsoleScreenBufferInfo(handleOut, &csbi);
	*x = csbi.dwCursorPosition.X;
	*y = csbi.dwCursorPosition.Y;
} else version (Posix) { // 1-based
	tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
	printf("\033[6n");
	scanf("\033[%d;%dR", y, x); // row, col
	tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
	--*x;
	--*y;
}
}

//
// ANCHOR Terminal input
//

/// Read a single immediate terminal/console event such as a keyboard or mouse.
///
/// Window resize events are handled externally.
/// Windows: User handler function called if EventType is WINDOW_BUFFER_SIZE_EVENT.
/// Posix: Handled externally via the SIGWINCH signal.
/// Params: ii = InputInfo structure
void conrdkey(InputInfo *ii) {
	ii.type = InputType.None;
version (Windows) {
	INPUT_RECORD ir = void;
	DWORD d = void;
L_READ_AGAIN:
	if (ReadConsoleInput(handleIn, &ir, 1, &d) == FALSE)
		return;

	switch (ir.EventType) {
	case KEY_EVENT:
		if (ir.KeyEvent.bKeyDown == FALSE)
			goto L_READ_AGAIN;
		
		with (ii) {
		type = InputType.Key;
		const DWORD state = ir.KeyEvent.dwControlKeyState;
		key.alt   = (state & ALT_PRESSED)   != 0;
		key.ctrl  = (state & CTRL_PRESSED)  != 0;
		key.shift = (state & SHIFT_PRESSED) != 0;
		key.keyChar = ir.KeyEvent.AsciiChar;
		key.keyCode = key.ctrl ?
			cast(Key)ir.KeyEvent.AsciiChar :
			cast(Key)ir.KeyEvent.wVirtualKeyCode;
		}
		break;
	case MOUSE_EVENT: //TODO: MOUSE_EVENT
		ii.type = InputType.Mouse;
		break;
	case WINDOW_BUFFER_SIZE_EVENT:
		with (ir)
		if (term_resize_handler)
			term_resize_handler(
				WindowBufferSizeEvent.dwSize.X,
				WindowBufferSizeEvent.dwSize.Y);
		FlushConsoleInputBuffer(handleIn);
		break;
	default: // Menu and Focus events
		goto L_READ_AGAIN;
	}
} else version (Posix) {
	//TODO: Get modifier keys states
	//TODO: See console_ioctl for KDGETKEYCODE
	//      https://linux.die.net/man/4/console_ioctl

	ii.type = InputType.Key;

	tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
	scope(exit) tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);

	uint c = getchar;

	with (ii.key)
	switch (c) {
	case 0: keyCode = Key.Null; return;
	case 1: keyCode = Key.HeadingStart; return;
	case 2: keyCode = Key.TextStart; return;
	case 3: /* ^C */ keyCode = Key.TextEnd; return;
	case 4: /* ^D */ keyCode = Key.TransmissionEnd; return;
	case 5: keyCode = Key.Enquiry; return;
	case 6: keyCode = Key.Acknowledge; return;
	case 7: keyCode = Key.Bell; return;
	case '\n', '\r': // \n (RETURN) or \r (ENTER)
		keyCode = Key.Enter;
		return;
	case 27: // ESC
		switch (c = getchar) {
		case '[':
			switch (c = getchar) {
			case 'A': keyCode = Key.UpArrow; return;
			case 'B': keyCode = Key.DownArrow; return;
			case 'C': keyCode = Key.RightArrow; return;
			case 'D': keyCode = Key.LeftArrow; return;
			case 'F': keyCode = Key.End; return;
			case 'H': keyCode = Key.Home; return;
			// There is an additional getchar due to the pending '~'
			case '2': keyCode = Key.Insert; getchar; return;
			case '3': keyCode = Key.Delete; getchar; return;
			case '5': keyCode = Key.PageUp; getchar; return;
			case '6': keyCode = Key.PageDown; getchar; return;
			default: goto L_DEFAULT;
			} // [
		default: goto L_DEFAULT;
		} // ESC
	case 0x08, 0x7F: // backspace
		keyCode = Key.Backspace;
		return;
	case 23: // #
		keyCode = Key.NumSign;
		keyChar = '#';
		return;
	default:
		if (c >= 'a' && c <= 'z') {
			keyCode = cast(Key)(c - 32);
			keyChar = cast(char)c;
			return;
		} else if (c >= 20 && c <= 126) {
			keyCode = cast(Key)c;
			keyChar = cast(char)c;
			return;
		}
	}

L_DEFAULT:
	ii.key.keyCode = cast(Key)c;
} // version (Posix)
}

/// Read a line from stdin.
/// Returns: Character slice; Or null on error.
char[] conrdln() {
	import core.stdc.ctype : isprint;
	
	// GNU readline has this set to 512
	enum BUFFERSIZE = 1024;
	
	__gshared char* buffer;
	
	if (buffer == null) {
		buffer = cast(char*)malloc(BUFFERSIZE);
		if (buffer == null)
			return null;
	}
	
	// NOTE: stdin is line-buffered by the host console in their own buffer.
	//       Hitting return or enter makes the console write its buffer to stdin.
	//       Reading stdin, we copy until we see a newline.
	size_t len;
	while (len < BUFFERSIZE) {
		int c = getchar();
		if (c == '\n' || c == EOF)
			break;
		buffer[len++] = cast(char)c;
	}
	buffer[len] = 0;
	return buffer[0..len];
}

/// Key information structure
struct KeyInfo {
	Key  keyCode;	/// Key keyCode.
	char keyChar;	/// Character.
	bool ctrl;	/// If either CTRL was held down.
	bool alt;	/// If either ALT was held down.
	bool shift;	/// If SHIFT was held down.
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
//TODO: Redo keycodes
//      < 128: ascii map
//      >=128: special codes (e.g., arrow keys)
enum Key : short {
	Null = 0,	/// ^@, NUL
	HeadingStart = 1,	// ^A, SOH
	TextStart = 2,	/// ^B, STX
	TextEnd = 3,	/// ^C, ETX
	TransmissionEnd = 4,	/// ^D, EOT
	Enquiry = 5, 	/// ^E, ENQ
	Acknowledge = 6,	/// ^F, ACK
	Bell = 7,	/// ^G, BEL
	Backspace = 8,	/// ^H, BS
	Tab = 9,	/// ^I, HT
	LineFeed = 10,	/// ^J, LF
	VerticalTab = 11,	/// ^K, VT
	FormFeed = 12,	/// ^L, FF
	Enter = 13,	/// ^M, CR (return key)
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
	NumSign = 252,	/// #
	Pa1 = 253,
	OemClear = 254
}