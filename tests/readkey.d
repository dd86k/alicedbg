module tests.readkey;

import std.stdio;
import term;
import core.stdc.stdio;
import core.stdc.string;

unittest {
	term_init;
	InputInfo input = void;
	bool cont = true; /// continue
	do {
		term_read(&input);
		switch (input.type) {
		case InputType.Key:
			KeyInfo k = input.key;
			writefln("key: v=%3d:%3d k=%-10s ctrl=%d shift=%d alt=%d",
				k.keyCode, k.keyChar, k.keyCode, k.ctrl, k.shift, k.alt);
			break;
		case InputType.Mouse:
			writeln("mouse");
			break;
		case InputType.None:
			writeln("none");
			break;
		default:
			writeln("unknown");
		}
	} while (cont);
}