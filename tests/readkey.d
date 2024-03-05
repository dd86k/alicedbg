module tests.readkey;

import term;
import core.stdc.stdio;

unittest {
	coninit();
	InputInfo input = void;
	puts("Press ^C to quit");
	puts("Reading keys...");
loop:
	conrdkey(&input);
	switch (input.type) {
	case InputType.Key:
		with (input.key)
		printf("key: v=%3d:%3d k=%3d ctrl=%d shift=%d alt=%d\n",
			keyCode, keyChar, keyCode, ctrl, shift, alt);
		break;
	case InputType.Mouse:
		puts("mouse");
		break;
	case InputType.None:
		puts("none");
		break;
	default:
		puts("unknown");
	}
	goto loop;
}