module tests.easy.target;

import core.thread : Thread;
import std.datetime : dur;

void main(string[] args) {
	if (args.length > 1) Thread.sleep(dur!"msecs"(500));
	
	void function() bad;
	bad();
}