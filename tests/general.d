module tests.general;

import core.stdc.stdio;
import core.stdc.string;

/// 
unittest {
	import adbg.utils.str : adbg_string_t;
	
	enum BUFFER_SIZE = 64;
	
	char[BUFFER_SIZE] buffer = void;
	
	// init
	
	printf("adbg_string_t: ");
	adbg_string_t s = adbg_string_t(buffer.ptr, BUFFER_SIZE);
	assert(s.left == BUFFER_SIZE - 1);
	assert(s.size == BUFFER_SIZE - 1);
	assert(s.pos  == 0);
	assert(s.str  == &buffer[0]);
	puts("OK");
	
	// reset
	
	printf("adbg_string_t.reset: ");
	s.pos = 3;
	s.left = BUFFER_SIZE - 3;
	s.reset(true);
	assert(buffer[0] == 0);
	assert(buffer[1] == 0);
	assert(buffer[BUFFER_SIZE - 1] == 0);
	assert(s.pos == 0);
	assert(s.left == BUFFER_SIZE - 1);
	puts("OK");
	
	// add(char)
	
	printf("adbg_string_t.add 'a': ");
	s.reset();
	s.add('a');
	assert(buffer[0] == 'a');
	assert(buffer[1] == 0);
	puts("OK");
	
	printf("adbg_string_t.add multiple: ");
	s.reset();
	s.add('a');
	s.add('b');
	s.add('c');
	assert(strcmp(s.str, "abc") == 0);
	puts("OK");
	
	// add(string)
	
	printf("adbg_string_t.add hello: ");
	s.reset();
	s.add("hello");
	assert(buffer[0] == 'h');
	assert(buffer[1] == 'e');
	assert(buffer[2] == 'l');
	assert(buffer[3] == 'l');
	assert(buffer[4] == 'o');
	assert(buffer[5] == 0);
	assert(buffer[6] == 0);
	assert(buffer[7] == 0);
	assert(buffer[8] == 0);
	puts("OK");
	
	printf("adbg_string_t.add big text: ");
	s.reset();
	assert(s.add(
		`Lorem ipsum dolor sit amet, consectetur adipiscing elit. `~
		`Etiam dignissim iaculis lectus. Aliquam volutpat rhoncus dignissim. `~
		`Donec maximus diam eros, a euismod quam consectetur sit amet. `~
		`Morbi vel ante viverra, condimentum elit porttitor, tempus metus. `~
		`Cras eget interdum turpis, vitae egestas ipsum. `~
		`Nam accumsan aliquam enim, id sodales tellus hendrerit id. `~
		`Proin vulputate hendrerit accumsan. Etiam vitae tempor libero.`));
	puts("OK");
	
	printf("adbg_string_t.add multi text: ");
	s.reset(true);
	s.add("123");
	s.add("abc");
	assert(strcmp(s.str, "123abc") == 0);
	puts("OK");
	
	// addx8
	
	printf("adbg_string_t.addx8: ");
	s.reset();
	s.addx8(0xe0);
	assert(buffer[0]  == 'e');
	assert(buffer[1]  == '0');
	assert(buffer[2] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx8 0x3 false: ");
	s.reset();
	s.addx8(0xe);
	assert(buffer[0]  == 'e');
	assert(buffer[1] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx8 0x3 true: ");
	s.reset();
	s.addx8(0xe, true);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == 'e');
	assert(buffer[2] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx8 multiple: ");
	s.reset();
	s.addx8(0x80);
	s.addx8(0x86);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '8');
	assert(buffer[3]  == '6');
	assert(buffer[4] == 0);
	puts("OK");
	
	// addx16
	
	printf("adbg_string_t.addx16: ");
	s.reset();
	s.addx16(0xabcd);
	assert(buffer[0]  == 'a');
	assert(buffer[1]  == 'b');
	assert(buffer[2]  == 'c');
	assert(buffer[3]  == 'd');
	assert(buffer[4] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx16 false: ");
	s.reset();
	s.addx16(0xff);
	assert(buffer[0]  == 'f');
	assert(buffer[1]  == 'f');
	assert(buffer[2] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx16 true: ");
	s.reset();
	s.addx16(0xee, true);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == 'e');
	assert(buffer[3]  == 'e');
	assert(buffer[4] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx16 0x0: ");
	s.reset();
	s.addx16(0, true);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '0');
	assert(buffer[3]  == '0');
	assert(buffer[4] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx16 0x8086: ");
	s.reset();
	s.addx16(0x8086);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '8');
	assert(buffer[3]  == '6');
	assert(buffer[4] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx16 multiple: ");
	s.reset();
	s.addx16(0x80);
	s.addx16(0x86);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '8');
	assert(buffer[3]  == '6');
	assert(buffer[4] == 0);
	puts("OK");
	
	// addx32
	
	printf("adbg_string_t.addx32: ");
	s.reset();
	s.addx32(0x1234_abcd);
	assert(buffer[0]  == '1');
	assert(buffer[1]  == '2');
	assert(buffer[2]  == '3');
	assert(buffer[3]  == '4');
	assert(buffer[4]  == 'a');
	assert(buffer[5]  == 'b');
	assert(buffer[6]  == 'c');
	assert(buffer[7]  == 'd');
	assert(buffer[8] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx32 false: ");
	s.reset();
	s.addx32(0xed);
	assert(buffer[0]  == 'e');
	assert(buffer[1]  == 'd');
	assert(buffer[2] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx32 true: ");
	s.reset();
	s.addx32(0xcc, true);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '0');
	assert(buffer[3]  == '0');
	assert(buffer[4]  == '0');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == 'c');
	assert(buffer[7]  == 'c');
	assert(buffer[8] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx32 0x0: ");
	s.reset();
	s.addx32(0, true);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '0');
	assert(buffer[3]  == '0');
	assert(buffer[4]  == '0');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == '0');
	assert(buffer[7]  == '0');
	assert(buffer[8] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx32 0x80486: ");
	s.reset();
	s.addx32(0x80486);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '4');
	assert(buffer[3]  == '8');
	assert(buffer[4]  == '6');
	assert(buffer[5] == 0);
	puts("OK");
	
	// addx64
	
	printf("adbg_string_t.addx64: ");
	s.reset();
	s.addx64(0xdd86_c0ff_ee08_0486);
	assert(buffer[0]  == 'd');
	assert(buffer[1]  == 'd');
	assert(buffer[2]  == '8');
	assert(buffer[3]  == '6');
	assert(buffer[4]  == 'c');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == 'f');
	assert(buffer[7]  == 'f');
	assert(buffer[8]  == 'e');
	assert(buffer[9]  == 'e');
	assert(buffer[10] == '0');
	assert(buffer[11] == '8');
	assert(buffer[12] == '0');
	assert(buffer[13] == '4');
	assert(buffer[14] == '8');
	assert(buffer[15] == '6');
	assert(buffer[16] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx64 false: ");
	s.reset();
	s.addx64(0xbb);
	assert(buffer[0]  == 'b');
	assert(buffer[1]  == 'b');
	assert(buffer[2]  == 0);
	puts("OK");
	
	printf("adbg_string_t.addx64 0xdd: ");
	s.reset();
	s.addx64(0xdd, true);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '0');
	assert(buffer[3]  == '0');
	assert(buffer[4]  == '0');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == '0');
	assert(buffer[7]  == '0');
	assert(buffer[8]  == '0');
	assert(buffer[9]  == '0');
	assert(buffer[10] == '0');
	assert(buffer[11] == '0');
	assert(buffer[12] == '0');
	assert(buffer[13] == '0');
	assert(buffer[14] == 'd');
	assert(buffer[15] == 'd');
	assert(buffer[16] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx64 0x0: ");
	s.reset();
	s.addx64(0, true);
	assert(buffer[0]  == '0');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '0');
	assert(buffer[3]  == '0');
	assert(buffer[4]  == '0');
	assert(buffer[5]  == '0');
	assert(buffer[6]  == '0');
	assert(buffer[7]  == '0');
	assert(buffer[8]  == '0');
	assert(buffer[9]  == '0');
	assert(buffer[10] == '0');
	assert(buffer[11] == '0');
	assert(buffer[12] == '0');
	assert(buffer[13] == '0');
	assert(buffer[14] == '0');
	assert(buffer[15] == '0');
	assert(buffer[16] == 0);
	puts("OK");
	
	printf("adbg_string_t.addx64 0x80960: ");
	s.reset();
	s.addx64(0x80960);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '9');
	assert(buffer[3]  == '6');
	assert(buffer[4]  == '0');
	assert(buffer[5] == 0);
	puts("OK");
}