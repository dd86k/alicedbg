module tests.general;

import core.stdc.stdio;
import core.stdc.string;

/// 
unittest {
	import adbg.utils.string : adbg_string_t;
	
	enum BUFFER_SIZE = 80;
	enum LAST_ITEM = BUFFER_SIZE - 1;
	
	char[BUFFER_SIZE] buffer = void;
	
	// init
	
	printf("adbg_string_t: ");
	adbg_string_t s = adbg_string_t(buffer.ptr, BUFFER_SIZE);
	assert(s.size == BUFFER_SIZE);
	assert(s.length  == 0);
	assert(s.str  == &buffer[0]);
	puts("OK");
	
	// reset
	
	printf("adbg_string_t.reset: ");
	s.length = 3;
	s.reset(true);
	assert(buffer[0] == 0);
	assert(buffer[1] == 0);
	assert(buffer[LAST_ITEM] == 0);
	assert(s.length == 0);
	puts("OK");
	
	// add(char)
	
	s.reset();
	printf("adbg_string_t.add 'a': ");
	assert(s.addc('a') == false);
	assert(buffer[0] == 'a');
	assert(buffer[1] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.add multiple: ");
	assert(s.addc('a') == false);
	assert(s.addc('b') == false);
	assert(s.addc('c') == false);
	assert(strcmp(s.str, "abc") == 0);
	puts("OK");
	
	// add(string)
	
	s.reset();
	printf("adbg_string_t.add hello: ");
	assert(s.adds("hello") == false);
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
	
	s.reset();
	printf("adbg_string_t.add big text: ");
	immutable string lorem =
		`Lorem ipsum dolor sit amet, consectetur adipiscing elit. `~
		`Etiam dignissim iaculis lectus. Aliquam volutpat rhoncus dignissim. `~
		`Donec maximus diam eros, a euismod quam consectetur sit amet. `~
		`Morbi vel ante viverra, condimentum elit porttitor, tempus metus. `~
		`Cras eget interdum turpis, vitae egestas ipsum. `~
		`Nam accumsan aliquam enim, id sodales tellus hendrerit id. `~
		`Proin vulputate hendrerit accumsan. Etiam vitae tempor libero.`;
	assert(lorem.length > s.size);
	assert(s.adds(lorem.ptr));
	assert(buffer[0] == 'L');
	puts("OK");
	
	s.reset(true);
	printf("adbg_string_t.add multi text: ");
	s.adds("123");
	s.adds("abc");
	assert(strcmp(s.str, "123abc") == 0);
	puts("OK");
	
	// addx8
	
	s.reset();
	printf("adbg_string_t.addx8: ");
	assert(s.addx8(0xe0) == false);
	assert(buffer[0] == 'e');
	assert(buffer[1] == '0');
	assert(buffer[2] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx8 0 false: ");
	assert(s.addx8(0) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx8 0 true: ");
	assert(s.addx8(0, true) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == '0');
	assert(buffer[2] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx8 0x3 false: ");
	assert(s.addx8(0xe) == false);
	assert(buffer[0]  == 'e');
	assert(buffer[1] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx8 0x3 true: ");
	assert(s.addx8(0xe, true) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == 'e');
	assert(buffer[2] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx8 multiple: ");
	assert(s.addx8(0x80) == false);
	assert(s.addx8(0x86) == false);
	assert(buffer[0] == '8');
	assert(buffer[1] == '0');
	assert(buffer[2] == '8');
	assert(buffer[3] == '6');
	assert(buffer[4] == 0);
	puts("OK");
	
	// addx16
	
	s.reset();
	printf("adbg_string_t.addx16: ");
	assert(s.addx16(0xabcd) == false);
	assert(buffer[0] == 'a');
	assert(buffer[1] == 'b');
	assert(buffer[2] == 'c');
	assert(buffer[3] == 'd');
	assert(buffer[4] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx16 false: ");
	assert(s.addx16(0xff) == false);
	assert(buffer[0] == 'f');
	assert(buffer[1] == 'f');
	assert(buffer[2] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx16 true: ");
	assert(s.addx16(0xee, true) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == '0');
	assert(buffer[2] == 'e');
	assert(buffer[3] == 'e');
	assert(buffer[4] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx16 0 false: ");
	assert(s.addx16(0) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx16 0 true: ");
	assert(s.addx16(0, true) == false);
	assert(buffer[0] == '0');
	assert(buffer[1] == '0');
	assert(buffer[2] == '0');
	assert(buffer[3] == '0');
	assert(buffer[4] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx16 0x8086: ");
	assert(s.addx16(0x8086) == false);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '8');
	assert(buffer[3]  == '6');
	assert(buffer[4] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx16 multiple: ");
	assert(s.addx16(0x80) == false);
	assert(s.addx16(0x86) == false);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '8');
	assert(buffer[3]  == '6');
	assert(buffer[4] == 0);
	puts("OK");
	
	// addx32
	
	s.reset();
	printf("adbg_string_t.addx32: ");
	assert(s.addx32(0x1234_abcd) == false);
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
	
	s.reset();
	printf("adbg_string_t.addx32 false: ");
	assert(s.addx32(0xed) == false);
	assert(buffer[0]  == 'e');
	assert(buffer[1]  == 'd');
	assert(buffer[2] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx32 true: ");
	assert(s.addx32(0xcc, true) == false);
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
	
	s.reset();
	printf("adbg_string_t.addx32 0 false: ");
	assert(s.addx32(0) == false);
	assert(buffer[0]  == '0');
	assert(buffer[1] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx32 0 true: ");
	assert(s.addx32(0, true) == false);
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
	
	s.reset();
	printf("adbg_string_t.addx32 0x80486: ");
	assert(s.addx32(0x80486) == false);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '4');
	assert(buffer[3]  == '8');
	assert(buffer[4]  == '6');
	assert(buffer[5] == 0);
	puts("OK");
	
	// addx64
	
	s.reset();
	printf("adbg_string_t.addx64: ");
	assert(s.addx64(0xdd86_c0ff_ee08_0486) == false);
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
	
	s.reset();
	printf("adbg_string_t.addx64 false: ");
	assert(s.addx64(0xbb) == false);
	assert(buffer[0]  == 'b');
	assert(buffer[1]  == 'b');
	assert(buffer[2]  == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx64 0xdd: ");
	assert(s.addx64(0xdd, true) == false);
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
	
	s.reset();
	printf("adbg_string_t.addx64 0 false: ");
	assert(s.addx64(0) == false);
	assert(buffer[0]  == '0');
	assert(buffer[1] == 0);
	puts("OK");
	
	s.reset();
	printf("adbg_string_t.addx64 0 true: ");
	assert(s.addx64(0, true) == false);
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
	
	s.reset();
	printf("adbg_string_t.addx64 0x80960: ");
	assert(s.addx64(0x80960) == false);
	assert(buffer[0]  == '8');
	assert(buffer[1]  == '0');
	assert(buffer[2]  == '9');
	assert(buffer[3]  == '6');
	assert(buffer[4]  == '0');
	assert(buffer[5] == 0);
	puts("OK");
}