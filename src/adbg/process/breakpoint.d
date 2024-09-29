/// Process breakpoint management and evaluation.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.breakpoint;

import adbg.process.base;
import adbg.process.memory;
import adbg.error;
import adbg.utils.list;
import adbg.utils.bit;

extern (C):

// NOTE: When a breakpoint is hit by the debugger, the address should
//       be checked against the process' breakpoint list.

// TODO: Test Thumb BKPT
// TODO: Test AArch32 BKPT
// TODO: Test AArch64 BRK

// TODO: Move opcode bits to dedicated module
version (X86) {
	private alias ubyte opcode_t;
	private immutable ubyte[] bpdata = [ 0xcc ]; // int3
} else version (X86_64) {
	private alias ubyte opcode_t;
	private immutable ubyte[] bpdata = [ 0xcc ]; // int3
} else version (ARM_Thumb) {
	// Thumb BKPT
	//       1       index
	// 5432 1098 7654 3210
	// 1011 1110 |       |
	//           +-imm8--+
	private template T16BKPT(ubyte n) {
		enum T16BKPT = ARRAY16!(0xbe << 8 | n);
		/*
		version (BigEndian)
		enum ubyte[2] T16BKPT = [ 0xbe, n ];
		else
		enum ubyte[2] T16BKPT = [ n, 0xbe ];
		*/
	}
	private alias ushort opcode_t;
	private immutable ubyte[] bpdata = T16BKPT!(0xdd);
	//private immutable ubyte[] bpdata = [ 0xbe, 0xdd ]; // BRK #221
} else version (ARM) {
	// AArch32 BKPT
	//  3           2            1       index
	// 1098 7654 3210 9876 5432 1098 7654 3210
	// |  | 0001 0010 |            | 0111 |  |
	// cond(!=1110)   +---imm12----+      imm4 - imm12:imm4
	private template A32BKPT(ushort n) {
		enum A32BKPT = ARRAY32!(0xe12 << 20 | (n >> 4) << 8 | 7 << 4 | n & 15);
		/*
		version (BigEndian)
		enum ubyte[4] A32BKPT = [ 0xe1, 0x20 | (n >> 12), (n >> 4) & 255, 0x70 | (n & 15) ];
		else
		enum ubyte[4] A32BKPT = [ 0x70 | (n & 15), (n >> 4) & 255, 0x20 | (n >> 12), 0xe1 ];
		*/
	}
	private alias uint opcode_t;
	private immutable ubyte[] bpdata = A32BKPT!(0xdd);
	//private immutable ubyte[] bpdata = [ 0xe1, 0x20, 0x0d, 0x7d ]; // BRK #221
} else version (AArch64) {
	// AArch64 BRK
	//  3           2            1       index
	// 1098 7654 3210 9876 5432 1098 7654 3210
	// 1101 0100 001|                  |0 0000
	//              +-------imm16------+
	private template A64BRK(ushort n) {
		enum A64BRK = ARRAY32!(0xd42 << 21 | n << 5);
		/*
		version (BigEndian)
		enum ubyte[4] A64BRK = [ 0xd4, n >> 11, (n >> 3) & 255, (n & 7) << 5 ];
		else
		enum ubyte[4] A64BRK = [ (n & 7) << 5, (n >> 3) & 255, n >> 11, 0xd4 ];
		*/
	}
	private alias uint opcode_t;
	private immutable ubyte[] bpdata = A64BRK!(0xdd);
	//private immutable ubyte[] bpdata = [ 0xa0, 0x1b, 0x20, 0xd4 ]; // BRK #221
} else
	static assert(0, "Missing BREAKPOINT value for target platform");

private enum bplength = bpdata.length;

// Breakpoint layout in memory
struct adbg_breakpoint_t { align(1):
	union {
		opcode_t opcode;
		ubyte[bplength] opdata;
	}
	int magic;
	int id;
}

struct adbg_breakpoint_entry_t {
	size_t address;
}

// TODO: Breakpoint API
//       Add, remove, get list, etc. + initiate function