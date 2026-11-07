/// Mostly internal module that deals with GUIDs and UUIDs.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.utils.uid;

import adbg.include.c.stdio;
import adbg.utils.bit;

extern (C):

enum {
	UID_GUID	= 0,	/// Global UID (little-endian, ala Microsoft)
	UID_UUID	= 1,	/// Universal UID (big-endian)
	UID_TEXTLEN	= 36,	/// Text buffer length
}

/// UUID/GUID structure
union UID {
	this (ubyte p0, ubyte p1, ubyte p2, ubyte p3,
		ubyte p4, ubyte p5, ubyte p6, ubyte p7,
		ubyte p8, ubyte p9, ubyte p10, ubyte p11,
		ubyte p12, ubyte p13, ubyte p14, ubyte p15) {
		data[0] = p0;
		data[1] = p1;
		data[2] = p2;
		data[3] = p3;
		data[4] = p4;
		data[5] = p5;
		data[6] = p6;
		data[7] = p7;
		data[8] = p8;
		data[9] = p9;
		data[10] = p10;
		data[11] = p11;
		data[12] = p12;
		data[13] = p13;
		data[14] = p14;
		data[15] = p15;
	}
	ubyte[16] data;
	ushort[8] u16;
	uint[4]   u32;
	ulong[2]  u64; // Preferred to use when size width = 64
	struct {
		uint     time_low;
		ushort   time_mid;
		ushort   time_ver;	// and time_hi
		ushort   clock;	// seq_hi and res_clock_low
		ubyte[6] node;
	}
}

/// Format the UID into a text buffer.
///
/// If the target endianness does not match the compile target, this function
/// will automatically performs a swap. This function does not terminate the string.
/// Params:
/// 	uid = UID structure.
/// 	buffer = Text buffer of UID_TEXTLEN in size.
/// 	target = UID_GUID or UID_UUID.
/// Returns: Whatever snprintf returns
int uid_text(ref UID uid, ref char[UID_TEXTLEN] buffer, int target) {
	return uid_string(uid, buffer.ptr, UID_TEXTLEN, target);
}

/// Format the UID into a text buffer.
///
/// If the target endianness does not match the compile target, this function
/// will automatically performs a swap. This function does not terminate the string.
/// Params:
/// 	uid = UID structure.
/// 	buf = Text buffer.
/// 	buflen = Text buffer length.
/// 	target = UID_GUID or UID_UUID.
/// Returns: Whatever snprintf returns
int uid_string(ref UID uid, char *buf, size_t buflen, int target) {
	version (LittleEndian) {
		if (target == UID_UUID) uid_swap(uid);
	} else {
		if (target == UID_GUID) uid_swap(uid);
	}
	return snprintf(buf, buflen,
		"%08X-%04X-%04X-%04X-%02X%02X%02X%02X%02X%02X",
		uid.time_low, uid.time_mid, uid.time_ver, uid.clock,
		uid.data[10], uid.data[11], uid.data[12],
		uid.data[13], uid.data[14], uid.data[15]);
}

/// Swap endianness of a UID. GUID (LSB) becomes UUID (MSB) and vice-versa.
/// Params: uid = UID structure
void uid_swap(ref UID uid) {
	uid.time_low = adbg_bswap32(uid.time_low);
	uid.time_mid = adbg_bswap16(uid.time_mid);
	uid.time_ver = adbg_bswap16(uid.time_ver);
	uid.clock    = adbg_bswap16(uid.clock);
}
extern (D) unittest {
	UID uid;
	uid.time_low = 0x01_000000;
	uid.time_mid = 0x02_00;
	uid.time_ver = 0x03_00;
	uid.clock    = 0x04_00;
	uid_swap(uid);
	assert(uid.time_low == 1);
	assert(uid.time_mid == 2);
	assert(uid.time_ver == 3);
	assert(uid.clock    == 4);
}

/// Return zero if UID is NIL.
/// Params: uid = UID structure
/// Returns: Non-zero if non-empty.
bool uid_nil(ref UID uid) {
	return uid.u64[0] == 0 && uid.u64[1] == 0;
}
extern (D) unittest {
	UID uid;
	assert(uid_nil(uid));
}