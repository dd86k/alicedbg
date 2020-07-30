/**
 * Mostly internal module that deals with GUIDs and UUIDs.
 *
 * License: BSD 3-clause
 */
module adbg.utils.uid;

import core.stdc.stdio;
import adbg.utils.bit;

extern (C):

enum {
	UID_GUID	= 0,
	UID_UUID	= 1,
	UID_LENGTH	= 38	// usually 36 but.. {} and \0
}
alias char[UID_LENGTH] UID_TEXT;

/**
 * UUID/GUID structure
 */
struct UID {
	union {
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
}

/**
 * Uses snprintf to format the UID into a text buffer. If the target endianness
 * does not match the compile target, this function will automatically perform
 * a swap.
 * Params:
 * 	uid = UID structure
 * 	buf = Text buffer (char[38])
 * 	target = UID_GUID or UID_UUID
 * Returns: Whatever snprintf returns
 */
int uid_str(ref UID uid, ref UID_TEXT buf, int target) {
	version (LittleEndian) {
		if (target == UID_UUID)
			uid_swap(uid);
	} else {
		if (target == UID_GUID)
			uid_swap(uid);
	}
	return snprintf(cast(char*)buf, UID_LENGTH,
	"%08X-%04X-%04X-%04X-%02X%02X%02X%02X%02X%02X",
	uid.time_low, uid.time_mid, uid.time_ver, uid.clock,
	uid.data[10], uid.data[11], uid.data[12],
	uid.data[13], uid.data[14], uid.data[15]
	);
}

/**
 * Swap endianness of a UID. GUID (LSB) becomes UUID (MSB) and vice-versa.
 * Params: uid = UID structure
 */
void uid_swap(ref UID uid) {
	uid.time_low = adbg_util_bswap32(uid.time_low);
	uid.time_mid = adbg_util_bswap16(uid.time_mid);
	uid.time_ver = adbg_util_bswap16(uid.time_ver);
	uid.clock = adbg_util_bswap16(uid.clock);
}

/**
 * Return zero if UID is NIL.
 * Params: uid = UID structure
 * Returns: Non-zero if non-empty.
 */
int uid_nil(ref UID uid) {
	version (ILP64) {
		if (uid.u64[0]) return 0;
		if (uid.u64[1]) return 0;
	} else {
		if (uid.u32[0]) return 0;
		if (uid.u32[1]) return 0;
		if (uid.u32[2]) return 0;
		if (uid.u32[3]) return 0;
	}
	return 1;
}