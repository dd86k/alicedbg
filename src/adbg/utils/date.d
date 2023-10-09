/// Minimal date utility.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.utils.date;

extern (C):

/// Convert a 32-bit time_t into a datetime string formatted as "Www Mmm dd hh:mm:ss yyyy".
///
/// This was created because the Microsoft's Visual C Runtime (msvcrt v130) crashed
/// on strftime with a value higher than 0x8000000 with 0xC0000409
/// (STATUS_STACK_BUFFER_OVERRUN). Mostly used for PE32's TimeDateStamp field.
///
/// Params: timestamp = Timestamp.
/// Returns: Formatted string
/// Note: Doesn't check for leak year.
const(char)* ctime32(uint timestamp) {
	// NOTE: Notable values
	// windbg x64: 0xB8A65683 (2068-03-02, crashing)
	// windbg x86: 0x2F269970 (1995-01-25)
	// putty x64: 0x5D873EBE (Sun Sep 22 15:28:30 2019)
	// NOTE: PeInternals is also affected by the weird dates in x86 windbg builds
	import adbg.include.c.stdio : snprintf;
	
	enum S_YEAR = 31557600;
	enum S_MONTH = 2629800;
	enum S_DAY = 86400;
	enum S_HOUR = 3600;
	enum S_MINUTE = 60;
	enum BSZ = 32;	// Typically 24 chars, but 32 is safer with alignment
	enum BASE_YEAR = 1970;
	enum BASE_DOW = 3; // Thursday, starts with Monday
	
	__gshared char[BSZ] _buffer;
	__gshared const(char)*[] DOW = [ // Day of Week
		"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun",
	];
	__gshared const(char)*[] MON = [ // Month
		"Jan", "Feb", "Mar", "Apr",
		"May", "Jun", "Jul", "Aug",
		"Sep", "Oct", "Nov", "Dec",
	];
	__gshared const(char)* error_s = "(error)";
	
	// day of the week
	int dow = ((timestamp / S_DAY) + BASE_DOW) % 7;
	if (dow < 0) dow += 7;
	const(char) *dow_s = dow > 7 ? error_s : DOW[dow];
	
	// year
	int year = timestamp / S_YEAR;
	timestamp -= year * S_YEAR;
	year += BASE_YEAR;
	
	// month
	int month = timestamp / S_MONTH;
	timestamp -= month * S_MONTH;
	month += 1;
	
	// days
	int day = timestamp / S_DAY;
	timestamp -= day * S_DAY;
	day += month & 1 ? 2 : 1;
	
	// hours
	int hours = timestamp / S_HOUR;
	timestamp -= hours * S_HOUR;
	
	// minutes
	int mins = timestamp / S_MINUTE;
	timestamp -= mins * S_MINUTE;
	
	// seconds
	int secs = timestamp;
	
	// month name
	const(char) *mon_s =
		month < 1 || month > 12 ? error_s : MON[month - 1];
	
	// WeekDay Month day hour:minutes:seconds year
	return snprintf(cast(char*)_buffer, BSZ,
		"%s %s %2d %2d:%02d:%02d %d",
		dow_s, mon_s, day, hours, mins, secs, year) < 0 ?
		error_s : cast(char*)_buffer;
}