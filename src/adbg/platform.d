/**
 * Compile constants
 *
 * License: BSD 3-clause
 */
module adbg.platform;

extern (C):

//
// ANCHOR Compile settings
//

/// Amount of pointers to allocate
enum ADBG_CLI_ARGV_ARRAY_COUNT	= 16;
/// Length of array for argv parsing
enum ADBG_CLI_ARGV_ARRAY_LENGTH	= ADBG_CLI_ARGV_ARRAY_COUNT * size_t.sizeof;
/// The maximum amount of breakpoints that the debugger can have.
enum ADBG_MAX_BREAKPOINTS	= 4;
/// Child stack size if USE_CLONE is specified.
enum ADBG_CHILD_STACK_SIZE	= 1024 * 1024 * 8;

//
// Constants
//

/// Application version
enum ADBG_VERSION = "0.0.0";

debug enum __BUILDTYPE__ = "debug";	/// Build type
else  enum __BUILDTYPE__ = "release";	/// Build type

private enum VERSION_TARGET_INFO = 2083;

struct adbg_info_t {
	const(char) *adbgver = ADBG_VERSION;
	const(char) *build   = __BUILDTYPE__;
	const(char) *arch    = TARGET_PLATFORM;
	const(char) *os      = TARGET_OS;
	const(char) *crt     = TARGET_CRT;
	const(char) *cpprt   = TARGET_CPPRT;
	const(char) *env     = TARGET_ENV;
	const(char) *objfmt  = TARGET_OBJFMT;
	const(char) *fltabi  = TARGET_FLTABI;
	const(char) *asmhint = IN_ASM_STR;
}

//
// ANCHOR ABI string
//

version (X86) {
	enum TARGET_PLATFORM = "x86";	/// Platform ABI string
	public alias opcode_t = ubyte;
} else version (X86_64) {
	enum TARGET_PLATFORM = "x86_64";	/// Platform ABI string
	public alias opcode_t = ubyte;
} else version (ARM_Thumb) {
	enum TARGET_PLATFORM = "arm_t32";	/// Platform ABI string
	public alias opcode_t = ushort;
} else version (ARM) {
	enum TARGET_PLATFORM = "arm_a32";	/// Platform ABI string
	public alias opcode_t = uint;
} else version (AArch64) {
	enum TARGET_PLATFORM = "arm_a64";	/// Platform ABI string
	public alias opcode_t = uint;
}
else
	static assert(0, "Platform not supported.");

//
// ANCHOR CRT string
//

version (CRuntime_Bionic)
	enum TARGET_CRT = "Bionic";	/// Platform CRT string
else version (CRuntime_DigitalMars)
	enum TARGET_CRT = "DigitalMars";	/// Platform CRT string
else version (CRuntime_Glibc)
	enum TARGET_CRT = "Glibc";	/// Platform CRT string
else version (CRuntime_Microsoft)
	enum TARGET_CRT = "Microsoft";	/// Platform CRT string
else version (CRuntime_Musl)
	enum TARGET_CRT = "Musl";	/// Platform CRT string
else version (CRuntime_Newlib) // Cygwin
	enum TARGET_CRT = "Newlib";	/// Platform CRT string
else version (CRuntime_UClibc)
	enum TARGET_CRT = "UClibc";	/// Platform CRT string
else version (CRuntime_WASI) // WebAssembly
	enum TARGET_CRT = "WASI";	/// Platform CRT string
else
	enum TARGET_CRT = "Unknown";	/// Platform CRT string

//
// ANCHOR OS string
//

version (Win64)
	enum TARGET_OS = "Win64";	/// Platform OS string
else version (Win32)
	enum TARGET_OS = "Win32";	/// Platform OS string
else version (linux)
	enum TARGET_OS = "Linux";	/// Platform OS string
else version (OSX)
	enum TARGET_OS = "macOS";	/// Platform OS string
else version (FreeBSD)
	enum TARGET_OS = "FreeBSD";	/// Platform OS string
else version (OpenBSD)
	enum TARGET_OS = "OpenBSD";	/// Platform OS string
else version (NetBSD)
	enum TARGET_OS = "NetBSD";	/// Platform OS string
else version (DragonflyBSD)
	enum TARGET_OS = "DragonflyBSD";	/// Platform OS string
else version (BSD)
	enum TARGET_OS = "BSD";	/// Platform OS string
else version (Solaris)
	enum TARGET_OS = "Solaris";	/// Platform OS string
else version (AIX)
	enum TARGET_OS = "AIX";	/// Platform OS string
else version (SkyOS)
	enum TARGET_OS = "SkyOS";	/// Platform OS string
else version (SysV3)
	enum TARGET_OS = "SysV3";	/// Platform OS string
else version (SysV4)
	enum TARGET_OS = "SysV4";	/// Platform OS string
else version (Hurd)
	enum TARGET_OS = "GNU Hurd";	/// Platform OS string
else version (Android)
	enum TARGET_OS = "Android";	/// Platform OS string
else version (Emscripten)
	enum TARGET_OS = "Emscripten";	/// Platform OS string
else version (PlayStation)
	enum TARGET_OS = "PlayStation";	/// Platform OS string
else version (PlayStation3)
	enum TARGET_OS = "PlayStation3";	/// Platform OS string
else
	enum TARGET_OS = "Unknown";	/// Platform OS string

//
// ANCHOR Additional Target Information
//

version (DigitalMars) {
	static if (__VERSION__ >= VERSION_TARGET_INFO)
		private enum FEATURE_TARGETINFO = true;
	else
		private enum FEATURE_TARGETINFO = false;
} else version (LDC) {
	static if (__VERSION__ >= VERSION_TARGET_INFO)
		private enum FEATURE_TARGETINFO = true;
	else
		private enum FEATURE_TARGETINFO = false;
} else
	private enum FEATURE_TARGETINFO = false;

static if (FEATURE_TARGETINFO) {
	/// Target object format string
	enum TARGET_OBJFMT = __traits(getTargetInfo, "objectFormat");
	/// Target float ABI string
	enum TARGET_FLTABI  = __traits(getTargetInfo, "floatAbi");
	// Likely to happen on non-Windows platforms
	private enum __tinfo = __traits(getTargetInfo, "cppRuntimeLibrary");
	static if (__tinfo == null)
		enum TARGET_CPPRT = "none"; /// Target C++ Runtime string
	else
		enum TARGET_CPPRT = __tinfo; /// Target C++ Runtime string
} else {
	/// Target object format string
	enum TARGET_OBJFMT = "unknown";
	/// Target float ABI string
	enum TARGET_FLTABI  = "unknown";
	version (CppRuntime_Gcc)
		enum TARGET_CPPRT = "libstdc++"; /// Target C++ Runtime string
	else version (CppRuntime_Microsoft)
		enum TARGET_CPPRT = "libcmt"; /// Target C++ Runtime string
	else version (CppRuntime_Clang)
		enum TARGET_CPPRT = "clang"; /// Target C++ Runtime string
	else version (CppRuntime_DigitalMars)
		enum TARGET_CPPRT = "dmc++"; /// Target C++ Runtime string
	else version (CppRuntime_Sun)
		enum TARGET_CPPRT = "sun"; /// Target C++ Runtime string
	else // assuming none
		enum TARGET_CPPRT = "none"; /// Target C++ Runtime string
}

//
// ANCHOR Environement string
//        This constitutes environment C libraries (e.g., wrappers)
//

version (MinGW) {
	enum TARGET_ENV = "MinGW";
} else version (Cygwin) {
	enum TARGET_ENV = "Cygwin";
} else version (FreeStanding) { // now that would surprise me
	enum TARGET_ENV = "Bare-metal";
} else {
	enum TARGET_ENV = "none";
}

//
// ANCHOR Inline Assembler string
//

enum InlineAsm {
	None,
	DMD_x86,
	DMD_x86_64,
	LDC_x86,
	LDC_x86_64,
	GDC_x86,
	GDC_x86_64,
}

version (DigitalMars) {
	version (D_InlineAsm_X86) {
		enum IN_ASM = InlineAsm.DMD_x86;
	} else version (D_InlineAsm_X86_64) {
		enum IN_ASM = InlineAsm.DMD_x86_64;
	} else {
		enum IN_ASM = InlineAsm.None;
	}
} else
version (GNU_Inline) {
	//TODO: Check which FE version implemented inlined asm
	version (X86) {
		enum IN_ASM = InlineAsm.GDC_x86;
	} else version (X86_64) {
		enum IN_ASM = InlineAsm.GDC_x86_64;
	} else version (D_InlineAsm_X86) {
		enum IN_ASM = InlineAsm.GDC_x86;
	} else version (D_InlineAsm_X86_64) {
		enum IN_ASM = InlineAsm.GDC_x86_64;
	} else {
		enum IN_ASM = InlineAsm.None;
	}
} else
version (LDC) {
	version (D_InlineAsm_X86) {
		enum IN_ASM = InlineAsm.LDC_x86;
	} else version (D_InlineAsm_X86_64) {
		enum IN_ASM = InlineAsm.LDC_x86_64;
	} else {
		enum IN_ASM = InlineAsm.None;
	}
} else
	enum IN_ASM = InlineAsm.None;

static if (IN_ASM == InlineAsm.DMD_x86)
	enum IN_ASM_STR = "dmd-x86";
else static if (IN_ASM == InlineAsm.DMD_x86_64)
	enum IN_ASM_STR = "dmd-x86_64";
else static if (IN_ASM == InlineAsm.GDC_x86)
	enum IN_ASM_STR = "gdc-x86";
else static if (IN_ASM == InlineAsm.GDC_x86_64)
	enum IN_ASM_STR = "gdc-x86_64";
else static if (IN_ASM == InlineAsm.LDC_x86)
	enum IN_ASM_STR = "ldc-x86";
else static if (IN_ASM == InlineAsm.LDC_x86_64)
	enum IN_ASM_STR = "ldc-x86_64";
else
	enum IN_ASM_STR = "none";

debug (PrintTargetInfo) {
	pragma(msg, "ADBG_VERSION\t", ADBG_VERSION);
	pragma(msg, "__BUILDTYPE__\t", __BUILDTYPE__);
	pragma(msg, "TARGET_PLATFORM\t", TARGET_PLATFORM);
	pragma(msg, "TARGET_OS\t", TARGET_OS);
	pragma(msg, "TARGET_CRT\t", TARGET_CRT);
	pragma(msg, "TARGET_CPPRT\t", TARGET_CPPRT);
	pragma(msg, "TARGET_ENV\t", TARGET_ENV);
	pragma(msg, "TARGET_OBJFMT\t", TARGET_OBJFMT);
	pragma(msg, "TARGET_FLTABI\t", TARGET_FLTABI);
	pragma(msg, "IN_ASM_STR\t", IN_ASM_STR);
}

//
// ANCHOR External functions
//

/**
 * Get compilation information structure.
 * Returns: AdbgInfo structure pointer
 */
immutable(adbg_info_t)* adbg_info() {
	immutable static adbg_info_t info;
	return &info;
}
