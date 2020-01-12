module consts;

/// Project version
enum PROJECT_VERSION = "0.0.0";

debug enum __BUILDTYPE__ = "debug";	/// Build type
else  enum __BUILDTYPE__ = "release";	/// Build type

//
// PLATFORM_ABI string
//

version (X86) {
	enum __ABI__ = "x86";	/// Platform ABI string
	version = X86_ANY;
	version = ABI32;
} else
version (X86_64) {
	enum __ABI__ = "amd64";	/// Platform ABI string
	version = X86_ANY;
	version = ABI64;
} else {
	static assert(0,
		"alicedbg is currently not supported on this ABI");
}

pragma(msg, "* abi: ", __ABI__);

//
// PLATFORM_CRT string
//

version (CRuntime_Microsoft)
	enum __CRT__ = "Microsoft";	/// Platform CRT string
else
version (CRuntime_Bionic)
	enum __CRT__ = "Bionic";	/// Platform CRT string
else
version (CRuntime_DigitalMars)
	enum __CRT__ = "DigitalMars";	/// Platform CRT string
else
version (CRuntime_Glibc)
	enum __CRT__ = "Glibc";	/// Platform CRT string
else
version (CRuntime_Musl)
	enum __CRT__ = "Musl";	/// Platform CRT string
else
version (CRuntime_UClibc)
	enum __CRT__ = "UClibc";	/// Platform CRT string
else
	enum __CRT__ = "Unknown";	/// Platform CRT string

pragma(msg, "* crt: ", __CRT__);

//
// PLATFORM_OS string
//

version (Win64)
	enum __OS__ = "Win64";	/// Platform OS string
else
version (Win32)
	enum __OS__ = "Win32";	/// Platform OS string
else
version (linux)
	enum __OS__ = "Linux";	/// Platform OS string
else
version (OSX)
	enum __OS__ = "macOS";	/// Platform OS string
else
version (FreeBSD)
	enum __OS__ = "FreeBSD";	/// Platform OS string
else
version (OpenBSD)
	enum __OS__ = "OpenBSD";	/// Platform OS string
else
version (NetBSD)
	enum __OS__ = "NetBSD";	/// Platform OS string
else
version (DragonflyBSD)
	enum __OS__ = "DragonflyBSD";	/// Platform OS string
else
version (BSD)
	enum __OS__ = "BSD";	/// Platform OS string
else
version (Solaris)
	enum __OS__ = "Solaris";	/// Platform OS string
else
version (AIX)
	enum __OS__ = "AIX";	/// Platform OS string
else
version (SkyOS)
	enum __OS__ = "SkyOS";	/// Platform OS string
else
version (SysV3)
	enum __OS__ = "SysV3";	/// Platform OS string
else
version (SysV4)
	enum __OS__ = "SysV4";	/// Platform OS string
else
version (Hurd)
	enum __OS__ = "GNU Hurd";	/// Platform OS string
else
version (Android)
	enum __OS__ = "Android";	/// Platform OS string
else
version (Emscripten)
	enum __OS__ = "Emscripten";	/// Platform OS string
else
version (PlayStation)
	enum __OS__ = "PlayStation";	/// Platform OS string
else
version (PlayStation3)
	enum __OS__ = "PlayStation3";	/// Platform OS string
else
	enum __OS__ = "Unknown";	/// Platform OS string

pragma(msg, "* os: ", __OS__);