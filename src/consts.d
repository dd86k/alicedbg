module consts;

/// Project version
enum PROJECT_VERSION = "0.0.0";
/// stringbuilder buffer size (and maximum size)
enum STRINGBUILDER_SIZE = 256;

debug enum __BUILDTYPE__ = "debug";	/// Build type
else  enum __BUILDTYPE__ = "release";	/// Build type

//
// PLATFORM_ABI string
//

version (X86) {
	enum __ABI__ = "x86";	/// Platform ABI string compiled for
	version = X86_ANY;
	version = ABI32;
} else
version (X86_64) {
	enum __ABI__ = "amd64";	/// Platform ABI string compiled for
	version = X86_ANY;
	version = ABI64;
} else {
	static assert(0,
		"alicedbg currently only supports x86 and x86-64");
}

pragma(msg, "* abi: ", __ABI__);

//
// PLATFORM_CRT string
//

version (CRuntime_Microsoft)
	enum __CRT__ = "Microsoft";	/// Platform CRT string compiled with
else
version (CRuntime_Bionic)
	enum __CRT__ = "Bionic";	/// Platform CRT string compiled with
else
version (CRuntime_DigitalMars)
	enum __CRT__ = "DigitalMars";	/// Platform CRT string compiled with
else
version (CRuntime_Glibc)
	enum __CRT__ = "Glibc";	/// Platform CRT string compiled with
else
version (CRuntime_Musl)
	enum __CRT__ = "Musl";	/// Platform CRT string compiled with
else
version (CRuntime_UClibc)
	enum __CRT__ = "UClibc";	/// Platform CRT string compiled with
else
	enum __CRT__ = "unknown";	/// Platform CRT string compiled with

pragma(msg, "* crt: ", __CRT__);

//
// PLATFORM_OS string
//

version (Win64) {
	enum __OS__ = "win64";	/// Platform OS string compiled for
} else
version (Win32) {
	enum __OS__ = "win32";	/// Platform OS string compiled for
} else
version (linux) {
	enum __OS__ = "linux";	/// Platform OS string compiled for
} else
version (OSX) {
	enum __OS__ = "osx";	/// Platform OS string compiled for
} else
version (FreeBSD) {
	enum __OS__ = "freebsd";	/// Platform OS string compiled for
} else
version (OpenBSD) {
	enum __OS__ = "openbsd";	/// Platform OS string compiled for
} else
version (NetBSD) {
	enum __OS__ = "netbsd";	/// Platform OS string compiled for
} else
version (DragonflyBSD) {
	enum __OS__ = "dragonflybsd";	/// Platform OS string compiled for
} else
version (BSD) {
	enum __OS__ = "bsd";	/// Platform OS string compiled for
} else
version (Solaris) {
	enum __OS__ = "solaris";	/// Platform OS string compiled for
} else
version (AIX) {
	enum __OS__ = "aix";	/// Platform OS string compiled for
} else
version (SkyOS) {
	enum __OS__ = "skyos";	/// Platform OS string compiled for
} else
version (SysV3) {
	enum __OS__ = "sysv3";	/// Platform OS string compiled for
} else
version (SysV4) {
	enum __OS__ = "sysv4";	/// Platform OS string compiled for
} else
version (Hurd) {
	enum __OS__ = "hurd";	/// Platform OS string compiled for
} else
version (Android) {
	enum __OS__ = "android";	/// Platform OS string compiled for
} else
version (Emscripten) {
	enum __OS__ = "emscripten";	/// Platform OS string compiled for
} else
version (PlayStation) {
	enum __OS__ = "playstation";	/// Platform OS string compiled for
} else
version (PlayStation3) {
	enum __OS__ = "playstation3";	/// Platform OS string compiled for
} else {
	enum __OS__ = "unknown";	/// Platform OS string compiled for
}

pragma(msg, "* os: ", __OS__);