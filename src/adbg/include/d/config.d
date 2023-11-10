/// D configuration constants.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.d.config;

//
// ANCHOR GDC versioning from DMD-FE
//

/// GDC 4.x front-end version
enum GDC_4  = 2_055; // 2.055.x: 4.6 (Debian 7)
/// GDC 5.x front-end version
enum GDC_5  = 2_067; // 2.067.x: 5.4 (Ubuntu 16.04)
/// GDC 8.x front-end version
enum GDC_8  = 2_068; // 2.068.1: 8.4 (Ubuntu 18.04), 8.3 (Debian 10.7)
/// GDC 9.x front-end version
enum GDC_9  = 2_076; // 2.076.1: 9.5 (Ubuntu 22.04:gdc-9)
/// GDC 10.x front-end version
enum GDC_10 = 2_076; // 2.076.1: 10.3,10.5 (Ubuntu 20.04)
/// GDC 11.x front-end version
enum GDC_11 = 2_076; // 2.076.1: 11.2,11.4 (Ubuntu 22.04)
/// GDC 12.x front-end version
//enum GDC_12 = 2_098; // Tested on 12.1, 2.098.0-beta.1 (or 2.098.1 at release)
enum GDC_12 = 2_100; // 2.100.x: 12.1 (Ubuntu 22.04), 12.2 (Debian 12)
/// GDC 13.x front-end version
enum GDC_13 = 2_103; // 2.103.x: 13.1.1 (OpenSUSE Tumbleweed 202307178, Artix Linux 20230711)

// gcc/d/d-builtins.cc::d_init_versions emits nothing interesting.

//TODO: enum GDC_VERSION = 0;
version (GNU) {
	static if (__VERSION__ == GDC_13)
		/// GCC back-end major version for GDC. Starts at version 10 minimum.
		enum GDC_VERSION = 13;
	else static if (__VERSION == GDC_12)
		/// Ditto
		enum GDC_VERSION = 12;
	else static if (__VERSION == GDC_11) // 11..9
		/// Ditto
		enum GDC_VERSION = 9;
	else static if (__VERSION == GDC_8)
		/// Ditto
		enum GDC_VERSION = 8;
	else static if (__VERSION == GDC_5)
		/// Ditto
		enum GDC_VERSION = 5;
	else static if (__VERSION == GDC_4)
		/// Ditto
		enum GDC_VERSION = 4;
	else // Unknown
		/// Ditto
		enum GDC_VERSION = 0;
	
	version (GNU_SjLj_Exceptions)
		/// GDC exception implementation.
		enum GDC_EXCEPTION_MODE = "SjLj";
	else version (GNU_SEH_Exceptions)
		/// Ditto
		enum GDC_EXCEPTION_MODE = "SEH";
	else version (GNU_DWARF2_Exceptions)
		/// Ditto
		enum GDC_EXCEPTION_MODE = "DWARF2";
	else
		/// Ditto
		enum GDC_EXCEPTION_MODE = "Unknown";
} else {
	/// Ditto
	enum GDC_VERSION = 0;
	/// Ditto
	enum GDC_EXCEPTION_MODE = null;
}

//
// ANCHOR LDC LLVM versioning
//

version (LDC) {
	// NOTE: LDC doesn't seem to fill in for minor versions
	//       Last tested with ldc 1.32.2 (dmdfe 2.102.2, llvm 15.0.7)
	// See driver/main.cpp::registerPredefinedVersions.
	// No traits to get LDC/LLVM versions.
	// LDC started in 2009, supporting LLVM 2.0.
	version (LDC_LLVM_1800) {
		enum LLVM_VERSION = 18;	/// LLVM version used to compile.
	} else version (LDC_LLVM_1700) {
		enum LLVM_VERSION = 17;	/// Ditto
	} else version (LDC_LLVM_1600) {
		enum LLVM_VERSION = 16;	/// Ditto
	} else version (LDC_LLVM_1500) {
		enum LLVM_VERSION = 15;	/// Ditto
	} else version (LDC_LLVM_1400) {
		enum LLVM_VERSION = 14;	/// Ditto
	} else version (LDC_LLVM_1300) {
		enum LLVM_VERSION = 13;	/// Ditto
	} else version (LDC_LLVM_1200) {
		enum LLVM_VERSION = 12;	/// Ditto
	} else version (LDC_LLVM_1100) {
		enum LLVM_VERSION = 11;	/// Ditto
	} else version (LDC_LLVM_1000) {
		enum LLVM_VERSION = 10;	/// Ditto
	} else version (LDC_LLVM_900) {
		enum LLVM_VERSION = 9;	/// Ditto
	} else version (LDC_LLVM_800) {
		enum LLVM_VERSION = 8;	/// Ditto
	} else version (LDC_LLVM_700) {
		enum LLVM_VERSION = 7;	/// Ditto
	} else version (LDC_LLVM_600) {
		enum LLVM_VERSION = 6;	/// Ditto
	} else version (LDC_LLVM_500) {
		enum LLVM_VERSION = 5;	/// Ditto
	} else version (LDC_LLVM_400) {
		enum LLVM_VERSION = 4;	/// Ditto
	} else version (LDC_LLVM_300) {
		enum LLVM_VERSION = 3;	/// Ditto
	} else version (LDC_LLVM_200) {
		enum LLVM_VERSION = 2;	/// Ditto
	} else
		enum LLVM_VERSION = 0;	/// Ditto
} else {
	enum LLVM_VERSION = 0;	/// Ditto
}

//
// ANCHOR Compiler support enumerations
//

/// core.bitop.bswap supports ulong.
// Added in druntime/d07e682f21b0043354fc4b9ca6d5d2b176a63539
// git describe --contains says v2.071.0-b1
// but successfully compiled on GDC 6.3 (DMD-2.068)
enum COMPILER_FEAT_BSWAP64       = __VERSION__ >= 2_068;
/// If set, the compiler supports the getTargetInfo trait.
enum COMPILER_FEAT_TARGETINFO    = __VERSION__ >= 2_083;
/// If set, the compiler supports the printf and scanf pragmas.
enum COMPILER_FEAT_PRAGMA_PRINTF = __VERSION__ >= 2_092;
/// Compiler supports DIP1034 (bottom type, includes noreturn).
enum COMPILER_FEAT_NORETURN      = __VERSION__ >= 2_096;
/// Compiler has support for core.int128.
enum COMPILER_FEAT_INT128        = __VERSION__ >= 2_100;
/// Compiler supports @mustuse function attribute.
enum COMPILER_FEAT_MUSTUSE       = __VERSION__ >= 2_100;