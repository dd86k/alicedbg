/// D configuration constants.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.d.config;

//
// ANCHOR GDC versioning from DMD-FE
//

/// GDC 5.x
enum GDC_5  = 2_067; // 2.067.x: 5.4 (Ubuntu 16.04)
/// GDC 8.x
enum GDC_8  = 2_068; // 2.068.1: 8.4 (Ubuntu 18.04), 8.3 (Debian 10.7)
/// GDC 9.x
enum GDC_9  = 2_076; // 2.076.1: 9.5 (Ubuntu 22.04:gdc-9)
/// GDC 10.x
enum GDC_10 = 2_076; // 2.076.1: 10.3 (Ubuntu 20.04)
/// GDC 11.x
enum GDC_11 = 2_076; // 2.076.1: 11.2 (Ubuntu 22.04)
/// GDC 12.x
//enum GDC_12 = 2_098; // Tested on 12.1, 2.098.0-beta.1 (or 2.098.1 at release)
enum GDC_12 = 2_100; // 2.100.x: 12.1 (Ubuntu 22.04), 12.2 (Debian 12)
/// GDC 13.x
enum GDC_13 = 2_103; // 2.103.x: 13.1.1 (OpenSUSE Tumbleweed 202307178, Artix Linux 20230711)

// gcc/d/d-builtins.cc::d_init_versions emits nothing interesting.

//TODO: enum GDC_VERSION = 0;

//
// ANCHOR LDC LLVM versioning
//

version (LDC) {
	// NOTE: LDC doesn't seem to fill in for minor versions
	//       Last tested with ldc 1.32.2 (dmdfe 2.102.2, llvm 15.0.7)
	// See driver/main.cpp::registerPredefinedVersions.
	// No traits to get LDC/LLVM versions.
	// LDC started in 2009, supporting LLVM 2.0.
	version (LDC_LLVM_1700) {
		enum LLVM_VERSION = 17;	/// LLVM version from compiler used.
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
/// If set, the compiler supports the getTargetInfo trait.
enum COMPILER_FEAT_TARGETINFO    = __VERSION__ >= 2_083;
/// If set, the compiler supports the printf and scanf pragmas.
enum COMPILER_FEAT_PRAGMA_PRINTF = __VERSION__ >= 2_092;
/// Compiler supports DIP1034 (bottom type, includes noreturn).
enum COMPILER_FEAT_NORETURN      = __VERSION__ >= 2_096;
/// Compiler has support for core.int128.
enum COMPILER_FEAT_INT128        = __VERSION__ >= 2_100;