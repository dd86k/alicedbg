/// D configuration constants.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © 2019-2022 dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.d.config;

//
// ANCHOR GDC versioning from DMD-FE
//

/// GDC 5.x
enum GDC_5  = 2_067; // 2.067.x: 5.4 (Ubuntu 16.04)
/// GDC 8.x
enum GDC_8  = 2_068; // 2.068.1: 8.4 (Ubuntu 18.04)
/// GDC 9.x
enum GDC_9  = 2_076; // 2.076.1: 9.5 (Ubuntu 22.04:gdc-9)
/// GDC 10.x
enum GDC_10 = 2_076; // 2.076.1: 10.3 (Ubuntu 20.04)
/// GDC 11.x
enum GDC_11 = 2_076; // 2.076.1: 11.2 (Ubuntu 22.04)
/// GDC 12.x
//enum GDC_12 = 2_098; // Tested on 12.1, 2.098.0-beta.1 (or 2.098.1 at release)
enum GDC_12 = 2_100; // 2.100.x: 12.1 (Ubuntu 22.04), 12.2 (Debian 12)

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