/**
 * Missing or incorrect core.stdc.stdio definitions.
 *
 * For example, when compiled with -betterC, `putchar` from core.stdc.stdio
 * still mangles to `_D4core4stdc5stdio7putcharFiZi` due to the D extern, so
 * the function links up with the version from the druntime (or itself).
 * On top of that, stdout isn't initialized since that's done in the Druntime.
 * So when executed, boom, crash.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.include.c.stdio;

import adbg.include.d.config : COMPILER_FEAT_PRAGMA_PRINTF, GDC_11;

extern (C):
@system:
@nogc:
nothrow:

// NOTE: Wrong extern.
//       Should be C, but they're defined as D.
//       This is wrong for symbol mangling (e.g., _putchar vs. _D4core4stdc5stdio7putcharFiZi).

/// 
int putchar(int);
/// 
int getchar();

// NOTE: I really don't know why dmd's lld-link (win64) wouldn't pick up snprintf
//       from core.stdc.stdio._snprintf, so this is one of those copy-paste fix.

version (Windows) {
	static if (COMPILER_FEAT_PRAGMA_PRINTF) {
		///
		pragma(printf)
		int   _snprintf(scope char* s, size_t n, scope const char* fmt, scope const ...);
		alias _snprintf snprintf;
	} else {
		///
		int   _snprintf(scope char* s, size_t n, scope const char* fmt, scope const ...);
		alias _snprintf snprintf;
	}
} else {
	static if (COMPILER_FEAT_PRAGMA_PRINTF) {
		///
		pragma(printf)
		int   snprintf(scope char* s, size_t n, scope const char* fmt, scope const ...);
	} else {
		///
		int   snprintf(scope char* s, size_t n, scope const char* fmt, scope const ...);
	}
}

// NOTE: Wrong printf/scanf detection for GDC 11 and lower.
//       scanf conditions were the same for printf

version (GNU) {
	static if (__VERSION__ <= GDC_11) { // GDC 11.3
		/// 
		int __isoc99_sscanf(scope const char* s, scope const char* format, scope ...);
		/// 
		alias sscanf = __isoc99_sscanf;
		/// 
		int __isoc99_scanf(scope const char* format, scope ...);
		/// 
		alias scanf = __isoc99_scanf;
	}
}

public import core.stdc.stdio;