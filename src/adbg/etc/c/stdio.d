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
module adbg.etc.c.stdio;

extern (C):
@system:
@nogc:
nothrow:

/// 
int putchar(int);
/// 
int getchar();

// NOTE: I really don't know why dmd's lld-link (win64) wouldn't pick up snprintf
//       from core.stdc.stdio._snprintf, so this is one of those copy-paste fix.

///
pragma(printf)
int   _snprintf(scope char* s, size_t n, scope const char* fmt, scope const ...);
///
alias _snprintf snprintf;

public import core.stdc.stdio;