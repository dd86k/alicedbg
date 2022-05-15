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

public import core.stdc.stdio;