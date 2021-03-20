/**
 * Missing or incorrect core.stdc.stdio definitions.
 *
 * For example, when compiled with -betterC, putchar from core.stdc.stdio
 * still mangles to `_D4core4stdc5stdio7putcharFiZi` which is NOT the C mangled
 * name for `putchar`, because it is defined as extern (C). Which leads to a
 * runtime crash for some reason.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: See LICENSE
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