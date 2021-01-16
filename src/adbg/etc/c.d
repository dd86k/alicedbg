/**
 * This module adbg.exist solely because some definitions are missing or incorrect.
 *
 * For example, putchar from core.stdc.stdio mangles to
 * `_D4core4stdc5stdio7putcharFiZi` which is NOT the C mangled name of
 * `_putchar`. Which would lead to a runtime crash.
 *
 * License: BSD-3-Clause
 */
module adbg.etc.c;

extern (C):

/// Proper C declaration of core.stdc.stdio.putchar
int putchar(int);
/// Proper C declaration of core.stdc.stdio.getchar
int getchar();