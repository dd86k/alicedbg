/**
 * This module adbg.exist solely because some definitions are missing or incorrect.
 *
 * For example, putchar from core.stdc.stdio mangles to
 * `_D4core4stdc5stdio7putcharFiZi` which is NOT the C runtime definition of
 * `_putchar`. Which would lead to a crash. D people rejected this 'bug' as well.
 *
 * License: BSD 3-clause
 */
module adbg.etc.c;

extern:
extern (C):

/// Proper C declaration of core.stdc.stdio.putchar
int putchar(int);
/// Proper C declaration of core.stdc.stdio.getchar
int getchar();