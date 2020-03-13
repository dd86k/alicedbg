/**
 * This module exist solely because some definitions are missing or incorrect.
 *
 * For example, putchar from core.stdc.stdio mangles to
 * `_D4core4stdc5stdio7putcharFiZi` which is NOT the C runtime definition:
 * `_putchar`. Which would lead to a crash. D people rejected this as well.
 *
 * License: BSD 3-Clause
 */
module etc.ddc;

extern (C):

int putchar(int);
int getchar();