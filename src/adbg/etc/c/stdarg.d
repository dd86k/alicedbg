/**
 * Missing or incorrect core.stdc.stdarg definitions.
 *
 * Fixes missing __va_tag_list on Posix platforms.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.etc.c.stdarg;

extern (C):
@system:
@nogc:
nothrow:

version (Posix)
version (DigitalMars)
public struct __va_list_tag
{
    uint offset_regs = 6 * 8;            // no regs
    uint offset_fpregs = 6 * 8 + 8 * 16; // no fp regs
    void* stack_args;
    void* reg_args;
}

public import core.stdc.stdarg;