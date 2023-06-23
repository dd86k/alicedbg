/**
 * Older core.stdc.stdlib definitions. 
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.include.c.stdlib;

extern (C):

void exit(int);
void _Exit(int);

public import core.stdc.stdlib;