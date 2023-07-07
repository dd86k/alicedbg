/// Missing definitions in core.stdc.config.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.c.config;

public import core.stdc.config;

/// Maps to a C "long int" type.
alias c_longint = c_long;
/// Maps to a C "unsigned long int" type.
alias c_ulongint = c_ulong;