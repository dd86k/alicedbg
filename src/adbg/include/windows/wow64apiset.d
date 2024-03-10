/// wow64apiset bindings
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.windows.wow64apiset;

version (Win64):

private import adbg.include.windows.winnt;

extern (Windows):

BOOL Wow64GetThreadContext(HANDLE, WOW64_CONTEXT*);
BOOL Wow64SetThreadContext(HANDLE, WOW64_CONTEXT*);

