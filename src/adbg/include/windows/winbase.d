/// Extra definitions for winbase.h.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.windows.winbase;

version (Windows):

public import core.sys.windows.winbase;
public import core.sys.windows.winnt; // For types

// Vista and up
extern (Windows)
BOOL QueryFullProcessImageNameA(
  HANDLE hProcess,	// [in]
  DWORD  dwFlags,	// [in]
  LPSTR  lpExeName,	// [out]
  PDWORD lpdwSize	// [in, out
);