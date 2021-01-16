/**
 * Windows Defenitions
 *
 * This is in a separate module to aid exporting "headers".
 * Publicly imports core.sys.windows.windef.
 *
 * License: BSD-3-Clause
 */
module adbg.sys.windows.def;

version (Windows):

public import core.sys.windows.windef;

enum WOW64_SIZE_OF_80387_REGISTERS = 80;
enum WOW64_MAXIMUM_SUPPORTED_EXTENSION = 512;
enum EXCEPTION_CONTINUE_SEARCH = 0; /// Show dialog
enum EXCEPTION_EXECUTE_HANDLER = 1; /// Do not show dialog
enum EXCEPTION_CONTINUE_EXECUTION = 0xffffffff;
enum EXCEPTION_MAXIMUM_PARAMETERS = 15; // valid in 8.1 .. 10.0.17134.0