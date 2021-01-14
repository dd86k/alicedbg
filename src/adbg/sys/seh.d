/**
 * SEH package
 *
 * License: BSD 3-clause
 */
module adbg.sys.seh;

version (Windows) {
	public import adbg.sys.windows.seh;
} else
version (Posix) {
	public import adbg.sys.posix.seh;
}