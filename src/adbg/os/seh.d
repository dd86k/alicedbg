/**
 * SEH package
 *
 * License: BSD 3-clause
 */
module adbg.os.seh;

version (Windows) {
	public import adbg.os.windows.seh;
} else
version (Posix) {
	public import adbg.os.posix.seh;
}