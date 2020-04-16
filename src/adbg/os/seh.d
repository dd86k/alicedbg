/**
 * SEH package
 *
 * License: BSD 3-Clause
 */
module adbg.os.seh;

version (Windows) {
	public import adbg.os.windows.seh;
} else
version (Posix) {
	public import adbg.os.posix.seh;
}