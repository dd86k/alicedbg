/**
 * SEH package
 *
 * License: BSD 3-Clause
 */
module os.seh;

version (Windows) {
	public import os.windows.seh;
} else
version (Posix) {
	public import os.posix.seh;
}