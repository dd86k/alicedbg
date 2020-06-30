/**
 *
 *
 * License: BSD 3-Clause
 */
module adbg.sys.posix.unistd;

version (Posix):

version (CRuntime_Musl) {
	public import core.sys.posix.unistd : fork, execve, pipe;
	public extern (C) ssize_t pread(int, void *, size_t, off_t);
	public extern (C) ssize_t pwrite(int, const(void)*, size_t, off_t);
} else {
	public import core.sys.posix.unistd : fork, execve, pread, pwrite, pipe;
}