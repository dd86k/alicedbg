module os.seh;

version (Windows) {
	public import os.windows.seh;
} else
version (Posix) {
	public import os.posix.seh;
}