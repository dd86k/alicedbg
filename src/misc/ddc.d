/**
 * C compability external functions.
 *
 * It's a set of C runtime external bindings and enumerations and aliases to
 * aid development in betterC modes.
 *
 * Why? Because some functions are externed as (D) in core.stdc, which does not
 * mangle well. So instead of getting `_D3ddc7putchar`, we get `_putchar`.
 */
module misc.ddc;
/*
enum NULL_CHAR = cast(char*)0; /// Null character pointer

//
// stdio.h
//

version (CRuntime_Microsoft) {
	enum _NFILE = 20;

	struct _iobuf { align(1):
		char*	_ptr;
		int	_cnt;
		char*	_base;
		int	_flag;
		int	_file;
		int	_charbuf;
		int	_bufsiz;
		int	__tmpnum;
	}

	alias _iobuf FILE;

	enum {
		_IOFBF   = 0,
		_IOLBF   = 0x40,
		_IONBF   = 4,
		_IOREAD  = 1,	// non-standard
		_IOWRT   = 2,	// non-standard
		_IOMYBUF = 8,	// non-standard
		_IOEOF   = 0x10,	// non-standard
		_IOERR   = 0x20,	// non-standard
		_IOSTRG  = 0x40,	// non-standard
		_IORW    = 0x80,	// non-standard
		_IOAPP   = 0x200,	// non-standard
		_IOAPPEND = 0x200,	// non-standard
	}

	private extern shared void function() _fcloseallp;
	version (DigitalMars) {
		private shared extern extern(C) FILE[_NFILE] _iob;
		shared stdin  = &_iob[0];
		shared stdout = &_iob[1];
		shared stderr = &_iob[2];
		shared stdaux = &_iob[3];
		shared stdprn = &_iob[4];
	}
	version (LDC) {
		private __gshared extern extern(C) FILE[_NFILE] _iob;
		enum stdin  = &_iob[0];
		enum stdout = &_iob[1];
		enum stderr = &_iob[2];
		enum stdaux = &_iob[3];
		enum stdprn = &_iob[4];
		public extern (C) {
			int printf(const(char)*, ...);
			void putchar(int);
			char* fgets(char*, int, shared(FILE)*);
			int fputs(const(char)*, FILE*);
			int getchar();
			int fflush(FILE*);
		}
	} else {
		public extern (C) {
			int printf(const(char)*, ...);
			void putchar(int);
			char* fgets(char*, int, shared(FILE)*);
			int fputs(const(char)*, shared(FILE)*);
			int getchar();
			int fflush(shared(FILE)*);
		}
	}

	//TODO: Check library strings to fix vsnprintf linkage
	version (DigitalMars) extern (C)
	int vsnprintf(char *, size_t, const(char) *, va_list);

	version (LDC) extern (C)
	int __stdio_common_vsprintf(char *, size_t, const(char) *, va_list);
	version (LDC) alias __stdio_common_vsprintf vsnprintf;

	public import core.stdc.stdio : puts;
	public import core.stdc.stdarg : va_list, va_start;
} else { // x86-windows-omf and linux seems to be fine
	public import core.stdc.stdio;
	public import core.stdc.stdarg;
}
*/
