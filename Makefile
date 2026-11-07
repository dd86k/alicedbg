# Makefile alternative to DUB for alicedbg
#
# Portable across GNU make and BSD makes (FreeBSD/NetBSD/OpenBSD).
# Uses `!=` for shell assignment (supported by BSD makes and GNU make >=4.0)
# instead of GNU-only `ifeq`/`endif` conditionals and `$(wildcard ...)`.
#
# Build type is picked with BUILD (release, release-debug, debug, debugv, trace)
# and STATIC=1 links statically, e.g. `make dumper BUILD=debug`.
# Switching BUILD does not invalidate outputs; run `make clean` first.

DC ?= dmd
BUILD ?= release
STATIC ?= 0
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib

LIB_SRCS != find core objects src -name '*.d'
COMMON_SRCS != find common/src -name '*.d'
DEBUGGER_SRCS != find debugger/src -name '*.d'
DUMPER_SRCS != find dumper/src -name '*.d'
# DUB excludes the frontend's main.d when testing and supplies its own main
DEBUGGER_TEST_SRCS != find debugger/src -name '*.d' ! -name main.d
DUMPER_TEST_SRCS != find dumper/src -name '*.d' ! -name main.d

# Compiler-specific flag mapping. DMD flags are the baseline; LDC and GDC
# equivalents are selected by matching $(DC) against the compiler binary name.
# Strip any directory prefix so absolute paths (e.g. /usr/pkg/gcc15/bin/gdc) match.
# GDC comes in gdc, gdc-15, gcc-gdc, gcc-gdc-15, and egdc (OpenBSD) flavors, so catch them all
# GDC gets no betterC flag, mirroring dub.sdl (-fno-druntime only works for static builds).
DC_NAME       != basename "$(DC)"
OFLAG         != case "$(DC_NAME)" in *gdc*) echo "-o" ;; *) echo "-of=" ;; esac
VERSION_FLAG  != case "$(DC_NAME)" in ldc*) echo "-d-version" ;; *gdc*) echo "-fversion" ;; *) echo "-version" ;; esac
UNITTEST_FLAG != case "$(DC_NAME)" in *gdc*) echo "-funittest" ;; *) echo "-unittest" ;; esac
MAIN_FLAG     != case "$(DC_NAME)" in *gdc*) echo "-fmain" ;; *) echo "-main" ;; esac
TEST_FLAGS    != case "$(DC_NAME)" in ldc*) echo "-g -d-debug" ;; *gdc*) echo "-g -fdebug" ;; *) echo "-g -debug" ;; esac
BUILD_FLAGS   != case "$(DC_NAME):$(BUILD)" in \
	ldc*:release)       echo "-betterC -O2 -release -boundscheck=off" ;; \
	ldc*:release-debug) echo "-betterC -O2 -release -boundscheck=off -g" ;; \
	ldc*:debug)         echo "-betterC -g -d-debug" ;; \
	ldc*:debugv)        echo "-betterC -g -d-debug -d-version=DebugV -d-version=PrintTargetInfo --vgc" ;; \
	ldc*:trace)         echo "-betterC -g -d-debug -d-version=Trace -d-version=AdbgTrace --vgc" ;; \
	*gdc*:release)       echo "-O2 -frelease -fno-bounds-check" ;; \
	*gdc*:release-debug) echo "-O2 -frelease -fno-bounds-check -g" ;; \
	*gdc*:debug)         echo "-g -fdebug" ;; \
	*gdc*:debugv)        echo "-g -fdebug -fversion=DebugV -fversion=PrintTargetInfo -ftransition=nogc -ftransition=tls" ;; \
	*gdc*:trace)         echo "-g -fdebug -fversion=Trace -fversion=AdbgTrace -ftransition=nogc -ftransition=tls" ;; \
	*:release)       echo "-betterC -O -release -boundscheck=off" ;; \
	*:release-debug) echo "-betterC -O -release -boundscheck=off -g" ;; \
	*:debug)         echo "-betterC -g -debug" ;; \
	*:debugv)        echo "-betterC -g -debug -version=DebugV -version=PrintTargetInfo -vgc -vtls" ;; \
	*:trace)         echo "-betterC -g -debug -version=Trace -version=AdbgTrace -vgc -vtls" ;; \
	*) echo "unknown BUILD=$(BUILD)" >&2; echo "-BUILD-ERROR" ;; esac
STATIC_FLAGS  != case "$(STATIC):$(DC_NAME)" in \
	1:ldc*)  echo "--static" ;; \
	1:*gdc*) echo "-fno-druntime -Wl,-static" ;; \
	1:*)     echo "-L=-static" ;; esac

LIB_IMPORTS = -Icore -Iobjects -Isrc
DFLAGS = $(BUILD_FLAGS) $(STATIC_FLAGS) $(LIB_IMPORTS) -Icommon/src

# Default target
all: debugger

# Build targets
debugger: alicedbg
dumper: alicedump
library: libalicedbg.a

alicedbg: $(LIB_SRCS) $(COMMON_SRCS) $(DEBUGGER_SRCS)
	$(DC) $(DFLAGS) $(OFLAG)alicedbg $(LIB_SRCS) $(COMMON_SRCS) $(DEBUGGER_SRCS)

alicedump: $(LIB_SRCS) $(COMMON_SRCS) $(DUMPER_SRCS)
	$(DC) $(DFLAGS) $(OFLAG)alicedump $(LIB_SRCS) $(COMMON_SRCS) $(DUMPER_SRCS)

# GDC has no -lib, so go through a single object and ar; LDC needs -oq since
# module basenames collide (e.g. ptrace)
libalicedbg.a: $(LIB_SRCS)
	case "$(DC_NAME)" in \
	*gdc*) $(DC) $(DFLAGS) $(VERSION_FLAG)=StaticLib -c -o libalicedbg.o $(LIB_SRCS) && \
		ar rcs libalicedbg.a libalicedbg.o && rm -f libalicedbg.o ;; \
	ldc*) $(DC) $(DFLAGS) $(VERSION_FLAG)=StaticLib -lib -oq -od=libalicedbg.objs $(OFLAG)libalicedbg.a $(LIB_SRCS) && \
		rm -rf libalicedbg.objs ;; \
	*) $(DC) $(DFLAGS) $(VERSION_FLAG)=StaticLib -lib $(OFLAG)libalicedbg.a $(LIB_SRCS) ;; \
	esac

# Tests run with druntime (no betterC), same as dub's unittest build type
test: $(LIB_SRCS)
	$(DC) $(TEST_FLAGS) $(UNITTEST_FLAG) $(MAIN_FLAG) $(LIB_IMPORTS) $(OFLAG)alicedbg-test-library $(LIB_SRCS)
	./alicedbg-test-library

test-debugger: $(LIB_SRCS) $(COMMON_SRCS) $(DEBUGGER_TEST_SRCS)
	$(DC) $(TEST_FLAGS) $(UNITTEST_FLAG) $(MAIN_FLAG) $(LIB_IMPORTS) -Icommon/src $(OFLAG)alicedbg-debugger-test-application \
		$(LIB_SRCS) $(COMMON_SRCS) $(DEBUGGER_TEST_SRCS)
	./alicedbg-debugger-test-application

test-dumper: $(LIB_SRCS) $(COMMON_SRCS) $(DUMPER_TEST_SRCS)
	$(DC) $(TEST_FLAGS) $(UNITTEST_FLAG) $(MAIN_FLAG) $(LIB_IMPORTS) -Icommon/src $(OFLAG)alicedbg-dumper-test-application \
		$(LIB_SRCS) $(COMMON_SRCS) $(DUMPER_TEST_SRCS)
	./alicedbg-dumper-test-application

test-threading: $(LIB_SRCS) tests/threading.d
	$(DC) $(TEST_FLAGS) $(UNITTEST_FLAG) $(MAIN_FLAG) $(LIB_IMPORTS) $(OFLAG)alicedbg-test-threading $(LIB_SRCS) tests/threading.d
	./alicedbg-test-threading

test-setjmp: $(LIB_SRCS) tests/setjmp.d
	$(DC) $(TEST_FLAGS) $(UNITTEST_FLAG) $(MAIN_FLAG) $(LIB_IMPORTS) $(OFLAG)alicedbg-test-setjmp $(LIB_SRCS) tests/setjmp.d
	./alicedbg-test-setjmp

easy-target: tests/easy-target.d
	$(DC) $(TEST_FLAGS) $(OFLAG)easy-target tests/easy-target.d

test-easy: $(LIB_SRCS) tests/easy.d easy-target
	$(DC) $(TEST_FLAGS) $(UNITTEST_FLAG) $(MAIN_FLAG) $(LIB_IMPORTS) $(OFLAG)alicedbg-test-easy-api $(LIB_SRCS) tests/easy.d
	./alicedbg-test-easy-api

# Install/uninstall
install: alicedbg alicedump
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 alicedbg $(DESTDIR)$(BINDIR)/alicedbg
	install -m 755 alicedump $(DESTDIR)$(BINDIR)/alicedump

install-library: libalicedbg.a
	install -d $(DESTDIR)$(LIBDIR)
	install -m 644 libalicedbg.a $(DESTDIR)$(LIBDIR)/libalicedbg.a

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/alicedbg $(DESTDIR)$(BINDIR)/alicedump $(DESTDIR)$(LIBDIR)/libalicedbg.a

# Clean
clean:
	rm -rf libalicedbg.objs
	rm -f alicedbg alicedbg.o alicedump alicedump.o libalicedbg.a libalicedbg.o \
		alicedbg-test-library alicedbg-test-library.o \
		alicedbg-debugger-test-application alicedbg-debugger-test-application.o \
		alicedbg-dumper-test-application alicedbg-dumper-test-application.o \
		alicedbg-test-threading alicedbg-test-threading.o \
		alicedbg-test-setjmp alicedbg-test-setjmp.o \
		alicedbg-test-easy-api alicedbg-test-easy-api.o \
		easy-target easy-target.o

.PHONY: all debugger dumper library \
	test test-debugger test-dumper test-threading test-setjmp test-easy \
	install install-library uninstall clean
