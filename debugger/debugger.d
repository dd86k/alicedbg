/// Common global variables and functions so they can be used throughout the
/// entirety of the program.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module debugger;

import core.stdc.stdio : puts;
import core.stdc.stdlib : exit;
import core.stdc.string : strerror;
import core.stdc.errno : errno;
import adbg.error;
import adbg.disassembler;
import adbg.debugger.exception;
import adbg.machines : AdbgMachine;
import core.stdc.stdio : FILE;
import core.stdc.stdlib : malloc;

public:
extern (C):
__gshared:

/// 
int opt_pid;
/// 
const(char) **opt_file_argv;