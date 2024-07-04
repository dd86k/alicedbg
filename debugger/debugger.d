/// Common global variables and functions so they can be used throughout the
/// entirety of the program.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module debugger;

public:
extern (C):
__gshared:

/// 
int opt_pid;
/// 
const(char) **opt_file_argv;