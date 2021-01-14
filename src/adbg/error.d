/**
 * License: BSD 3-clause
 */
module adbg.error;

extern (C):

// Error code structure
// 00000000
// ||||++++- Errorcode
// ||++----- Module
// ++------- Reserved

//TODO: AdbgErrModule
//      enum AdbgErrorModule
//      << 16
//      00 Application (cli, front-ends)
//      01 System
//      02 Debugger
//      03 Disassembler
//      04 Object
//      05 Utilities