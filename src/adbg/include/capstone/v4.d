module adbg.include.capstone.v4;

import core.stdc.config;
import core.stdc.stdio;
import core.stdc.stdarg;

import adbg.include.capstone.arm64;
import adbg.include.capstone.arm;
import adbg.include.capstone.evm;
import adbg.include.capstone.m680x;
import adbg.include.capstone.m68k;
import adbg.include.capstone.mips;
import adbg.include.capstone.ppc;
import adbg.include.capstone.sparc;
import adbg.include.capstone.systemz;
import adbg.include.capstone.tms320c64x;
import adbg.include.capstone.x86;
import adbg.include.capstone.xcore;

extern (C):

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2016 */

// Capstone D "header" refined/fixed by dd86k <dd@dax.moe>

// Capstone API version
enum CS_API_MAJOR = 4;
enum CS_API_MINOR = 0;

// Capstone package version
enum CS_VERSION_MAJOR = CS_API_MAJOR;
enum CS_VERSION_MINOR = CS_API_MINOR;
enum CS_VERSION_EXTRA = 0;

/// Macro to create combined version which can be compared to
/// result of cs_version() API.
extern (D) auto CS_MAKE_VERSION(T0, T1)(auto ref T0 major, auto ref T1 minor)
{
    return (major << 8) + minor;
}

/// Maximum size of an instruction mnemonic string.
enum CS_MNEMONIC_SIZE = 32;

/// Handle using with all API
alias csh = size_t;

/// Architecture type
enum
{
    CS_ARCH_ARM = 0,    ///< ARM architecture (including Thumb, Thumb-2)
    CS_ARCH_ARM64 = 1,  ///< ARM-64, also called AArch64
    CS_ARCH_MIPS = 2,   ///< Mips architecture
    CS_ARCH_X86 = 3,    ///< X86 architecture (including x86 & x86-64)
    CS_ARCH_PPC = 4,    ///< PowerPC architecture
    CS_ARCH_SPARC = 5,  ///< Sparc architecture
    CS_ARCH_SYSZ = 6,   ///< SystemZ architecture
    CS_ARCH_XCORE = 7,  ///< XCore architecture
    CS_ARCH_M68K = 8,   ///< 68K architecture
    CS_ARCH_TMS320C64X = 9, ///< TMS320C64x architecture
    CS_ARCH_M680X = 10, ///< 680X architecture
    CS_ARCH_EVM = 11,   ///< Ethereum architecture
    CS_ARCH_MAX = 12,
    CS_ARCH_ALL = 0xFFFF // All architectures - for cs_support()
}
alias int cs_arch;

// Support value to verify diet mode of the engine.
// If cs_support(CS_SUPPORT_DIET) return True, the engine was compiled
// in diet mode.
enum CS_SUPPORT_DIET = CS_ARCH_ALL + 1;

// Support value to verify X86 reduce mode of the engine.
// If cs_support(CS_SUPPORT_X86_REDUCE) return True, the engine was compiled
// in X86 reduce mode.
enum CS_SUPPORT_X86_REDUCE = CS_ARCH_ALL + 2;

/// Mode type
enum
{
    CS_MODE_LITTLE_ENDIAN = 0,  /// little-endian mode (default mode)
    CS_MODE_ARM = 0,        /// 32-bit ARM
    CS_MODE_16 = 1 << 1,    /// 16-bit mode (X86)
    CS_MODE_32 = 1 << 2,    /// 32-bit mode (X86)
    CS_MODE_64 = 1 << 3,    /// 64-bit mode (X86, PPC)
    CS_MODE_THUMB = 1 << 4, /// ARM's Thumb mode, including Thumb-2
    CS_MODE_MCLASS = 1 << 5,    /// ARM's Cortex-M series
    CS_MODE_V8 = 1 << 6,    /// ARMv8 A32 encodings for ARM
    CS_MODE_MICRO = 1 << 4, /// MicroMips mode (MIPS)
    CS_MODE_MIPS3 = 1 << 5, /// Mips III ISA
    CS_MODE_MIPS32R6 = 1 << 6,  /// Mips32r6 ISA
    CS_MODE_MIPS2 = 1 << 7, /// Mips II ISA
    CS_MODE_V9 = 1 << 4,    /// SparcV9 mode (Sparc)
    CS_MODE_QPX = 1 << 4,   /// Quad Processing eXtensions mode (PPC)
    CS_MODE_M68K_000 = 1 << 1,  /// M68K 68000 mode
    CS_MODE_M68K_010 = 1 << 2,  /// M68K 68010 mode
    CS_MODE_M68K_020 = 1 << 3,  /// M68K 68020 mode
    CS_MODE_M68K_030 = 1 << 4,  /// M68K 68030 mode
    CS_MODE_M68K_040 = 1 << 5,  /// M68K 68040 mode
    CS_MODE_M68K_060 = 1 << 6,  /// M68K 68060 mode
    CS_MODE_BIG_ENDIAN = 1 << 31,   /// big-endian mode
    CS_MODE_MIPS32 = CS_MODE_32,    /// Mips32 ISA (Mips)
    CS_MODE_MIPS64 = CS_MODE_64,    /// Mips64 ISA (Mips)
    CS_MODE_M680X_6301 = 1 << 1,    /// M680X Hitachi 6301,6303 mode
    CS_MODE_M680X_6309 = 1 << 2,    /// M680X Hitachi 6309 mode
    CS_MODE_M680X_6800 = 1 << 3,    /// M680X Motorola 6800,6802 mode
    CS_MODE_M680X_6801 = 1 << 4,    /// M680X Motorola 6801,6803 mode
    CS_MODE_M680X_6805 = 1 << 5,    /// M680X Motorola/Freescale 6805 mode
    CS_MODE_M680X_6808 = 1 << 6,    /// M680X Motorola/Freescale/NXP 68HC08 mode
    CS_MODE_M680X_6809 = 1 << 7,    /// M680X Motorola 6809 mode
    CS_MODE_M680X_6811 = 1 << 8,    /// M680X Motorola/Freescale/NXP 68HC11 mode
    CS_MODE_M680X_CPU12 = 1 << 9,   /// M680X Motorola/Freescale/NXP CPU12
    ///< used on M68HC12/HCS12
    CS_MODE_M680X_HCS08 = 1 << 10 ///< M680X Freescale/NXP HCS08 mode
}
alias int cs_mode;

alias cs_malloc_t = void* function (size_t size);
alias cs_calloc_t = void* function (size_t nmemb, size_t size);
alias cs_realloc_t = void* function (void* ptr, size_t size);
alias cs_free_t = void function (void* ptr);
alias cs_vsnprintf_t = int function (char* str, size_t size, const(char)* format, va_list ap);

/// User-defined dynamic memory related functions: malloc/calloc/realloc/free/vsnprintf()
/// By default, Capstone uses system's malloc(), calloc(), realloc(), free() & vsnprintf().
struct cs_opt_mem
{
    cs_malloc_t malloc;
    cs_calloc_t calloc;
    cs_realloc_t realloc;
    cs_free_t free;
    cs_vsnprintf_t vsnprintf;
}

/// Customize mnemonic for instructions with alternative name.
/// To reset existing customized instruction to its default mnemonic,
/// call cs_option(CS_OPT_MNEMONIC) again with the same @id and NULL value
/// for @mnemonic.
struct cs_opt_mnem
{
    /// ID of instruction to be customized.
    uint id;
    /// Customized instruction mnemonic.
    const(char)* mnemonic;
}

/// Runtime option for the disassembled engine
enum
{
    CS_OPT_INVALID = 0,         /// No option specified
    CS_OPT_SYNTAX = 1,          /// Assembly output syntax
    CS_OPT_DETAIL = 2,          /// Break down instruction structure into details
    CS_OPT_MODE = 3,            /// Change engine's mode at run-time
    CS_OPT_MEM = 4,             /// User-defined dynamic memory related functions
    CS_OPT_SKIPDATA = 5,        /// Skip data when disassembling. Then engine is in SKIPDATA mode.
    CS_OPT_SKIPDATA_SETUP = 6,  /// Setup user-defined function for SKIPDATA option
    CS_OPT_MNEMONIC = 7,        /// Customize instruction mnemonic
    CS_OPT_UNSIGNED = 8,        /// print immediate operands in unsigned form
}
alias int cs_opt_type;

/// Runtime option value (associated with option type above)
enum
{
    CS_OPT_OFF = 0,     /// Turn OFF an option - default for CS_OPT_DETAIL, CS_OPT_SKIPDATA, CS_OPT_UNSIGNED.
    CS_OPT_ON = 3,      /// Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA).
    CS_OPT_SYNTAX_DEFAULT = 0,  /// Default asm syntax (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_INTEL = 1,    /// X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_ATT = 2,      /// X86 ATT asm syntax (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_NOREGNAME = 3,    /// Prints register name with only number (CS_OPT_SYNTAX)
    CS_OPT_SYNTAX_MASM = 4,     /// X86 Intel Masm syntax (CS_OPT_SYNTAX).
}
alias int cs_opt_value;

/// Common instruction operand types - to be consistent across all architectures.
enum
{
    CS_OP_INVALID = 0,  /// uninitialized/invalid operand.
    CS_OP_REG = 1,  /// Register operand.
    CS_OP_IMM = 2,  /// Immediate operand.
    CS_OP_MEM = 3,  /// Memory operand.
    CS_OP_FP = 4,   /// Floating-Point operand.
}
alias int cs_op_type;

/// Common instruction operand access types - to be consistent across all architectures.
/// It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
enum
{
    CS_AC_INVALID = 0,  /// Uninitialized/invalid access type.
    CS_AC_READ = 1 << 0,    /// Operand read from memory or register.
    CS_AC_WRITE = 1 << 1,   /// Operand write to memory or register.
}
alias int cs_ac_type;

/// Common instruction groups - to be consistent across all architectures.
enum
{
    CS_GRP_INVALID = 0, /// uninitialized/invalid group.
    CS_GRP_JUMP = 1,    /// all jump instructions (conditional+direct+indirect jumps)
    CS_GRP_CALL = 2,    /// all call instructions
    CS_GRP_RET = 3,     /// all return instructions
    CS_GRP_INT = 4,     /// all interrupt instructions (int+syscall)
    CS_GRP_IRET = 5,    /// all interrupt return instructions
    CS_GRP_PRIVILEGE = 6,   /// all privileged instructions
    CS_GRP_BRANCH_RELATIVE = 7, /// all relative branching instructions
}
alias int cs_group_type;

/**
 User-defined callback function for SKIPDATA option.
 See tests/test_skipdata.c for sample code demonstrating this API.

 @code: the input buffer containing code to be disassembled.
        This is the same buffer passed to cs_disasm().
 @code_size: size (in bytes) of the above @code buffer.
 @offset: the position of the currently-examining byte in the input
      buffer @code mentioned above.
 @user_data: user-data passed to cs_option() via @user_data field in
      cs_opt_skipdata struct below.

 @return: return number of bytes to skip, or 0 to immediately stop disassembling.
*/
alias cs_skipdata_cb_t = c_ulong function (const(ubyte)* code, size_t code_size, size_t offset, void* user_data);

/// User-customized setup for SKIPDATA option
struct cs_opt_skipdata
{
    /// Capstone considers data to skip as special "instructions".
    /// User can specify the string for this instruction's "mnemonic" here.
    /// By default (if @mnemonic is NULL), Capstone use ".byte".
    const(char)* mnemonic;

    /// User-defined callback function to be called when Capstone hits data.
    /// If the returned value from this callback is positive (>0), Capstone
    /// will skip exactly that number of bytes & continue. Otherwise, if
    /// the callback returns 0, Capstone stops disassembling and returns
    /// immediately from cs_disasm()
    /// NOTE: if this callback pointer is NULL, Capstone would skip a number
    /// of bytes depending on architectures, as following:
    /// Arm:     2 bytes (Thumb mode) or 4 bytes.
    /// Arm64:   4 bytes.
    /// Mips:    4 bytes.
    /// M680x:   1 byte.
    /// PowerPC: 4 bytes.
    /// Sparc:   4 bytes.
    /// SystemZ: 2 bytes.
    /// X86:     1 bytes.
    /// XCore:   2 bytes.
    /// EVM:     1 bytes.
    cs_skipdata_cb_t callback; // default value is NULL

    /// User-defined data to be passed to @callback function pointer.
    void* user_data;
}

/// NOTE: All information in cs_detail is only available when CS_OPT_DETAIL = CS_OPT_ON
/// Initialized as memset(., 0, offsetof(cs_detail, ARCH)+sizeof(cs_ARCH))
/// by ARCH_getInstruction in arch/ARCH/ARCHDisassembler.c
/// if cs_detail changes, in particular if a field is added after the union,
/// then update arch/ARCH/ARCHDisassembler.c accordingly
struct cs_detail
{
    ushort[12] regs_read; ///< list of implicit registers read by this insn
    ubyte regs_read_count; ///< number of implicit registers read by this insn

    ushort[20] regs_write; ///< list of implicit registers modified by this insn
    ubyte regs_write_count; ///< number of implicit registers modified by this insn

    ubyte[8] groups; ///< list of group this instruction belong to
    ubyte groups_count; ///< number of groups this insn belongs to

    /// Architecture-specific instruction info
    union
    {
        cs_x86 x86;     /// X86 architecture, including 16-bit, 32-bit & 64-bit mode
        cs_arm64 arm64; /// ARM64 architecture (aka AArch64)
        cs_arm arm;     /// ARM architecture (including Thumb/Thumb2)
        cs_m68k m68k;   /// M68K architecture
        cs_mips mips;   /// MIPS architecture
        cs_ppc ppc;     /// PowerPC architecture
        cs_sparc sparc; /// Sparc architecture
        cs_sysz sysz;   /// SystemZ architecture
        cs_xcore xcore; /// XCore architecture
        cs_tms320c64x tms320c64x;   /// TMS320C64x architecture
        cs_m680x m680x; /// M680X architecture
        cs_evm evm;     /// Ethereum architecture
    }
}

/// Detail information of disassembled instruction
struct cs_insn
{
    /// Instruction ID (basically a numeric ID for the instruction mnemonic)
    /// Find the instruction id in the '[ARCH]_insn' enum in the header file
    /// of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
    /// 'x86_insn' in x86.h for X86, etc...
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    /// NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
    uint id;

    /// Address (EIP) of this instruction
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    ulong address;

    /// Size of this instruction
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    ushort size;

    /// Machine bytes of this instruction, with number of bytes indicated by @size above
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    ubyte[16] bytes;

    /// Ascii text of instruction mnemonic
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    char[CS_MNEMONIC_SIZE] mnemonic;

    /// Ascii text of instruction operands
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    char[160] op_str;

    /// Pointer to cs_detail.
    /// NOTE: detail pointer is only valid when both requirements below are met:
    /// (1) CS_OP_DETAIL = CS_OPT_ON
    /// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
    ///
    /// NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
    ///     is not NULL, its content is still irrelevant.
    cs_detail* detail;
}

/// Calculate the offset of a disassembled instruction in its buffer, given its position
/// in its array of disassembled insn
/// NOTE: this macro works with position (>=1), not index
extern (D) auto CS_INSN_OFFSET(T0, T1)(auto ref T0 insns, auto ref T1 post)
{
    return insns[post - 1].address - insns[0].address;
}

/// All type of errors encountered by Capstone API.
/// These are values returned by cs_errno()
enum
{
    CS_ERR_OK = 0,      /// No error: everything was fine
    CS_ERR_MEM = 1,     /// Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    CS_ERR_ARCH = 2,    /// Unsupported architecture: cs_open()
    CS_ERR_HANDLE = 3,  /// Invalid handle: cs_op_count(), cs_op_index()
    CS_ERR_CSH = 4,     /// Invalid csh argument: cs_close(), cs_errno(), cs_option()
    CS_ERR_MODE = 5,    /// Invalid/unsupported mode: cs_open()
    CS_ERR_OPTION = 6,  /// Invalid/unsupported option: cs_option()
    CS_ERR_DETAIL = 7,  /// Information is unavailable because detail option is OFF
    CS_ERR_MEMSETUP = 8,    /// Dynamic memory management uninitialized (see CS_OPT_MEM)
    CS_ERR_VERSION = 9, /// Unsupported version (bindings)
    CS_ERR_DIET = 10,   /// Access irrelevant data in "diet" engine
    CS_ERR_SKIPDATA = 11,   /// Access irrelevant data for "data" instruction in SKIPDATA mode
    CS_ERR_X86_ATT = 12,    /// X86 AT&T syntax is unsupported (opt-out at compile time)
    CS_ERR_X86_INTEL = 13,  /// X86 Intel syntax is unsupported (opt-out at compile time)
    CS_ERR_X86_MASM = 14,   /// X86 Intel syntax is unsupported (opt-out at compile time)
}
alias int cs_err;

version (Capstone_Static) {

//
// ANCHOR: Static config
//

/**
 Return combined API version & major and minor version numbers.

 @major: major number of API version
 @minor: minor number of API version

 @return hexical number as (major << 8 | minor), which encodes both
	 major & minor versions.
	 NOTE: This returned value can be compared with version number made
	 with macro CS_MAKE_VERSION

 For example, second API version would return 1 in @major, and 1 in @minor
 The return value would be 0x0101

 NOTE: if you only care about returned value, but not major and minor values,
 set both @major & @minor arguments to NULL.
*/
uint cs_version (int* major, int* minor);

/**
 This API can be used to either ask for archs supported by this library,
 or check to see if the library was compile with 'diet' option (or called
 in 'diet' mode).

 To check if a particular arch is supported by this library, set @query to
 arch mode (CS_ARCH_* value).
 To verify if this library supports all the archs, use CS_ARCH_ALL.

 To check if this library is in 'diet' mode, set @query to CS_SUPPORT_DIET.

 @return True if this library supports the given arch, or in 'diet' mode.
*/
bool cs_support (int query);

/**
 Initialize CS handle: this must be done before any usage of CS.

 @arch: architecture type (CS_ARCH_*)
 @mode: hardware mode. This is combined of CS_MODE_*
 @handle: pointer to handle, which will be updated at return time

 @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
 for detailed error).
*/
cs_err cs_open (cs_arch arch, cs_mode mode, csh* handle);

/**
 Close CS handle: MUST do to release the handle when it is not used anymore.
 NOTE: this must be only called when there is no longer usage of Capstone,
 not even access to cs_insn array. The reason is the this API releases some
 cached memory, thus access to any Capstone API after cs_close() might crash
 your application.

 In fact,this API invalidate @handle by ZERO out its value (i.e *handle = 0).

 @handle: pointer to a handle returned by cs_open()

 @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
 for detailed error).
*/
cs_err cs_close (csh* handle);

/**
 Set option for disassembling engine at runtime

 @handle: handle returned by cs_open()
 @type: type of option to be set
 @value: option value corresponding with @type

 @return: CS_ERR_OK on success, or other value on failure.
 Refer to cs_err enum for detailed error.

 NOTE: in the case of CS_OPT_MEM, handle's value can be anything,
 so that cs_option(handle, CS_OPT_MEM, value) can (i.e must) be called
 even before cs_open()
*/
cs_err cs_option (csh handle, cs_opt_type type, size_t value);

/**
 Report the last error number when some API function fail.
 Like glibc's errno, cs_errno might not retain its old value once accessed.

 @handle: handle returned by cs_open()

 @return: error code of cs_err enum type (CS_ERR_*, see above)
*/
cs_err cs_errno (csh handle);

/**
 Return a string describing given error code.

 @code: error code (see CS_ERR_* above)

 @return: returns a pointer to a string that describes the error code
	passed in the argument @code
*/
const(char)* cs_strerror (cs_err code);

/**
 Disassemble binary code, given the code buffer, size, address and number
 of instructions to be decoded.
 This API dynamically allocate memory to contain disassembled instruction.
 Resulting instructions will be put into @*insn

 NOTE 1: this API will automatically determine memory needed to contain
 output disassembled instructions in @insn.

 NOTE 2: caller must free the allocated memory itself to avoid memory leaking.

 NOTE 3: for system with scarce memory to be dynamically allocated such as
 OS kernel or firmware, the API cs_disasm_iter() might be a better choice than
 cs_disasm(). The reason is that with cs_disasm(), based on limited available
 memory, we have to calculate in advance how many instructions to be disassembled,
 which complicates things. This is especially troublesome for the case @count=0,
 when cs_disasm() runs uncontrollably (until either end of input buffer, or
 when it encounters an invalid instruction).

 @handle: handle returned by cs_open()
 @code: buffer containing raw binary code to be disassembled.
 @code_size: size of the above code buffer.
 @address: address of the first instruction in given raw code buffer.
 @insn: array of instructions filled in by this API.
	   NOTE: @insn will be allocated by this function, and should be freed
	   with cs_free() API.
 @count: number of instructions to be disassembled, or 0 to get all of them

 @return: the number of successfully disassembled instructions,
 or 0 if this function failed to disassemble the given code

 On failure, call cs_errno() for error code.
*/
size_t cs_disasm (
    csh handle,
    const(ubyte)* code,
    size_t code_size,
    ulong address,
    size_t count,
    cs_insn** insn);

/**
  Deprecated function - to be retired in the next version!
  Use cs_disasm() instead of cs_disasm_ex()
*/
size_t cs_disasm_ex (
    csh handle,
    const(ubyte)* code,
    size_t code_size,
    ulong address,
    size_t count,
    cs_insn** insn);

/**
 Free memory allocated by cs_malloc() or cs_disasm() (argument @insn)

 @insn: pointer returned by @insn argument in cs_disasm() or cs_malloc()
 @count: number of cs_insn structures returned by cs_disasm(), or 1
     to free memory allocated by cs_malloc().
*/
void cs_free (cs_insn* insn, size_t count);

/**
 Allocate memory for 1 instruction to be used by cs_disasm_iter().

 @handle: handle returned by cs_open()

 NOTE: when no longer in use, you can reclaim the memory allocated for
 this instruction with cs_free(insn, 1)
*/
cs_insn* cs_malloc (csh handle);

/**
 Fast API to disassemble binary code, given the code buffer, size, address
 and number of instructions to be decoded.
 This API puts the resulting instruction into a given cache in @insn.
 See tests/test_iter.c for sample code demonstrating this API.

 NOTE 1: this API will update @code, @size & @address to point to the next
 instruction in the input buffer. Therefore, it is convenient to use
 cs_disasm_iter() inside a loop to quickly iterate all the instructions.
 While decoding one instruction at a time can also be achieved with
 cs_disasm(count=1), some benchmarks shown that cs_disasm_iter() can be 30%
 faster on random input.

 NOTE 2: the cache in @insn can be created with cs_malloc() API.

 NOTE 3: for system with scarce memory to be dynamically allocated such as
 OS kernel or firmware, this API is recommended over cs_disasm(), which
 allocates memory based on the number of instructions to be disassembled.
 The reason is that with cs_disasm(), based on limited available memory,
 we have to calculate in advance how many instructions to be disassembled,
 which complicates things. This is especially troublesome for the case
 @count=0, when cs_disasm() runs uncontrollably (until either end of input
 buffer, or when it encounters an invalid instruction).

 @handle: handle returned by cs_open()
 @code: buffer containing raw binary code to be disassembled
 @size: size of above code
 @address: address of the first insn in given raw code buffer
 @insn: pointer to instruction to be filled in by this API.

 @return: true if this API successfully decode 1 instruction,
 or false otherwise.

 On failure, call cs_errno() for error code.
*/
bool cs_disasm_iter (
    csh handle,
    const(ubyte*)* code,
    size_t* size,
    ulong* address,
    cs_insn* insn);

/**
 Return friendly name of register in a string.
 Find the instruction id from header file of corresponding architecture (arm.h for ARM,
 x86.h for X86, ...)

 WARN: when in 'diet' mode, this API is irrelevant because engine does not
 store register name.

 @handle: handle returned by cs_open()
 @reg_id: register id

 @return: string name of the register, or NULL if @reg_id is invalid.
*/
const(char)* cs_reg_name (csh handle, uint reg_id);

/**
 Return friendly name of an instruction in a string.
 Find the instruction id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 store instruction name.

 @handle: handle returned by cs_open()
 @insn_id: instruction id

 @return: string name of the instruction, or NULL if @insn_id is invalid.
*/
const(char)* cs_insn_name (csh handle, uint insn_id);

/**
 Return friendly name of a group id (that an instruction can belong to)
 Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 store group name.

 @handle: handle returned by cs_open()
 @group_id: group id

 @return: string name of the group, or NULL if @group_id is invalid.
*/
const(char)* cs_group_name (csh handle, uint group_id);

/**
 Check if a disassembled instruction belong to a particular group.
 Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
 Internally, this simply verifies if @group_id matches any member of insn->groups array.

 NOTE: this API is only valid when detail option is ON (which is OFF by default).

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 update @groups array.

 @handle: handle returned by cs_open()
 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @group_id: group that you want to check if this instruction belong to.

 @return: true if this instruction indeed belongs to the given group, or false otherwise.
*/
bool cs_insn_group (csh handle, const(cs_insn)* insn, uint group_id);

/**
 Check if a disassembled instruction IMPLICITLY used a particular register.
 Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
 Internally, this simply verifies if @reg_id matches any member of insn->regs_read array.

 NOTE: this API is only valid when detail option is ON (which is OFF by default)

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 update @regs_read array.

 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @reg_id: register that you want to check if this instruction used it.

 @return: true if this instruction indeed implicitly used the given register, or false otherwise.
*/
bool cs_reg_read (csh handle, const(cs_insn)* insn, uint reg_id);

/**
 Check if a disassembled instruction IMPLICITLY modified a particular register.
 Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
 Internally, this simply verifies if @reg_id matches any member of insn->regs_write array.

 NOTE: this API is only valid when detail option is ON (which is OFF by default)

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 update @regs_write array.

 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @reg_id: register that you want to check if this instruction modified it.

 @return: true if this instruction indeed implicitly modified the given register, or false otherwise.
*/
bool cs_reg_write (csh handle, const(cs_insn)* insn, uint reg_id);

/**
 Count the number of operands of a given type.
 Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

 NOTE: this API is only valid when detail option is ON (which is OFF by default)

 @handle: handle returned by cs_open()
 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @op_type: Operand type to be found.

 @return: number of operands of given type @op_type in instruction @insn,
 or -1 on failure.
*/
int cs_op_count (csh handle, const(cs_insn)* insn, uint op_type);

/**
 Retrieve the position of operand of given type in <arch>.operands[] array.
 Later, the operand can be accessed using the returned position.
 Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

 NOTE: this API is only valid when detail option is ON (which is OFF by default)

 @handle: handle returned by cs_open()
 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @op_type: Operand type to be found.
 @position: position of the operand to be found. This must be in the range
			[1, cs_op_count(handle, insn, op_type)]

 @return: index of operand of given type @op_type in <arch>.operands[] array
 in instruction @insn, or -1 on failure.
*/
int cs_op_index (csh handle, const(cs_insn)* insn, uint op_type, uint position);

/// Type of array to keep the list of registers
alias cs_regs = ushort[64];

/**
 Retrieve all the registers accessed by an instruction, either explicitly or
 implicitly.

 WARN: when in 'diet' mode, this API is irrelevant because engine does not
 store registers.

 @handle: handle returned by cs_open()
 @insn: disassembled instruction structure returned from cs_disasm() or cs_disasm_iter()
 @regs_read: on return, this array contains all registers read by instruction.
 @regs_read_count: number of registers kept inside @regs_read array.
 @regs_write: on return, this array contains all registers written by instruction.
 @regs_write_count: number of registers kept inside @regs_write array.

 @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
 for detailed error).
*/
cs_err cs_regs_access (
    csh handle,
    const(cs_insn)* insn,
    cs_regs regs_read,
    ubyte* regs_read_count,
    cs_regs regs_write,
    ubyte* regs_write_count);

} else {

//
// ANCHOR: Dynamic library
//

import bindbc.loader;
import bindbc.loader.sharedlib;

private {
    alias pcs_version = uint function(int* major, int* minor);
    alias pcs_support = uint function(int* major, int* minor);
    alias pcs_open = cs_err function(cs_arch arch, cs_mode mode, csh* handle);
    alias pcs_close = cs_err function(csh* handle);
    alias pcs_option = cs_err function(csh handle, cs_opt_type type, size_t value);
    alias pcs_errno = cs_err function(csh handle);
    alias pcs_strerror = const(char)* function(cs_err code);
    alias pcs_disasm = size_t function(
        csh handle,
        const(ubyte)* code,
        size_t code_size,
        ulong address,
        size_t count,
        cs_insn** insn);
    alias pcs_disasm_ex = size_t function(
        csh handle,
        const(ubyte)* code,
        size_t code_size,
        ulong address,
        size_t count,
        cs_insn** insn);
    alias pcs_free = void function(cs_insn* insn, size_t count);
    alias pcs_malloc = cs_insn* function(csh handle);
    alias pcs_disasm_iter = bool function(
        csh handle,
        const(ubyte*)* code,
        size_t* size,
        ulong* address,
        cs_insn* insn);
    alias pcs_reg_name = const(char)* function(csh handle, uint reg_id);
    alias pcs_insn_name = const(char)* function(csh handle, uint insn_id);
    alias pcs_group_name = const(char)* function(csh handle, uint group_id);
    alias pcs_insn_group = bool function(csh handle, const(cs_insn)* insn, uint group_id);
    alias pcs_reg_read = bool function(csh handle, const(cs_insn)* insn, uint reg_id);
    alias pcs_reg_write = bool function(csh handle, const(cs_insn)* insn, uint reg_id);
    alias pcs_op_count = int function(csh handle, const(cs_insn)* insn, uint op_type);
    alias pcs_op_index = int function(csh handle, const(cs_insn)* insn, uint op_type, uint position);
    alias pcs_regs_access = cs_err function(
        csh handle,
        const(cs_insn)* insn,
        cs_regs regs_read,
        ubyte* regs_read_count,
        cs_regs regs_write,
        ubyte* regs_write_count);
}

alias cs_regs = ushort[64];

__gshared pcs_version cs_version;
__gshared pcs_support cs_support;
__gshared pcs_open cs_open;
__gshared pcs_close cs_close;
__gshared pcs_option cs_option;
__gshared pcs_errno cs_errno;
__gshared pcs_strerror cs_strerror;
__gshared pcs_disasm cs_disasm;
__gshared pcs_disasm_ex cs_disasm_ex;
__gshared pcs_free cs_free;
__gshared pcs_malloc cs_malloc;
__gshared pcs_disasm_iter cs_disasm_iter;
__gshared pcs_reg_name cs_reg_name;
__gshared pcs_insn_name cs_insn_name;
__gshared pcs_group_name cs_group_name;
__gshared pcs_insn_group cs_insn_group;
__gshared pcs_reg_read cs_reg_read;
__gshared pcs_reg_write cs_reg_write;
__gshared pcs_op_count cs_op_count;
__gshared pcs_op_index cs_op_index;
__gshared pcs_regs_access cs_regs_access;

bool capstone_dyn_init()
{
    version (Windows)
    {
        static immutable const(char)*[] libraries = [
            "capstone.dll",
        ];
    }
    else version (OSX)
    {
        static immutable const(char)*[] libraries = [
            "libcapstone.dylib",
        ];
    }
    else version (Posix)
    {
        static immutable const(char)*[] libraries = [
            "libcapstone.so.4",
            "libcapstone.so",
        ];
    }
    
    SharedLib lib = void;
    
    foreach (libname; libraries)
    {
        if ((lib = load(libname)) == invalidHandle)
            continue;
        break;
    }
    
    bindSymbol(lib, cast(void**)&cs_version, "cs_version");
    bindSymbol(lib, cast(void**)&cs_support, "cs_support");
    bindSymbol(lib, cast(void**)&cs_open, "cs_open");
    bindSymbol(lib, cast(void**)&cs_close, "cs_close");
    bindSymbol(lib, cast(void**)&cs_option, "cs_option");
    bindSymbol(lib, cast(void**)&cs_errno, "cs_errno");
    bindSymbol(lib, cast(void**)&cs_strerror, "cs_strerror");
    bindSymbol(lib, cast(void**)&cs_disasm, "cs_disasm");
    bindSymbol(lib, cast(void**)&cs_disasm_ex, "cs_disasm_ex");
    bindSymbol(lib, cast(void**)&cs_free, "cs_free");
    bindSymbol(lib, cast(void**)&cs_malloc, "cs_malloc");
    bindSymbol(lib, cast(void**)&cs_disasm_iter, "cs_disasm_iter");
    bindSymbol(lib, cast(void**)&cs_reg_name, "cs_reg_name");
    bindSymbol(lib, cast(void**)&cs_insn_name, "cs_insn_name");
    bindSymbol(lib, cast(void**)&cs_group_name, "cs_group_name");
    bindSymbol(lib, cast(void**)&cs_insn_group, "cs_insn_group");
    bindSymbol(lib, cast(void**)&cs_reg_read, "cs_reg_read");
    bindSymbol(lib, cast(void**)&cs_reg_write, "cs_reg_write");
    bindSymbol(lib, cast(void**)&cs_op_count, "cs_op_count");
    bindSymbol(lib, cast(void**)&cs_op_index, "cs_op_index");
    bindSymbol(lib, cast(void**)&cs_regs_access, "cs_regs_access");
    
    return errorCount() > 0;
}

}
