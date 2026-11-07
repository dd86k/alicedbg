/// CodeView type records and information.
///
/// Sources:
/// - Microsoft Symbol and Type Information CodeView 1.0
/// - https://github.com/Microsoft/microsoft-pdb/blob/master/include/cvinfo.h
/// - https://llvm.org/docs/PDB/CodeViewSymbols.html
/// - https://llvm.org/docs/PDB/CodeViewTypes.html
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.types.cv;

// NOTE: CodeView Glossary
//
//       UDT
//           Likely means User-Defined Type.

// NOTE: CodeView Debug Sections
//
//       Version (bitfields?)
//       0x0000_0001: Microsoft CodeView 4.0 Debugger specifications
//       0x0000_0002: PDB 2.0, MSVC 2.0 and later
//       0x0000_0004: PDB 7.0, MSVC 7.0 and later (big offsets?)
//
//       Symbols (.debug$S in COFF objects)
//       Leaf: u16le:length, u16le:index/type, ...
//       example:
//                     +- Entry length (inclusive)
//                     |     +- S_OBJNAME_ST (0x0009)
//                     |     |               ++- Path length
//       |-version-| |-+-| |-+-| |signature| || "C:\"...
//       02 00 00 00 58 00 09 00 00 00 00 00 51 43 3a 5c
//
//       2-byte padding for 16:16 compilers, 4-byte padding for 16:32 compilers

extern (C):

enum CV_MMASK        = 0x700;	/// mode mask
enum CV_TMASK        = 0x0f0;	/// type mask

enum CV_SIGNATURE_C6         = 0; 	/// Actual signature is >64K
enum CV_SIGNATURE_C7         = 1; 	/// First explicit signature
enum CV_SIGNATURE_C11        = 2; 	/// C11 (vc5.x) 32-bit types
enum CV_SIGNATURE_C13        = 4; 	/// C13 (vc7.x) zero terminated names
enum CV_SIGNATURE_RESERVED   = 5; 	/// All signatures from 5 to 64K are reserved

// At least Leaf Records
struct cv_record_t {
	ushort length;
	ushort kind;
}

// Used in PDBs
alias LEAF_ENUM_e = ushort;
enum : LEAF_ENUM_e {
	// leaf indices starting records but referenced from symbol records

	LF_MODIFIER_16t     = 0x0001,
	LF_POINTER_16t      = 0x0002,
	LF_ARRAY_16t        = 0x0003,
	LF_CLASS_16t        = 0x0004,
	LF_STRUCTURE_16t    = 0x0005,
	LF_UNION_16t        = 0x0006,
	LF_ENUM_16t         = 0x0007,
	LF_PROCEDURE_16t    = 0x0008,
	LF_MFUNCTION_16t    = 0x0009,
	LF_VTSHAPE          = 0x000a,
	LF_COBOL0_16t       = 0x000b,
	LF_COBOL1           = 0x000c,
	LF_BARRAY_16t       = 0x000d,
	LF_LABEL            = 0x000e,
	LF_NULL             = 0x000f,
	LF_NOTTRAN          = 0x0010,
	LF_DIMARRAY_16t     = 0x0011,
	LF_VFTPATH_16t      = 0x0012,
	LF_PRECOMP_16t      = 0x0013,       // not referenced from symbol
	LF_ENDPRECOMP       = 0x0014,       // not referenced from symbol
	LF_OEM_16t          = 0x0015,       // oem definable type string
	LF_TYPESERVER_ST    = 0x0016,       // not referenced from symbol

	// leaf indices starting records but referenced only from type records

	LF_SKIP_16t         = 0x0200,
	LF_ARGLIST_16t      = 0x0201,
	LF_DEFARG_16t       = 0x0202,
	LF_LIST             = 0x0203,
	LF_FIELDLIST_16t    = 0x0204,
	LF_DERIVED_16t      = 0x0205,
	LF_BITFIELD_16t     = 0x0206,
	LF_METHODLIST_16t   = 0x0207,
	LF_DIMCONU_16t      = 0x0208,
	LF_DIMCONLU_16t     = 0x0209,
	LF_DIMVARU_16t      = 0x020a,
	LF_DIMVARLU_16t     = 0x020b,
	LF_REFSYM           = 0x020c,

	LF_BCLASS_16t       = 0x0400,
	LF_VBCLASS_16t      = 0x0401,
	LF_IVBCLASS_16t     = 0x0402,
	LF_ENUMERATE_ST     = 0x0403,
	LF_FRIENDFCN_16t    = 0x0404,
	LF_INDEX_16t        = 0x0405,
	LF_MEMBER_16t       = 0x0406,
	LF_STMEMBER_16t     = 0x0407,
	LF_METHOD_16t       = 0x0408,
	LF_NESTTYPE_16t     = 0x0409,
	LF_VFUNCTAB_16t     = 0x040a,
	LF_FRIENDCLS_16t    = 0x040b,
	LF_ONEMETHOD_16t    = 0x040c,
	LF_VFUNCOFF_16t     = 0x040d,

	// 32-bit type index versions of leaves, all have the 0x1000 bit set
	//
	LF_TI16_MAX         = 0x1000,

	LF_MODIFIER         = 0x1001,
	LF_POINTER          = 0x1002,
	LF_ARRAY_ST         = 0x1003,
	LF_CLASS_ST         = 0x1004,
	LF_STRUCTURE_ST     = 0x1005,
	LF_UNION_ST         = 0x1006,
	LF_ENUM_ST          = 0x1007,
	LF_PROCEDURE        = 0x1008,
	LF_MFUNCTION        = 0x1009,
	LF_COBOL0           = 0x100a,
	LF_BARRAY           = 0x100b,
	LF_DIMARRAY_ST      = 0x100c,
	LF_VFTPATH          = 0x100d,
	LF_PRECOMP_ST       = 0x100e,       // not referenced from symbol
	LF_OEM              = 0x100f,       // oem definable type string
	LF_ALIAS_ST         = 0x1010,       // alias (typedef) type
	LF_OEM2             = 0x1011,       // oem definable type string

	// leaf indices starting records but referenced only from type records

	LF_SKIP             = 0x1200,
	LF_ARGLIST          = 0x1201,
	LF_DEFARG_ST        = 0x1202,
	LF_FIELDLIST        = 0x1203,
	LF_DERIVED          = 0x1204,
	LF_BITFIELD         = 0x1205,
	LF_METHODLIST       = 0x1206,
	LF_DIMCONU          = 0x1207,
	LF_DIMCONLU         = 0x1208,
	LF_DIMVARU          = 0x1209,
	LF_DIMVARLU         = 0x120a,

	LF_BCLASS           = 0x1400,
	LF_VBCLASS          = 0x1401,
	LF_IVBCLASS         = 0x1402,
	LF_FRIENDFCN_ST     = 0x1403,
	LF_INDEX            = 0x1404,
	LF_MEMBER_ST        = 0x1405,
	LF_STMEMBER_ST      = 0x1406,
	LF_METHOD_ST        = 0x1407,
	LF_NESTTYPE_ST      = 0x1408,
	LF_VFUNCTAB         = 0x1409,
	LF_FRIENDCLS        = 0x140a,
	LF_ONEMETHOD_ST     = 0x140b,
	LF_VFUNCOFF         = 0x140c,
	LF_NESTTYPEEX_ST    = 0x140d,
	LF_MEMBERMODIFY_ST  = 0x140e,
	LF_MANAGED_ST       = 0x140f,

	// Types with SZ (null-terminated string) names

	LF_ST_MAX           = 0x1500,

	LF_TYPESERVER       = 0x1501,       // not referenced from symbol
	LF_ENUMERATE        = 0x1502,
	LF_ARRAY            = 0x1503,
	LF_CLASS            = 0x1504,
	LF_STRUCTURE        = 0x1505,
	LF_UNION            = 0x1506,
	LF_ENUM             = 0x1507,
	LF_DIMARRAY         = 0x1508,
	LF_PRECOMP          = 0x1509,       // not referenced from symbol
	LF_ALIAS            = 0x150a,       // alias (typedef) type
	LF_DEFARG           = 0x150b,
	LF_FRIENDFCN        = 0x150c,
	LF_MEMBER           = 0x150d,
	LF_STMEMBER         = 0x150e,
	LF_METHOD           = 0x150f,
	LF_NESTTYPE         = 0x1510,
	LF_ONEMETHOD        = 0x1511,
	LF_NESTTYPEEX       = 0x1512,
	LF_MEMBERMODIFY     = 0x1513,
	LF_MANAGED          = 0x1514,
	LF_TYPESERVER2      = 0x1515,

	/// Same as LF_ARRAY, but with stride between adjacent elements
	LF_STRIDED_ARRAY    = 0x1516,
	LF_HLSL             = 0x1517,
	LF_MODIFIER_EX      = 0x1518,
	LF_INTERFACE        = 0x1519,
	LF_BINTERFACE       = 0x151a,
	LF_VECTOR           = 0x151b,
	LF_MATRIX           = 0x151c,

	LF_VFTABLE          = 0x151d,      // a virtual function table
	LF_ENDOFLEAFRECORD  = LF_VFTABLE,

	LF_TYPE_LAST,                    // one greater than the last type record
	LF_TYPE_MAX         = LF_TYPE_LAST - 1,

	LF_FUNC_ID          = 0x1601,    // global func ID
	LF_MFUNC_ID         = 0x1602,    // member func ID
	LF_BUILDINFO        = 0x1603,    // build info: tool, version, command line, src/pdb file
	LF_SUBSTR_LIST      = 0x1604,    // similar to LF_ARGLIST, for list of sub strings
	LF_STRING_ID        = 0x1605,    // string ID

	/// Source and line on where an UDT is defined.
	/// Only generated by the compiler.
	LF_UDT_SRC_LINE     = 0x1606,

	/// Module, source, and line where an UDT is defined.
	/// Only generated by the linker.
	LF_UDT_MOD_SRC_LINE = 0x1607,

	/// one greater than the last ID record
	LF_ID_LAST,
	LF_ID_MAX           = LF_ID_LAST - 1,

	LF_NUMERIC          = 0x8000,
	LF_CHAR             = 0x8000,
	LF_SHORT            = 0x8001,
	LF_USHORT           = 0x8002,
	LF_LONG             = 0x8003,
	LF_ULONG            = 0x8004,
	LF_REAL32           = 0x8005,
	LF_REAL64           = 0x8006,
	LF_REAL80           = 0x8007,
	LF_REAL128          = 0x8008,
	LF_QUADWORD         = 0x8009,
	LF_UQUADWORD        = 0x800a,
	LF_REAL48           = 0x800b,
	LF_COMPLEX32        = 0x800c,
	LF_COMPLEX64        = 0x800d,
	LF_COMPLEX80        = 0x800e,
	LF_COMPLEX128       = 0x800f,
	LF_VARSTRING        = 0x8010,

	LF_OCTWORD          = 0x8017,
	LF_UOCTWORD         = 0x8018,

	LF_DECIMAL          = 0x8019,
	LF_DATE             = 0x801a,
	LF_UTF8STRING       = 0x801b,

	LF_REAL16           = 0x801c,

	LF_PAD0             = 0xf0,
	LF_PAD1             = 0xf1,
	LF_PAD2             = 0xf2,
	LF_PAD3             = 0xf3,
	LF_PAD4             = 0xf4,
	LF_PAD5             = 0xf5,
	LF_PAD6             = 0xf6,
	LF_PAD7             = 0xf7,
	LF_PAD8             = 0xf8,
	LF_PAD9             = 0xf9,
	LF_PAD10            = 0xfa,
	LF_PAD11            = 0xfb,
	LF_PAD12            = 0xfc,
	LF_PAD13            = 0xfd,
	LF_PAD14            = 0xfe,
	LF_PAD15            = 0xff,
}

const(char)* adbg_type_cv_leaf_enum_string(ushort val) {
	switch (val) {
	case LF_MODIFIER_16t:	return "LF_MODIFIER_16t";
	case LF_POINTER_16t:	return "LF_POINTER_16t";
	case LF_ARRAY_16t:	return "LF_ARRAY_16t";
	case LF_CLASS_16t:	return "LF_CLASS_16t";
	case LF_STRUCTURE_16t:	return "LF_STRUCTURE_16t";
	case LF_UNION_16t:	return "LF_UNION_16t";
	case LF_ENUM_16t:	return "LF_ENUM_16t";
	case LF_PROCEDURE_16t:	return "LF_PROCEDURE_16t";
	case LF_MFUNCTION_16t:	return "LF_MFUNCTION_16t";
	case LF_VTSHAPE:	return "LF_VTSHAPE";
	case LF_COBOL0_16t:	return "LF_COBOL0_16t";
	case LF_COBOL1:	return "LF_COBOL1";
	case LF_BARRAY_16t:	return "LF_BARRAY_16t";
	case LF_LABEL:	return "LF_LABEL";
	case LF_NULL:	return "LF_NULL";
	case LF_NOTTRAN:	return "LF_NOTTRAN";
	case LF_DIMARRAY_16t:	return "LF_DIMARRAY_16t";
	case LF_VFTPATH_16t:	return "LF_VFTPATH_16t";
	case LF_PRECOMP_16t:	return "LF_PRECOMP_16t";
	case LF_ENDPRECOMP:	return "LF_ENDPRECOMP";
	case LF_OEM_16t:	return "LF_OEM_16t";
	case LF_TYPESERVER_ST:	return "LF_TYPESERVER_ST";
	
	case LF_SKIP_16t:	return "LF_SKIP_16t";
	case LF_ARGLIST_16t:	return "LF_ARGLIST_16t";
	case LF_DEFARG_16t:	return "LF_DEFARG_16t";
	case LF_LIST:	return "LF_LIST";
	case LF_FIELDLIST_16t:	return "LF_FIELDLIST_16t";
	case LF_DERIVED_16t:	return "LF_DERIVED_16t";
	case LF_BITFIELD_16t:	return "LF_BITFIELD_16t";
	case LF_METHODLIST_16t:	return "LF_METHODLIST_16t";
	case LF_DIMCONU_16t:	return "LF_DIMCONU_16t";
	case LF_DIMCONLU_16t:	return "LF_DIMCONLU_16t";
	case LF_DIMVARU_16t:	return "LF_DIMVARU_16t";
	case LF_DIMVARLU_16t:	return "LF_DIMVARLU_16t";
	case LF_REFSYM:	return "LF_REFSYM";
	
	case LF_BCLASS_16t:	return "LF_BCLASS_16t";
	case LF_VBCLASS_16t:	return "LF_VBCLASS_16t";
	case LF_IVBCLASS_16t:	return "LF_IVBCLASS_16t";
	case LF_ENUMERATE_ST:	return "LF_ENUMERATE_ST";
	case LF_FRIENDFCN_16t:	return "LF_FRIENDFCN_16t";
	case LF_INDEX_16t:	return "LF_INDEX_16t";
	case LF_MEMBER_16t:	return "LF_MEMBER_16t";
	case LF_STMEMBER_16t:	return "LF_STMEMBER_16t";
	case LF_METHOD_16t:	return "LF_METHOD_16t";
	case LF_NESTTYPE_16t:	return "LF_NESTTYPE_16t";
	case LF_VFUNCTAB_16t:	return "LF_VFUNCTAB_16t";
	case LF_FRIENDCLS_16t:	return "LF_FRIENDCLS_16t";
	case LF_ONEMETHOD_16t:	return "LF_ONEMETHOD_16t";
	case LF_VFUNCOFF_16t:	return "LF_VFUNCOFF_16t";
	
	case LF_MODIFIER:	return "LF_MODIFIER";
	case LF_POINTER:	return "LF_POINTER";
	case LF_ARRAY_ST:	return "LF_ARRAY_ST";
	case LF_CLASS_ST:	return "LF_CLASS_ST";
	case LF_STRUCTURE_ST:	return "LF_STRUCTURE_ST";
	case LF_UNION_ST:	return "LF_UNION_ST";
	case LF_ENUM_ST:	return "LF_ENUM_ST";
	case LF_PROCEDURE:	return "LF_PROCEDURE";
	case LF_MFUNCTION:	return "LF_MFUNCTION";
	case LF_COBOL0:	return "LF_COBOL0";
	case LF_BARRAY:	return "LF_BARRAY";
	case LF_DIMARRAY_ST:	return "LF_DIMARRAY_ST";
	case LF_VFTPATH:	return "LF_VFTPATH";
	case LF_PRECOMP_ST:	return "LF_PRECOMP_ST";
	case LF_OEM:	return "LF_OEM";
	case LF_ALIAS_ST:	return "LF_ALIAS_ST";
	case LF_OEM2:	return "LF_OEM2";
	
	case LF_SKIP:	return "LF_SKIP";
	case LF_ARGLIST:	return "LF_ARGLIST";
	case LF_DEFARG_ST:	return "LF_DEFARG_ST";
	case LF_FIELDLIST:	return "LF_FIELDLIST";
	case LF_DERIVED:	return "LF_DERIVED";
	case LF_BITFIELD:	return "LF_BITFIELD";
	case LF_METHODLIST:	return "LF_METHODLIST";
	case LF_DIMCONU:	return "LF_DIMCONU";
	case LF_DIMCONLU:	return "LF_DIMCONLU";
	case LF_DIMVARU:	return "LF_DIMVARU";
	case LF_DIMVARLU:	return "LF_DIMVARLU";
	
	case LF_BCLASS:	return "LF_BCLASS";
	case LF_VBCLASS:	return "LF_VBCLASS";
	case LF_IVBCLASS:	return "LF_IVBCLASS";
	case LF_FRIENDFCN_ST:	return "LF_FRIENDFCN_ST";
	case LF_INDEX:	return "LF_INDEX";
	case LF_MEMBER_ST:	return "LF_MEMBER_ST";
	case LF_STMEMBER_ST:	return "LF_STMEMBER_ST";
	case LF_METHOD_ST:	return "LF_METHOD_ST";
	case LF_NESTTYPE_ST:	return "LF_NESTTYPE_ST";
	case LF_VFUNCTAB:	return "LF_VFUNCTAB";
	case LF_FRIENDCLS:	return "LF_FRIENDCLS";
	case LF_ONEMETHOD_ST:	return "LF_ONEMETHOD_ST";
	case LF_VFUNCOFF:	return "LF_VFUNCOFF";
	case LF_NESTTYPEEX_ST:	return "LF_NESTTYPEEX_ST";
	case LF_MEMBERMODIFY_ST:	return "LF_MEMBERMODIFY_ST";
	case LF_MANAGED_ST:	return "LF_MANAGED_ST";
	
	case LF_TYPESERVER:	return "LF_TYPESERVER";
	case LF_ENUMERATE:	return "LF_ENUMERATE";
	case LF_ARRAY:	return "LF_ARRAY";
	case LF_CLASS:	return "LF_CLASS";
	case LF_STRUCTURE:	return "LF_STRUCTURE";
	case LF_UNION:	return "LF_UNION";
	case LF_ENUM:	return "LF_ENUM";
	case LF_DIMARRAY:	return "LF_DIMARRAY";
	case LF_PRECOMP:	return "LF_PRECOMP";
	case LF_ALIAS:	return "LF_ALIAS";
	case LF_DEFARG:	return "LF_DEFARG";
	case LF_FRIENDFCN:	return "LF_FRIENDFCN";
	case LF_MEMBER:	return "LF_MEMBER";
	case LF_STMEMBER:	return "LF_STMEMBER";
	case LF_METHOD:	return "LF_METHOD";
	case LF_NESTTYPE:	return "LF_NESTTYPE";
	case LF_ONEMETHOD:	return "LF_ONEMETHOD";
	case LF_NESTTYPEEX:	return "LF_NESTTYPEEX";
	case LF_MEMBERMODIFY:	return "LF_MEMBERMODIFY";
	case LF_MANAGED:	return "LF_MANAGED";
	case LF_TYPESERVER2:	return "LF_TYPESERVER2";
	
	case LF_STRIDED_ARRAY:	return "LF_STRIDED_ARRAY";
	case LF_HLSL:	return "LF_HLSL";
	case LF_MODIFIER_EX:	return "LF_MODIFIER_EX";
	case LF_INTERFACE:	return "LF_INTERFACE";
	case LF_BINTERFACE:	return "LF_BINTERFACE";
	case LF_VECTOR:	return "LF_VECTOR";
	case LF_MATRIX:	return "LF_MATRIX";
	
	case LF_VFTABLE:	return "LF_VFTABLE";
	
	case LF_FUNC_ID:	return "LF_FUNC_ID";
	case LF_MFUNC_ID:	return "LF_MFUNC_ID";
	case LF_BUILDINFO:	return "LF_BUILDINFO";
	case LF_SUBSTR_LIST:	return "LF_SUBSTR_LIST";
	case LF_STRING_ID:	return "LF_STRING_ID";
	
	case LF_UDT_SRC_LINE:	return "LF_UDT_SRC_LINE";
	case LF_UDT_MOD_SRC_LINE:	return "LF_UDT_MOD_SRC_LINE";
	
	case LF_NUMERIC:	return "LF_NUMERIC";
//	case LF_CHAR:	return "LF_CHAR"; - Duplicate of LF_NUMERIC
	case LF_SHORT:	return "LF_SHORT";
	case LF_USHORT:	return "LF_USHORT";
	case LF_LONG:	return "LF_LONG";
	case LF_ULONG:	return "LF_ULONG";
	case LF_REAL32:	return "LF_REAL32";
	case LF_REAL64:	return "LF_REAL64";
	case LF_REAL80:	return "LF_REAL80";
	case LF_REAL128:	return "LF_REAL128";
	case LF_QUADWORD:	return "LF_QUADWORD";
	case LF_UQUADWORD:	return "LF_UQUADWORD";
	case LF_REAL48:	return "LF_REAL48";
	case LF_COMPLEX32:	return "LF_COMPLEX32";
	case LF_COMPLEX64:	return "LF_COMPLEX64";
	case LF_COMPLEX80:	return "LF_COMPLEX80";
	case LF_COMPLEX128:	return "LF_COMPLEX128";
	case LF_VARSTRING:	return "LF_VARSTRING";
	
	case LF_OCTWORD:	return "LF_OCTWORD";
	case LF_UOCTWORD:	return "LF_UOCTWORD";
	
	case LF_DECIMAL:	return "LF_DECIMAL";
	case LF_DATE:	return "LF_DATE";
	case LF_UTF8STRING:	return "LF_UTF8STRING";
	
	case LF_REAL16:	return "LF_REAL16";
	
	default:	return null;
	}
}

enum {
	CV_OEM_DIGITALMARS = 0x42,
}

alias SYM_ENUM_e = ushort;
enum : SYM_ENUM_e {
	S_COMPILE       =  0x0001,  // Compile flags symbol
	S_REGISTER_16t  =  0x0002,  // Register variable
	S_CONSTANT_16t  =  0x0003,  // constant symbol
	S_UDT_16t       =  0x0004,  // User defined type
	S_SSEARCH       =  0x0005,  // Start Search
	S_END           =  0x0006,  // Block, procedure, "with" or thunk end
	S_SKIP          =  0x0007,  // Reserve symbol space in $$Symbols table
	S_CVRESERVE     =  0x0008,  // Reserved symbol for CV internal use
	S_OBJNAME_ST    =  0x0009,  // path to object file name
	S_ENDARG        =  0x000a,  // end of argument/return list
	S_COBOLUDT_16t  =  0x000b,  // special UDT for cobol that does not symbol pack
	S_MANYREG_16t   =  0x000c,  // multiple register variable
	S_RETURN        =  0x000d,  // return description symbol
	S_ENTRYTHIS     =  0x000e,  // description of this pointer on entry

	S_BPREL16       =  0x0100,  // BP-relative
	S_LDATA16       =  0x0101,  // Module-local symbol
	S_GDATA16       =  0x0102,  // Global data symbol
	S_PUB16         =  0x0103,  // a public symbol
	S_LPROC16       =  0x0104,  // Local procedure start
	S_GPROC16       =  0x0105,  // Global procedure start
	S_THUNK16       =  0x0106,  // Thunk Start
	S_BLOCK16       =  0x0107,  // block start
	S_WITH16        =  0x0108,  // with start
	S_LABEL16       =  0x0109,  // code label
	S_CEXMODEL16    =  0x010a,  // change execution model
	S_VFTABLE16     =  0x010b,  // address of virtual function table
	S_REGREL16      =  0x010c,  // register relative address

	S_BPREL32_16t   =  0x0200,  // BP-relative
	S_LDATA32_16t   =  0x0201,  // Module-local symbol
	S_GDATA32_16t   =  0x0202,  // Global data symbol
	S_PUB32_16t     =  0x0203,  // a public symbol (CV internal reserved)
	S_LPROC32_16t   =  0x0204,  // Local procedure start
	S_GPROC32_16t   =  0x0205,  // Global procedure start
	S_THUNK32_ST    =  0x0206,  // Thunk Start
	S_BLOCK32_ST    =  0x0207,  // block start
	S_WITH32_ST     =  0x0208,  // with start
	S_LABEL32_ST    =  0x0209,  // code label
	S_CEXMODEL32    =  0x020a,  // change execution model
	S_VFTABLE32_16t =  0x020b,  // address of virtual function table
	S_REGREL32_16t  =  0x020c,  // register relative address
	S_LTHREAD32_16t =  0x020d,  // local thread storage
	S_GTHREAD32_16t =  0x020e,  // global thread storage
	S_SLINK32       =  0x020f,  // static link for MIPS EH implementation

	S_LPROCMIPS_16t =  0x0300,  // Local procedure start
	S_GPROCMIPS_16t =  0x0301,  // Global procedure start

	// if these ref symbols have names following then the names are in ST format
	S_PROCREF_ST    =  0x0400,  // Reference to a procedure
	S_DATAREF_ST    =  0x0401,  // Reference to data
	S_ALIGN         =  0x0402,  // Used for page alignment of symbols

	S_LPROCREF_ST   =  0x0403,  // Local Reference to a procedure
	S_OEM           =  0x0404,  // OEM defined symbol

	// sym records with 32-bit types embedded instead of 16-bit
	// all have 0x1000 bit set for easy identification
	// only do the 32-bit target versions since we don't really
	// care about 16-bit ones anymore.
	S_TI16_MAX          =  0x1000,

	// NOTE: DMD has S_REGISTER_V2 (same as S_REGISTER_ST)
	//       and S_CONSTANT_V2 (same as S_CONSTANT_ST)
	S_REGISTER_ST   =  0x1001,  // Register variable
	S_CONSTANT_ST   =  0x1002,  // constant symbol
	S_UDT_ST        =  0x1003,  // User defined type
	S_COBOLUDT_ST   =  0x1004,  // special UDT for cobol that does not symbol pack
	S_MANYREG_ST    =  0x1005,  // multiple register variable
	S_BPREL32_ST    =  0x1006,  // BP-relative
	S_LDATA32_ST    =  0x1007,  // Module-local symbol
	S_GDATA32_ST    =  0x1008,  // Global data symbol
	S_PUB32_ST      =  0x1009,  // a public symbol (CV internal reserved)
	S_LPROC32_ST    =  0x100a,  // Local procedure start
	S_GPROC32_ST    =  0x100b,  // Global procedure start
	S_VFTABLE32     =  0x100c,  // address of virtual function table
	S_REGREL32_ST   =  0x100d,  // register relative address
	S_LTHREAD32_ST  =  0x100e,  // local thread storage
	S_GTHREAD32_ST  =  0x100f,  // global thread storage

	S_LPROCMIPS_ST  =  0x1010,  // Local procedure start
	S_GPROCMIPS_ST  =  0x1011,  // Global procedure start

	S_FRAMEPROC     =  0x1012,  // extra frame and proc information
	S_COMPILE2_ST   =  0x1013,  // extended compile flags and info

	// new symbols necessary for 16-bit enumerates of IA64 registers
	// and IA64 specific symbols

	S_MANYREG2_ST   =  0x1014,  // multiple register variable
	S_LPROCIA64_ST  =  0x1015,  // Local procedure start (IA64)
	S_GPROCIA64_ST  =  0x1016,  // Global procedure start (IA64)

	// Local symbols for IL
	S_LOCALSLOT_ST  =  0x1017,  // local IL sym with field for local slot index
	S_PARAMSLOT_ST  =  0x1018,  // local IL sym with field for parameter slot index

	S_ANNOTATION    =  0x1019,  // Annotation string literals

	// symbols to support managed code debugging
	S_GMANPROC_ST   =  0x101a,  // Global proc
	S_LMANPROC_ST   =  0x101b,  // Local proc
	S_RESERVED1     =  0x101c,  // reserved
	S_RESERVED2     =  0x101d,  // reserved
	S_RESERVED3     =  0x101e,  // reserved
	S_RESERVED4     =  0x101f,  // reserved
	S_LMANDATA_ST   =  0x1020,
	S_GMANDATA_ST   =  0x1021,
	S_MANFRAMEREL_ST=  0x1022,
	S_MANREGISTER_ST=  0x1023,
	S_MANSLOT_ST    =  0x1024,
	S_MANMANYREG_ST =  0x1025,
	S_MANREGREL_ST  =  0x1026,
	S_MANMANYREG2_ST=  0x1027,
	S_MANTYPREF     =  0x1028,  // Index for type referenced by name from metadata
	S_UNAMESPACE_ST =  0x1029,  // Using namespace

	// Symbols w/ SZ name fields. All name fields contain utf8 encoded strings.
	S_ST_MAX        =  0x1100,  // starting point for SZ name symbols

	S_OBJNAME       =  0x1101,  // path to object file name
	S_THUNK32       =  0x1102,  // Thunk Start
	S_BLOCK32       =  0x1103,  // block start
	S_WITH32        =  0x1104,  // with start
	S_LABEL32       =  0x1105,  // code label
	S_REGISTER      =  0x1106,  // Register variable
	S_CONSTANT      =  0x1107,  // constant symbol
	S_UDT           =  0x1108,  // User defined type
	S_COBOLUDT      =  0x1109,  // special UDT for cobol that does not symbol pack
	S_MANYREG       =  0x110a,  // multiple register variable
	S_BPREL32       =  0x110b,  // BP-relative
	S_LDATA32       =  0x110c,  // Module-local symbol
	S_GDATA32       =  0x110d,  // Global data symbol
	S_PUB32         =  0x110e,  // a public symbol (CV internal reserved)
	S_LPROC32       =  0x110f,  // Local procedure start
	S_GPROC32       =  0x1110,  // Global procedure start
	S_REGREL32      =  0x1111,  // register relative address
	S_LTHREAD32     =  0x1112,  // local thread storage
	S_GTHREAD32     =  0x1113,  // global thread storage

	S_LPROCMIPS     =  0x1114,  // Local procedure start
	S_GPROCMIPS     =  0x1115,  // Global procedure start
	S_COMPILE2      =  0x1116,  // extended compile flags and info
	S_MANYREG2      =  0x1117,  // multiple register variable
	S_LPROCIA64     =  0x1118,  // Local procedure start (IA64)
	S_GPROCIA64     =  0x1119,  // Global procedure start (IA64)
	S_LOCALSLOT     =  0x111a,  // local IL sym with field for local slot index
	S_SLOT          = S_LOCALSLOT,  // alias for LOCALSLOT
	S_PARAMSLOT     =  0x111b,  // local IL sym with field for parameter slot index

	// symbols to support managed code debugging
	S_LMANDATA      =  0x111c,
	S_GMANDATA      =  0x111d,
	S_MANFRAMEREL   =  0x111e,
	S_MANREGISTER   =  0x111f,
	S_MANSLOT       =  0x1120,
	S_MANMANYREG    =  0x1121,
	S_MANREGREL     =  0x1122,
	S_MANMANYREG2   =  0x1123,
	S_UNAMESPACE    =  0x1124,  // Using namespace

	// ref symbols with name fields
	S_PROCREF       =  0x1125,  // Reference to a procedure
	S_DATAREF       =  0x1126,  // Reference to data
	S_LPROCREF      =  0x1127,  // Local Reference to a procedure
	S_ANNOTATIONREF =  0x1128,  // Reference to an S_ANNOTATION symbol
	S_TOKENREF      =  0x1129,  // Reference to one of the many MANPROCSYM's

	// continuation of managed symbols
	S_GMANPROC      =  0x112a,  // Global proc
	S_LMANPROC      =  0x112b,  // Local proc

	// short, light-weight thunks
	S_TRAMPOLINE    =  0x112c,  // trampoline thunks
	S_MANCONSTANT   =  0x112d,  // constants with metadata type info

	// native attributed local/parms
	S_ATTR_FRAMEREL =  0x112e,  // relative to virtual frame ptr
	S_ATTR_REGISTER =  0x112f,  // stored in a register
	S_ATTR_REGREL   =  0x1130,  // relative to register (alternate frame ptr)
	S_ATTR_MANYREG  =  0x1131,  // stored in >1 register

	// Separated code (from the compiler) support
	S_SEPCODE       =  0x1132,

	S_LOCAL_2005    =  0x1133,  // defines a local symbol in optimized code
	S_DEFRANGE_2005 =  0x1134,  // defines a single range of addresses in which symbol can be evaluated
	S_DEFRANGE2_2005 =  0x1135,  // defines ranges of addresses in which symbol can be evaluated

	S_SECTION       =  0x1136,  // A COFF section in a PE executable
	S_COFFGROUP     =  0x1137,  // A COFF group
	S_EXPORT        =  0x1138,  // A export

	S_CALLSITEINFO  =  0x1139,  // Indirect call site information
	S_FRAMECOOKIE   =  0x113a,  // Security cookie information

	S_DISCARDED     =  0x113b,  // Discarded by LINK /OPT:REF (experimental, see richards)

	S_COMPILE3      =  0x113c,  // Replacement for S_COMPILE2
	S_ENVBLOCK      =  0x113d,  // Environment block split off from S_COMPILE2

	S_LOCAL         =  0x113e,  // defines a local symbol in optimized code
	S_DEFRANGE      =  0x113f,  // defines a single range of addresses in which symbol can be evaluated
	S_DEFRANGE_SUBFIELD =  0x1140,           // ranges for a subfield

	S_DEFRANGE_REGISTER =  0x1141,           // ranges for en-registered symbol
	S_DEFRANGE_FRAMEPOINTER_REL =  0x1142,   // range for stack symbol.
	S_DEFRANGE_SUBFIELD_REGISTER =  0x1143,  // ranges for en-registered field of symbol
	S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE =  0x1144, // range for stack symbol span valid full scope of function body, gap might apply.
	S_DEFRANGE_REGISTER_REL =  0x1145, // range for symbol address as register + offset.

	// S_PROC symbols that reference ID instead of type
	S_LPROC32_ID     =  0x1146,
	S_GPROC32_ID     =  0x1147,
	S_LPROCMIPS_ID   =  0x1148,
	S_GPROCMIPS_ID   =  0x1149,
	S_LPROCIA64_ID   =  0x114a,
	S_GPROCIA64_ID   =  0x114b,

	S_BUILDINFO      = 0x114c, // build information.
	S_INLINESITE     = 0x114d, // inlined function callsite.
	S_INLINESITE_END = 0x114e,
	S_PROC_ID_END    = 0x114f,

	S_DEFRANGE_HLSL  = 0x1150,
	S_GDATA_HLSL     = 0x1151,
	S_LDATA_HLSL     = 0x1152,

	S_FILESTATIC     = 0x1153,

	// CC_DP_CXX
	S_LOCAL_DPC_GROUPSHARED = 0x1154, // DPC groupshared variable
	S_LPROC32_DPC = 0x1155, // DPC local procedure start
	S_LPROC32_DPC_ID =  0x1156,
	S_DEFRANGE_DPC_PTR_TAG =  0x1157, // DPC pointer tag definition range
	S_DPC_SYM_TAG_MAP = 0x1158, // DPC pointer tag value to symbol record map

	S_ARMSWITCHTABLE  = 0x1159,
	S_CALLEES = 0x115a,
	S_CALLERS = 0x115b,
	S_POGODATA = 0x115c,
	S_INLINESITE2 = 0x115d,      // extended inline site information

	S_HEAPALLOCSITE = 0x115e,    // heap allocation site

	S_MOD_TYPEREF = 0x115f,      // only generated at link time

	S_REF_MINIPDB = 0x1160,      // only generated at link time for mini PDB
	S_PDBMAP      = 0x1161,      // only generated at link time for mini PDB

	S_GDATA_HLSL32 = 0x1162,
	S_LDATA_HLSL32 = 0x1163,

	S_GDATA_HLSL32_EX = 0x1164,
	S_LDATA_HLSL32_EX = 0x1165,

	S_RECTYPE_MAX,               // one greater than last
	S_RECTYPE_LAST  = S_RECTYPE_MAX - 1,
	S_RECTYPE_PAD   = S_RECTYPE_MAX + 0x100 // Used *only* to verify symbol record types so that current PDB code can potentially read
				// future PDBs (assuming no format change, etc).
}

alias CV_CPU_TYPE_e = ushort;
enum : CV_CPU_TYPE_e {
	CV_CFL_8080         = 0x00,
	CV_CFL_8086         = 0x01,
	CV_CFL_80286        = 0x02,
	CV_CFL_80386        = 0x03,
	CV_CFL_80486        = 0x04,
	CV_CFL_PENTIUM      = 0x05,
	CV_CFL_PENTIUMII    = 0x06,
	CV_CFL_PENTIUMPRO   = CV_CFL_PENTIUMII,
	CV_CFL_PENTIUMIII   = 0x07,
	CV_CFL_MIPS         = 0x10,
	CV_CFL_MIPSR4000    = CV_CFL_MIPS,
	CV_CFL_MIPS16       = 0x11,
	CV_CFL_MIPS32       = 0x12,
	CV_CFL_MIPS64       = 0x13,
	CV_CFL_MIPSI        = 0x14,
	CV_CFL_MIPSII       = 0x15,
	CV_CFL_MIPSIII      = 0x16,
	CV_CFL_MIPSIV       = 0x17,
	CV_CFL_MIPSV        = 0x18,
	CV_CFL_M68000       = 0x20,
	CV_CFL_M68010       = 0x21,
	CV_CFL_M68020       = 0x22,
	CV_CFL_M68030       = 0x23,
	CV_CFL_M68040       = 0x24,
	CV_CFL_ALPHA        = 0x30,
	CV_CFL_ALPHA_21064  = CV_CFL_ALPHA,
	CV_CFL_ALPHA_21164  = 0x31,
	CV_CFL_ALPHA_21164A = 0x32,
	CV_CFL_ALPHA_21264  = 0x33,
	CV_CFL_ALPHA_21364  = 0x34,
	CV_CFL_PPC601       = 0x40,
	CV_CFL_PPC603       = 0x41,
	CV_CFL_PPC604       = 0x42,
	CV_CFL_PPC620       = 0x43,
	CV_CFL_PPCFP        = 0x44,
	CV_CFL_SH3          = 0x50,
	CV_CFL_SH3E         = 0x51,
	CV_CFL_SH3DSP       = 0x52,
	CV_CFL_SH4          = 0x53,
	CV_CFL_SHMEDIA      = 0x54,	/// SuperH 4A?
	CV_CFL_ARM3         = 0x60,
	CV_CFL_ARM4         = 0x61,
	CV_CFL_ARM4T        = 0x62,
	CV_CFL_ARM5         = 0x63,
	CV_CFL_ARM5T        = 0x64,
	CV_CFL_ARM6         = 0x65,
	CV_CFL_ARM_XMAC     = 0x66,	/// Arm with XMAC instruction
	CV_CFL_ARM_WMMX     = 0x67,	/// Intel XScale Wireless MMX
	CV_CFL_OMNI         = 0x70,	/// Intel Omni-Path Architecture?
	CV_CFL_IA64         = 0x80,
	CV_CFL_IA64_1       = 0x80,
	CV_CFL_IA64_2       = 0x81,
	CV_CFL_CEE          = 0x90,	/// COM+ EE (.NET IL instructions)
	CV_CFL_AM33         = 0xA0,
	CV_CFL_M32R         = 0xB0,
	CV_CFL_TRICORE      = 0xC0,
	CV_CFL_X64          = 0xD0,
	CV_CFL_AMD64        = CV_CFL_X64,
	CV_CFL_EBC          = 0xE0,	/// EFI Byte Code
	CV_CFL_THUMB        = 0xF0,
	CV_CFL_ARMNT        = 0xF4,
	CV_CFL_D3D11_SHADER = 0x100,
}

alias CV_type_e = ubyte;
enum : CV_type_e {
	CV_SPECIAL      = 0x00,         // special type size values
	CV_SIGNED       = 0x01,         // signed integral size values
	CV_UNSIGNED     = 0x02,         // unsigned integral size values
	CV_BOOLEAN      = 0x03,         // Boolean size values
	CV_REAL         = 0x04,         // real number size values
	CV_COMPLEX      = 0x05,         // complex number size values
	CV_SPECIAL2     = 0x06,         // second set of special types
	CV_INT          = 0x07,         // integral (int) values
	CV_CVRESERVED   = 0x0f,
}

// Type enum for pointer records
// Pointers can be one of the following types
alias CV_ptrtype_e = ubyte;
enum : CV_ptrtype_e {
	CV_PTR_NEAR         = 0x00, // 16 bit pointer
	CV_PTR_FAR          = 0x01, // 16:16 far pointer
	CV_PTR_HUGE         = 0x02, // 16:16 huge pointer
	CV_PTR_BASE_SEG     = 0x03, // based on segment
	CV_PTR_BASE_VAL     = 0x04, // based on value of base
	CV_PTR_BASE_SEGVAL  = 0x05, // based on segment value of base
	CV_PTR_BASE_ADDR    = 0x06, // based on address of base
	CV_PTR_BASE_SEGADDR = 0x07, // based on segment address of base
	CV_PTR_BASE_TYPE    = 0x08, // based on type
	CV_PTR_BASE_SELF    = 0x09, // based on self
	CV_PTR_NEAR32       = 0x0a, // 32 bit pointer
	CV_PTR_FAR32        = 0x0b, // 16:32 pointer
	CV_PTR_64           = 0x0c, // 64 bit pointer
	CV_PTR_UNUSEDPTR    = 0x0d  // first unused pointer type
}

//      Mode enum for pointers
//      Pointers can have one of the following modes
//
//  To support for l-value and r-value reference, we added CV_PTR_MODE_LVREF
//  and CV_PTR_MODE_RVREF.  CV_PTR_MODE_REF should be removed at some point.
//  We keep it now so that old code that uses it won't be broken.
alias CV_ptrmode_e = ubyte;
enum : CV_ptrmode_e {
	CV_PTR_MODE_PTR     = 0x00, // "normal" pointer
	CV_PTR_MODE_REF     = 0x01, // "old" reference
	CV_PTR_MODE_LVREF   = 0x01, // l-value reference
	CV_PTR_MODE_PMEM    = 0x02, // pointer to data member
	CV_PTR_MODE_PMFUNC  = 0x03, // pointer to member function
	CV_PTR_MODE_RVREF   = 0x04, // r-value reference
	CV_PTR_MODE_RESERVED= 0x05  // first unused pointer mode
}


// Enumeration for pointer-to-member types
alias CV_pmtype_e = ubyte;
enum : CV_pmtype_e {
	CV_PMTYPE_Undef     = 0x00, // not specified (pre VC8)
	CV_PMTYPE_D_Single  = 0x01, // member data, single inheritance
	CV_PMTYPE_D_Multiple= 0x02, // member data, multiple inheritance
	CV_PMTYPE_D_Virtual = 0x03, // member data, virtual inheritance
	CV_PMTYPE_D_General = 0x04, // member data, most general
	CV_PMTYPE_F_Single  = 0x05, // member function, single inheritance
	CV_PMTYPE_F_Multiple= 0x06, // member function, multiple inheritance
	CV_PMTYPE_F_Virtual = 0x07, // member function, virtual inheritance
	CV_PMTYPE_F_General = 0x08, // member function, most general
}

// Enumeration for method properties
alias CV_methodprop_e = ubyte;
enum : CV_methodprop_e {
	CV_MTvanilla        = 0x00,
	CV_MTvirtual        = 0x01,
	CV_MTstatic         = 0x02,
	CV_MTfriend         = 0x03,
	CV_MTintro          = 0x04,
	CV_MTpurevirt       = 0x05,
	CV_MTpureintro      = 0x06
}

// Subtype enumeration values for CV_SPECIAL
alias CV_special_e = ubyte;
enum : CV_special_e {
	CV_SP_NOTYPE    = 0x00,
	CV_SP_ABS       = 0x01,
	CV_SP_SEGMENT   = 0x02,
	CV_SP_VOID      = 0x03,
	CV_SP_CURRENCY  = 0x04,
	CV_SP_NBASICSTR = 0x05,
	CV_SP_FBASICSTR = 0x06,
	CV_SP_NOTTRANS  = 0x07,
	CV_SP_HRESULT   = 0x08,
}

// Subtype enumeration values for CV_SPECIAL2
alias CV_special2_e = ubyte;
enum : CV_special2_e {
	CV_S2_BIT       = 0x00,
	CV_S2_PASCHAR   = 0x01,         // Pascal CHAR
	CV_S2_BOOL32FF  = 0x02,         // 32-bit BOOL where true is 0xffffffff
}

// Subtype enumeration values for CV_SIGNED, CV_UNSIGNED and CV_BOOLEAN
alias CV_integral_e = ubyte;
enum : CV_integral_e {
	CV_IN_1BYTE     = 0x00,
	CV_IN_2BYTE     = 0x01,
	CV_IN_4BYTE     = 0x02,
	CV_IN_8BYTE     = 0x03,
	CV_IN_16BYTE    = 0x04
}

// Subtype enumeration values for CV_REAL and CV_COMPLEX
alias CV_real_e = ubyte;
enum : CV_real_e {
	CV_RC_REAL32    = 0x00,
	CV_RC_REAL64    = 0x01,
	CV_RC_REAL80    = 0x02,
	CV_RC_REAL128   = 0x03,
	CV_RC_REAL48    = 0x04,
	CV_RC_REAL32PP  = 0x05,   // 32-bit partial precision real
	CV_RC_REAL16    = 0x06,
}

// Subtype enumeration values for CV_INT (really int)
alias CV_int_e = ubyte;
enum : CV_int_e {
	CV_RI_CHAR      = 0x00,
	CV_RI_INT1      = 0x00,
	CV_RI_WCHAR     = 0x01,
	CV_RI_UINT1     = 0x01,
	CV_RI_INT2      = 0x02,
	CV_RI_UINT2     = 0x03,
	CV_RI_INT4      = 0x04,
	CV_RI_UINT4     = 0x05,
	CV_RI_INT8      = 0x06,
	CV_RI_UINT8     = 0x07,
	CV_RI_INT16     = 0x08,
	CV_RI_UINT16    = 0x09,
	CV_RI_CHAR16    = 0x0a,  // char16_t
	CV_RI_CHAR32    = 0x0b,  // char32_t
}


// Special Types
alias TYPE_ENUM_e = ushort;
enum : TYPE_ENUM_e {
	T_NOTYPE        = 0x0000,   // uncharacterized type (no type)
	T_ABS           = 0x0001,   // absolute symbol
	T_SEGMENT       = 0x0002,   // segment type
	T_VOID          = 0x0003,   // void
	T_HRESULT       = 0x0008,   // OLE/COM HRESULT
	T_32PHRESULT    = 0x0408,   // OLE/COM HRESULT __ptr32 *
	T_64PHRESULT    = 0x0608,   // OLE/COM HRESULT __ptr64 *

	T_PVOID         = 0x0103,   // near pointer to void
	T_PFVOID        = 0x0203,   // far pointer to void
	T_PHVOID        = 0x0303,   // huge pointer to void
	T_32PVOID       = 0x0403,   // 32 bit pointer to void
	T_32PFVOID      = 0x0503,   // 16:32 pointer to void
	T_64PVOID       = 0x0603,   // 64 bit pointer to void
	T_CURRENCY      = 0x0004,   // BASIC 8 byte currency value
	T_NBASICSTR     = 0x0005,   // Near BASIC string
	T_FBASICSTR     = 0x0006,   // Far BASIC string
	T_NOTTRANS      = 0x0007,   // type not translated by cvpack
	T_BIT           = 0x0060,   // bit
	T_PASCHAR       = 0x0061,   // Pascal CHAR
	T_BOOL32FF      = 0x0062,   // 32-bit BOOL where true is 0xffffffff


	//      Character "char" types

	T_CHAR          = 0x0010,   // 8 bit signed
	T_PCHAR         = 0x0110,   // 16 bit pointer to 8 bit signed
	T_PFCHAR        = 0x0210,   // 16:16 far pointer to 8 bit signed
	T_PHCHAR        = 0x0310,   // 16:16 huge pointer to 8 bit signed
	T_32PCHAR       = 0x0410,   // 32 bit pointer to 8 bit signed
	T_32PFCHAR      = 0x0510,   // 16:32 pointer to 8 bit signed
	T_64PCHAR       = 0x0610,   // 64 bit pointer to 8 bit signed

	T_UCHAR         = 0x0020,   // 8 bit unsigned
	T_PUCHAR        = 0x0120,   // 16 bit pointer to 8 bit unsigned
	T_PFUCHAR       = 0x0220,   // 16:16 far pointer to 8 bit unsigned
	T_PHUCHAR       = 0x0320,   // 16:16 huge pointer to 8 bit unsigned
	T_32PUCHAR      = 0x0420,   // 32 bit pointer to 8 bit unsigned
	T_32PFUCHAR     = 0x0520,   // 16:32 pointer to 8 bit unsigned
	T_64PUCHAR      = 0x0620,   // 64 bit pointer to 8 bit unsigned


	//      Character types

	T_RCHAR         = 0x0070,   // really a char
	T_PRCHAR        = 0x0170,   // 16 bit pointer to a real char
	T_PFRCHAR       = 0x0270,   // 16:16 far pointer to a real char
	T_PHRCHAR       = 0x0370,   // 16:16 huge pointer to a real char
	T_32PRCHAR      = 0x0470,   // 32 bit pointer to a real char
	T_32PFRCHAR     = 0x0570,   // 16:32 pointer to a real char
	T_64PRCHAR      = 0x0670,   // 64 bit pointer to a real char


	//      Wide character types

	T_WCHAR         = 0x0071,   // wide char
	T_PWCHAR        = 0x0171,   // 16 bit pointer to a wide char
	T_PFWCHAR       = 0x0271,   // 16:16 far pointer to a wide char
	T_PHWCHAR       = 0x0371,   // 16:16 huge pointer to a wide char
	T_32PWCHAR      = 0x0471,   // 32 bit pointer to a wide char
	T_32PFWCHAR     = 0x0571,   // 16:32 pointer to a wide char
	T_64PWCHAR      = 0x0671,   // 64 bit pointer to a wide char

	//      16-bit Unicode character types

	T_CHAR16         = 0x007a,   // 16-bit unicode char
	T_PCHAR16        = 0x017a,   // 16 bit pointer to a 16-bit unicode char
	T_PFCHAR16       = 0x027a,   // 16:16 far pointer to a 16-bit unicode char
	T_PHCHAR16       = 0x037a,   // 16:16 huge pointer to a 16-bit unicode char
	T_32PCHAR16      = 0x047a,   // 32 bit pointer to a 16-bit unicode char
	T_32PFCHAR16     = 0x057a,   // 16:32 pointer to a 16-bit unicode char
	T_64PCHAR16      = 0x067a,   // 64 bit pointer to a 16-bit unicode char

	//     32-bit Unicode character types

	T_CHAR32         = 0x007b,   // 32-bit unicode char
	T_PCHAR32        = 0x017b,   // 16 bit pointer to a 32-bit unicode char
	T_PFCHAR32       = 0x027b,   // 16:16 far pointer to a 32-bit unicode char
	T_PHCHAR32       = 0x037b,   // 16:16 huge pointer to a 32-bit unicode char
	T_32PCHAR32      = 0x047b,   // 32 bit pointer to a 32-bit unicode char
	T_32PFCHAR32     = 0x057b,   // 16:32 pointer to a 32-bit unicode char
	T_64PCHAR32      = 0x067b,   // 64 bit pointer to a 32-bit unicode char

	//      8-bit byte types

	T_INT1          = 0x0068,   // 8 bit signed int
	T_PINT1         = 0x0168,   // 16 bit pointer to 8 bit signed int
	T_PFINT1        = 0x0268,   // 16:16 far pointer to 8 bit signed int
	T_PHINT1        = 0x0368,   // 16:16 huge pointer to 8 bit signed int
	T_32PINT1       = 0x0468,   // 32 bit pointer to 8 bit signed int
	T_32PFINT1      = 0x0568,   // 16:32 pointer to 8 bit signed int
	T_64PINT1       = 0x0668,   // 64 bit pointer to 8 bit signed int

	T_UINT1         = 0x0069,   // 8 bit unsigned int
	T_PUINT1        = 0x0169,   // 16 bit pointer to 8 bit unsigned int
	T_PFUINT1       = 0x0269,   // 16:16 far pointer to 8 bit unsigned int
	T_PHUINT1       = 0x0369,   // 16:16 huge pointer to 8 bit unsigned int
	T_32PUINT1      = 0x0469,   // 32 bit pointer to 8 bit unsigned int
	T_32PFUINT1     = 0x0569,   // 16:32 pointer to 8 bit unsigned int
	T_64PUINT1      = 0x0669,   // 64 bit pointer to 8 bit unsigned int


	//      16-bit short types

	T_SHORT         = 0x0011,   // 16 bit signed
	T_PSHORT        = 0x0111,   // 16 bit pointer to 16 bit signed
	T_PFSHORT       = 0x0211,   // 16:16 far pointer to 16 bit signed
	T_PHSHORT       = 0x0311,   // 16:16 huge pointer to 16 bit signed
	T_32PSHORT      = 0x0411,   // 32 bit pointer to 16 bit signed
	T_32PFSHORT     = 0x0511,   // 16:32 pointer to 16 bit signed
	T_64PSHORT      = 0x0611,   // 64 bit pointer to 16 bit signed

	T_USHORT        = 0x0021,   // 16 bit unsigned
	T_PUSHORT       = 0x0121,   // 16 bit pointer to 16 bit unsigned
	T_PFUSHORT      = 0x0221,   // 16:16 far pointer to 16 bit unsigned
	T_PHUSHORT      = 0x0321,   // 16:16 huge pointer to 16 bit unsigned
	T_32PUSHORT     = 0x0421,   // 32 bit pointer to 16 bit unsigned
	T_32PFUSHORT    = 0x0521,   // 16:32 pointer to 16 bit unsigned
	T_64PUSHORT     = 0x0621,   // 64 bit pointer to 16 bit unsigned


	//      16-bit int types

	T_INT2          = 0x0072,   // 16 bit signed int
	T_PINT2         = 0x0172,   // 16 bit pointer to 16 bit signed int
	T_PFINT2        = 0x0272,   // 16:16 far pointer to 16 bit signed int
	T_PHINT2        = 0x0372,   // 16:16 huge pointer to 16 bit signed int
	T_32PINT2       = 0x0472,   // 32 bit pointer to 16 bit signed int
	T_32PFINT2      = 0x0572,   // 16:32 pointer to 16 bit signed int
	T_64PINT2       = 0x0672,   // 64 bit pointer to 16 bit signed int

	T_UINT2         = 0x0073,   // 16 bit unsigned int
	T_PUINT2        = 0x0173,   // 16 bit pointer to 16 bit unsigned int
	T_PFUINT2       = 0x0273,   // 16:16 far pointer to 16 bit unsigned int
	T_PHUINT2       = 0x0373,   // 16:16 huge pointer to 16 bit unsigned int
	T_32PUINT2      = 0x0473,   // 32 bit pointer to 16 bit unsigned int
	T_32PFUINT2     = 0x0573,   // 16:32 pointer to 16 bit unsigned int
	T_64PUINT2      = 0x0673,   // 64 bit pointer to 16 bit unsigned int


	//      32-bit long types

	T_LONG          = 0x0012,   // 32 bit signed
	T_ULONG         = 0x0022,   // 32 bit unsigned
	T_PLONG         = 0x0112,   // 16 bit pointer to 32 bit signed
	T_PULONG        = 0x0122,   // 16 bit pointer to 32 bit unsigned
	T_PFLONG        = 0x0212,   // 16:16 far pointer to 32 bit signed
	T_PFULONG       = 0x0222,   // 16:16 far pointer to 32 bit unsigned
	T_PHLONG        = 0x0312,   // 16:16 huge pointer to 32 bit signed
	T_PHULONG       = 0x0322,   // 16:16 huge pointer to 32 bit unsigned

	T_32PLONG       = 0x0412,   // 32 bit pointer to 32 bit signed
	T_32PULONG      = 0x0422,   // 32 bit pointer to 32 bit unsigned
	T_32PFLONG      = 0x0512,   // 16:32 pointer to 32 bit signed
	T_32PFULONG     = 0x0522,   // 16:32 pointer to 32 bit unsigned
	T_64PLONG       = 0x0612,   // 64 bit pointer to 32 bit signed
	T_64PULONG      = 0x0622,   // 64 bit pointer to 32 bit unsigned


	//      32-bit int types

	T_INT4          = 0x0074,   // 32 bit signed int
	T_PINT4         = 0x0174,   // 16 bit pointer to 32 bit signed int
	T_PFINT4        = 0x0274,   // 16:16 far pointer to 32 bit signed int
	T_PHINT4        = 0x0374,   // 16:16 huge pointer to 32 bit signed int
	T_32PINT4       = 0x0474,   // 32 bit pointer to 32 bit signed int
	T_32PFINT4      = 0x0574,   // 16:32 pointer to 32 bit signed int
	T_64PINT4       = 0x0674,   // 64 bit pointer to 32 bit signed int

	T_UINT4         = 0x0075,   // 32 bit unsigned int
	T_PUINT4        = 0x0175,   // 16 bit pointer to 32 bit unsigned int
	T_PFUINT4       = 0x0275,   // 16:16 far pointer to 32 bit unsigned int
	T_PHUINT4       = 0x0375,   // 16:16 huge pointer to 32 bit unsigned int
	T_32PUINT4      = 0x0475,   // 32 bit pointer to 32 bit unsigned int
	T_32PFUINT4     = 0x0575,   // 16:32 pointer to 32 bit unsigned int
	T_64PUINT4      = 0x0675,   // 64 bit pointer to 32 bit unsigned int


	//      64-bit quad types

	T_QUAD          = 0x0013,   // 64 bit signed
	T_PQUAD         = 0x0113,   // 16 bit pointer to 64 bit signed
	T_PFQUAD        = 0x0213,   // 16:16 far pointer to 64 bit signed
	T_PHQUAD        = 0x0313,   // 16:16 huge pointer to 64 bit signed
	T_32PQUAD       = 0x0413,   // 32 bit pointer to 64 bit signed
	T_32PFQUAD      = 0x0513,   // 16:32 pointer to 64 bit signed
	T_64PQUAD       = 0x0613,   // 64 bit pointer to 64 bit signed

	T_UQUAD         = 0x0023,   // 64 bit unsigned
	T_PUQUAD        = 0x0123,   // 16 bit pointer to 64 bit unsigned
	T_PFUQUAD       = 0x0223,   // 16:16 far pointer to 64 bit unsigned
	T_PHUQUAD       = 0x0323,   // 16:16 huge pointer to 64 bit unsigned
	T_32PUQUAD      = 0x0423,   // 32 bit pointer to 64 bit unsigned
	T_32PFUQUAD     = 0x0523,   // 16:32 pointer to 64 bit unsigned
	T_64PUQUAD      = 0x0623,   // 64 bit pointer to 64 bit unsigned


	//      64-bit int types

	T_INT8          = 0x0076,   // 64 bit signed int
	T_PINT8         = 0x0176,   // 16 bit pointer to 64 bit signed int
	T_PFINT8        = 0x0276,   // 16:16 far pointer to 64 bit signed int
	T_PHINT8        = 0x0376,   // 16:16 huge pointer to 64 bit signed int
	T_32PINT8       = 0x0476,   // 32 bit pointer to 64 bit signed int
	T_32PFINT8      = 0x0576,   // 16:32 pointer to 64 bit signed int
	T_64PINT8       = 0x0676,   // 64 bit pointer to 64 bit signed int

	T_UINT8         = 0x0077,   // 64 bit unsigned int
	T_PUINT8        = 0x0177,   // 16 bit pointer to 64 bit unsigned int
	T_PFUINT8       = 0x0277,   // 16:16 far pointer to 64 bit unsigned int
	T_PHUINT8       = 0x0377,   // 16:16 huge pointer to 64 bit unsigned int
	T_32PUINT8      = 0x0477,   // 32 bit pointer to 64 bit unsigned int
	T_32PFUINT8     = 0x0577,   // 16:32 pointer to 64 bit unsigned int
	T_64PUINT8      = 0x0677,   // 64 bit pointer to 64 bit unsigned int


	//      128-bit octet types

	T_OCT           = 0x0014,   // 128 bit signed
	T_POCT          = 0x0114,   // 16 bit pointer to 128 bit signed
	T_PFOCT         = 0x0214,   // 16:16 far pointer to 128 bit signed
	T_PHOCT         = 0x0314,   // 16:16 huge pointer to 128 bit signed
	T_32POCT        = 0x0414,   // 32 bit pointer to 128 bit signed
	T_32PFOCT       = 0x0514,   // 16:32 pointer to 128 bit signed
	T_64POCT        = 0x0614,   // 64 bit pointer to 128 bit signed

	T_UOCT          = 0x0024,   // 128 bit unsigned
	T_PUOCT         = 0x0124,   // 16 bit pointer to 128 bit unsigned
	T_PFUOCT        = 0x0224,   // 16:16 far pointer to 128 bit unsigned
	T_PHUOCT        = 0x0324,   // 16:16 huge pointer to 128 bit unsigned
	T_32PUOCT       = 0x0424,   // 32 bit pointer to 128 bit unsigned
	T_32PFUOCT      = 0x0524,   // 16:32 pointer to 128 bit unsigned
	T_64PUOCT       = 0x0624,   // 64 bit pointer to 128 bit unsigned


	//      128-bit int types

	T_INT16         = 0x0078,   // 128 bit signed int
	T_PINT16        = 0x0178,   // 16 bit pointer to 128 bit signed int
	T_PFINT16       = 0x0278,   // 16:16 far pointer to 128 bit signed int
	T_PHINT16       = 0x0378,   // 16:16 huge pointer to 128 bit signed int
	T_32PINT16      = 0x0478,   // 32 bit pointer to 128 bit signed int
	T_32PFINT16     = 0x0578,   // 16:32 pointer to 128 bit signed int
	T_64PINT16      = 0x0678,   // 64 bit pointer to 128 bit signed int

	T_UINT16        = 0x0079,   // 128 bit unsigned int
	T_PUINT16       = 0x0179,   // 16 bit pointer to 128 bit unsigned int
	T_PFUINT16      = 0x0279,   // 16:16 far pointer to 128 bit unsigned int
	T_PHUINT16      = 0x0379,   // 16:16 huge pointer to 128 bit unsigned int
	T_32PUINT16     = 0x0479,   // 32 bit pointer to 128 bit unsigned int
	T_32PFUINT16    = 0x0579,   // 16:32 pointer to 128 bit unsigned int
	T_64PUINT16     = 0x0679,   // 64 bit pointer to 128 bit unsigned int


	//      16-bit real types

	T_REAL16        = 0x0046,   // 16 bit real
	T_PREAL16       = 0x0146,   // 16 bit pointer to 16 bit real
	T_PFREAL16      = 0x0246,   // 16:16 far pointer to 16 bit real
	T_PHREAL16      = 0x0346,   // 16:16 huge pointer to 16 bit real
	T_32PREAL16     = 0x0446,   // 32 bit pointer to 16 bit real
	T_32PFREAL16    = 0x0546,   // 16:32 pointer to 16 bit real
	T_64PREAL16     = 0x0646,   // 64 bit pointer to 16 bit real


	//      32-bit real types

	T_REAL32        = 0x0040,   // 32 bit real
	T_PREAL32       = 0x0140,   // 16 bit pointer to 32 bit real
	T_PFREAL32      = 0x0240,   // 16:16 far pointer to 32 bit real
	T_PHREAL32      = 0x0340,   // 16:16 huge pointer to 32 bit real
	T_32PREAL32     = 0x0440,   // 32 bit pointer to 32 bit real
	T_32PFREAL32    = 0x0540,   // 16:32 pointer to 32 bit real
	T_64PREAL32     = 0x0640,   // 64 bit pointer to 32 bit real


	//      32-bit partial-precision real types

	T_REAL32PP      = 0x0045,   // 32 bit PP real
	T_PREAL32PP     = 0x0145,   // 16 bit pointer to 32 bit PP real
	T_PFREAL32PP    = 0x0245,   // 16:16 far pointer to 32 bit PP real
	T_PHREAL32PP    = 0x0345,   // 16:16 huge pointer to 32 bit PP real
	T_32PREAL32PP   = 0x0445,   // 32 bit pointer to 32 bit PP real
	T_32PFREAL32PP  = 0x0545,   // 16:32 pointer to 32 bit PP real
	T_64PREAL32PP   = 0x0645,   // 64 bit pointer to 32 bit PP real


	//      48-bit real types

	T_REAL48        = 0x0044,   // 48 bit real
	T_PREAL48       = 0x0144,   // 16 bit pointer to 48 bit real
	T_PFREAL48      = 0x0244,   // 16:16 far pointer to 48 bit real
	T_PHREAL48      = 0x0344,   // 16:16 huge pointer to 48 bit real
	T_32PREAL48     = 0x0444,   // 32 bit pointer to 48 bit real
	T_32PFREAL48    = 0x0544,   // 16:32 pointer to 48 bit real
	T_64PREAL48     = 0x0644,   // 64 bit pointer to 48 bit real


	//      64-bit real types

	T_REAL64        = 0x0041,   // 64 bit real
	T_PREAL64       = 0x0141,   // 16 bit pointer to 64 bit real
	T_PFREAL64      = 0x0241,   // 16:16 far pointer to 64 bit real
	T_PHREAL64      = 0x0341,   // 16:16 huge pointer to 64 bit real
	T_32PREAL64     = 0x0441,   // 32 bit pointer to 64 bit real
	T_32PFREAL64    = 0x0541,   // 16:32 pointer to 64 bit real
	T_64PREAL64     = 0x0641,   // 64 bit pointer to 64 bit real


	//      80-bit real types

	T_REAL80        = 0x0042,   // 80 bit real
	T_PREAL80       = 0x0142,   // 16 bit pointer to 80 bit real
	T_PFREAL80      = 0x0242,   // 16:16 far pointer to 80 bit real
	T_PHREAL80      = 0x0342,   // 16:16 huge pointer to 80 bit real
	T_32PREAL80     = 0x0442,   // 32 bit pointer to 80 bit real
	T_32PFREAL80    = 0x0542,   // 16:32 pointer to 80 bit real
	T_64PREAL80     = 0x0642,   // 64 bit pointer to 80 bit real


	//      128-bit real types

	T_REAL128       = 0x0043,   // 128 bit real
	T_PREAL128      = 0x0143,   // 16 bit pointer to 128 bit real
	T_PFREAL128     = 0x0243,   // 16:16 far pointer to 128 bit real
	T_PHREAL128     = 0x0343,   // 16:16 huge pointer to 128 bit real
	T_32PREAL128    = 0x0443,   // 32 bit pointer to 128 bit real
	T_32PFREAL128   = 0x0543,   // 16:32 pointer to 128 bit real
	T_64PREAL128    = 0x0643,   // 64 bit pointer to 128 bit real


	//      32-bit complex types

	T_CPLX32        = 0x0050,   // 32 bit complex
	T_PCPLX32       = 0x0150,   // 16 bit pointer to 32 bit complex
	T_PFCPLX32      = 0x0250,   // 16:16 far pointer to 32 bit complex
	T_PHCPLX32      = 0x0350,   // 16:16 huge pointer to 32 bit complex
	T_32PCPLX32     = 0x0450,   // 32 bit pointer to 32 bit complex
	T_32PFCPLX32    = 0x0550,   // 16:32 pointer to 32 bit complex
	T_64PCPLX32     = 0x0650,   // 64 bit pointer to 32 bit complex


	//      64-bit complex types

	T_CPLX64        = 0x0051,   // 64 bit complex
	T_PCPLX64       = 0x0151,   // 16 bit pointer to 64 bit complex
	T_PFCPLX64      = 0x0251,   // 16:16 far pointer to 64 bit complex
	T_PHCPLX64      = 0x0351,   // 16:16 huge pointer to 64 bit complex
	T_32PCPLX64     = 0x0451,   // 32 bit pointer to 64 bit complex
	T_32PFCPLX64    = 0x0551,   // 16:32 pointer to 64 bit complex
	T_64PCPLX64     = 0x0651,   // 64 bit pointer to 64 bit complex


	//      80-bit complex types

	T_CPLX80        = 0x0052,   // 80 bit complex
	T_PCPLX80       = 0x0152,   // 16 bit pointer to 80 bit complex
	T_PFCPLX80      = 0x0252,   // 16:16 far pointer to 80 bit complex
	T_PHCPLX80      = 0x0352,   // 16:16 huge pointer to 80 bit complex
	T_32PCPLX80     = 0x0452,   // 32 bit pointer to 80 bit complex
	T_32PFCPLX80    = 0x0552,   // 16:32 pointer to 80 bit complex
	T_64PCPLX80     = 0x0652,   // 64 bit pointer to 80 bit complex


	//      128-bit complex types

	T_CPLX128       = 0x0053,   // 128 bit complex
	T_PCPLX128      = 0x0153,   // 16 bit pointer to 128 bit complex
	T_PFCPLX128     = 0x0253,   // 16:16 far pointer to 128 bit complex
	T_PHCPLX128     = 0x0353,   // 16:16 huge pointer to 128 bit real
	T_32PCPLX128    = 0x0453,   // 32 bit pointer to 128 bit complex
	T_32PFCPLX128   = 0x0553,   // 16:32 pointer to 128 bit complex
	T_64PCPLX128    = 0x0653,   // 64 bit pointer to 128 bit complex


	//      boolean types

	T_BOOL08        = 0x0030,   // 8 bit boolean
	T_PBOOL08       = 0x0130,   // 16 bit pointer to  8 bit boolean
	T_PFBOOL08      = 0x0230,   // 16:16 far pointer to  8 bit boolean
	T_PHBOOL08      = 0x0330,   // 16:16 huge pointer to  8 bit boolean
	T_32PBOOL08     = 0x0430,   // 32 bit pointer to 8 bit boolean
	T_32PFBOOL08    = 0x0530,   // 16:32 pointer to 8 bit boolean
	T_64PBOOL08     = 0x0630,   // 64 bit pointer to 8 bit boolean

	T_BOOL16        = 0x0031,   // 16 bit boolean
	T_PBOOL16       = 0x0131,   // 16 bit pointer to 16 bit boolean
	T_PFBOOL16      = 0x0231,   // 16:16 far pointer to 16 bit boolean
	T_PHBOOL16      = 0x0331,   // 16:16 huge pointer to 16 bit boolean
	T_32PBOOL16     = 0x0431,   // 32 bit pointer to 18 bit boolean
	T_32PFBOOL16    = 0x0531,   // 16:32 pointer to 16 bit boolean
	T_64PBOOL16     = 0x0631,   // 64 bit pointer to 18 bit boolean

	T_BOOL32        = 0x0032,   // 32 bit boolean
	T_PBOOL32       = 0x0132,   // 16 bit pointer to 32 bit boolean
	T_PFBOOL32      = 0x0232,   // 16:16 far pointer to 32 bit boolean
	T_PHBOOL32      = 0x0332,   // 16:16 huge pointer to 32 bit boolean
	T_32PBOOL32     = 0x0432,   // 32 bit pointer to 32 bit boolean
	T_32PFBOOL32    = 0x0532,   // 16:32 pointer to 32 bit boolean
	T_64PBOOL32     = 0x0632,   // 64 bit pointer to 32 bit boolean

	T_BOOL64        = 0x0033,   // 64 bit boolean
	T_PBOOL64       = 0x0133,   // 16 bit pointer to 64 bit boolean
	T_PFBOOL64      = 0x0233,   // 16:16 far pointer to 64 bit boolean
	T_PHBOOL64      = 0x0333,   // 16:16 huge pointer to 64 bit boolean
	T_32PBOOL64     = 0x0433,   // 32 bit pointer to 64 bit boolean
	T_32PFBOOL64    = 0x0533,   // 16:32 pointer to 64 bit boolean
	T_64PBOOL64     = 0x0633,   // 64 bit pointer to 64 bit boolean


	//      Other pointer types

	T_NCVPTR        = 0x01f0,   // CV Internal type for created near pointers
	T_FCVPTR        = 0x02f0,   // CV Internal type for created far pointers
	T_HCVPTR        = 0x03f0,   // CV Internal type for created huge pointers
	T_32NCVPTR      = 0x04f0,   // CV Internal type for created near 32-bit pointers
	T_32FCVPTR      = 0x05f0,   // CV Internal type for created far 32-bit pointers
	T_64NCVPTR      = 0x06f0,   // CV Internal type for created near 64-bit pointers
}

//
// CV symbol record iterator
//
// A CV symbol blob is a packed sequence of records. Each record begins
// with cv_record_t { ushort length; ushort kind; }. `length` covers
// everything after itself (i.e., `kind` plus the trailing data), so the
// total byte advance per record is `length + sizeof(ushort)`.
//
// A length of 0 or 1 is invalid (length must at least cover `kind`).
// PDB symbol blobs sometimes contain S_END / S_BLOCK structure that we
// don't interpret here. The iterator just hands back the raw header
// pointer and the caller dispatches on `kind`.

/// CV symbol-record iterator state.
struct cv_sym_iter_t {
	ubyte *base;	/// Buffer start.
	uint length;	/// Buffer length in bytes.
	uint offset;	/// Current cursor.
}

/// Initialize an iterator over a CV symbol blob.
///
/// The buffer is borrowed; lifetime is the caller's responsibility.
void adbg_type_cv_sym_open(cv_sym_iter_t *it, void *data, uint size) {
	if (it == null)
		return;
	it.base   = cast(ubyte*)data;
	it.length = size;
	it.offset = 0;
}

/// Advance to the next CV symbol record.
///
/// Returns: Pointer to the record header (length + kind), or null at end
///          of buffer or on a malformed record (length < 2 or overflows
///          the buffer). The pointer is interior to the source buffer.
cv_record_t* adbg_type_cv_sym_next(cv_sym_iter_t *it) {
	if (it == null)
		return null;
	if (it.length - it.offset < cv_record_t.sizeof)
		return null;

	cv_record_t *r = cast(cv_record_t*)(it.base + it.offset);
	// `length` must cover at least the `kind` field.
	if (r.length < ushort.sizeof)
		return null;

	uint advance = ushort.sizeof + r.length;
	if (advance > it.length - it.offset)
		return null;

	it.offset += advance;
	return r;
}

//
// CV PROCSYM32 (S_GPROC32 / S_LPROC32 and *_ID variants)
//
// Reference: Microsoft cvinfo.h `PROCSYM32`. The fixed part follows the
// cv_record_t header; `Name` is a NUL-terminated string immediately after
// the fixed fields.
struct cv_procsym32_t { align(1):
	cv_record_t Header;
	uint Parent;	/// Parent symbol byte offset (0 for outermost).
	uint End;	/// Offset to matching S_END.
	uint Next;	/// Next procedure in the chain.
	uint CodeSize;	/// Procedure length in bytes.
	uint DbgStart;	/// Offset into the procedure of the first executable byte.
	uint DbgEnd;	/// Offset into the procedure of the last executable byte.
	uint TypeIndex;	/// Type index (or ID for _ID variants).
	uint CodeOffset;	/// Offset within the section.
	ushort Segment;	/// Section index (1-based, as in PE).
	ubyte Flags;	/// CV_PROCFLAGS bits.
	// char Name[];     // NUL-terminated, follows the fixed part.
}
static assert(cv_procsym32_t.sizeof == cv_record_t.sizeof + 35);

/// Returns: True for S_GPROC32 / S_LPROC32 and their `_ID` variants.
bool adbg_type_cv_sym_is_proc32(ushort kind) {
	switch (kind) {
	case S_GPROC32, S_LPROC32, S_GPROC32_ID, S_LPROC32_ID:
		return true;
	default:
		return false;
	}
}

/// Translate a few common SYM kinds to a short string for display.
/// Returns: null for kinds we don't recognize yet.
const(char)* adbg_type_cv_sym_enum_string(ushort kind) {
	switch (kind) {
	case S_GPROC32:    return "S_GPROC32";
	case S_LPROC32:    return "S_LPROC32";
	case S_GPROC32_ID: return "S_GPROC32_ID";
	case S_LPROC32_ID: return "S_LPROC32_ID";
	case S_END:        return "S_END";
	case S_PROC_ID_END: return "S_PROC_ID_END";
	case S_FRAMEPROC:  return "S_FRAMEPROC";
	case S_OBJNAME:    return "S_OBJNAME";
	case S_COMPILE3:   return "S_COMPILE3";
	case S_BUILDINFO:  return "S_BUILDINFO";
	case S_INLINESITE: return "S_INLINESITE";
	case S_INLINESITE_END: return "S_INLINESITE_END";
	default:           return null;
	}
}

//
// CV C13 line subsections
//
// The C13 region of a module stream is a sequence of subsections, each
// introduced by `cv_c13_subsection_header_t`. Subsection payloads are
// padded to a 4-byte boundary. For Objective 1, the two kinds that matter
// are DEBUG_S_LINES (line tables) and DEBUG_S_FILECHKSMS (file checksum
// records, which carry the file-name string-table offsets).

/// C13 subsection kinds. Values match `PdbSubsectionKind` in `adbg.objects.pdb`.
enum : uint {
	DEBUG_S_IGNORE             = 0x80000000, // mask for "ignore this entry"
	DEBUG_S_SYMBOLS            = 0xf1,
	DEBUG_S_LINES              = 0xf2,
	DEBUG_S_STRINGTABLE        = 0xf3,
	DEBUG_S_FILECHKSMS         = 0xf4,
	DEBUG_S_FRAMEDATA          = 0xf5,
	DEBUG_S_INLINEELINES       = 0xf6,
	DEBUG_S_CROSSSCOPEIMPORTS  = 0xf7,
	DEBUG_S_CROSSSCOPEEXPORTS  = 0xf8,
	DEBUG_S_IL_LINES           = 0xf9,
	DEBUG_S_FUNC_MDTOKEN_MAP   = 0xfa,
	DEBUG_S_TYPE_MDTOKEN_MAP   = 0xfb,
	DEBUG_S_MERGED_ASSEMBLYINPUT = 0xfc,
	DEBUG_S_COFF_SYMBOL_RVA    = 0xfd,
}

/// Translate a C13 subsection kind to a short string.
/// Returns: String name for kind of C13 debug entry.
const(char)* adbg_type_cv_c13_kind_string(uint kind) {
	switch (kind) {
	case DEBUG_S_SYMBOLS:             return "SYMBOLS";
	case DEBUG_S_LINES:               return "LINES";
	case DEBUG_S_STRINGTABLE:         return "STRINGTABLE";
	case DEBUG_S_FILECHKSMS:          return "FILECHKSMS";
	case DEBUG_S_FRAMEDATA:           return "FRAMEDATA";
	case DEBUG_S_INLINEELINES:        return "INLINEELINES";
	case DEBUG_S_CROSSSCOPEIMPORTS:   return "CROSSSCOPEIMPORTS";
	case DEBUG_S_CROSSSCOPEEXPORTS:   return "CROSSSCOPEEXPORTS";
	case DEBUG_S_IL_LINES:            return "IL_LINES";
	case DEBUG_S_FUNC_MDTOKEN_MAP:    return "FUNC_MDTOKEN_MAP";
	case DEBUG_S_TYPE_MDTOKEN_MAP:    return "TYPE_MDTOKEN_MAP";
	case DEBUG_S_MERGED_ASSEMBLYINPUT: return "MERGED_ASSEMBLYINPUT";
	case DEBUG_S_COFF_SYMBOL_RVA:     return "COFF_SYMBOL_RVA";
	default: return null;
	}
}

/// C13 subsection header: 8 bytes, followed by `Length` bytes of payload.
/// Subsections are 4-byte aligned.
struct cv_c13_subsection_header_t {
	uint Kind;	/// DEBUG_S_* value. High bit (DEBUG_S_IGNORE) means skip.
	uint Length;	/// Payload size, excluding this header.
}
static assert(cv_c13_subsection_header_t.sizeof == 8);

/// DEBUG_S_LINES subsection header (12 bytes), followed by one or more
/// per-file blocks (`cv_c13_lines_file_block_t`).
struct cv_c13_lines_header_t { align(1):
	uint OffsetInSection;	/// Start offset of the covered code in its section.
	ushort Segment;	/// 1-based section index.
	ushort Flags;	/// `CV_LINES_HAS_COLUMNS` if column info is present.
	uint CodeSize;	/// Bytes of code covered by this subsection.
}
static assert(cv_c13_lines_header_t.sizeof == 12);

/// Flag for `cv_c13_lines_header_t.Flags`: column-info entries follow lines.
enum CV_LINES_HAS_COLUMNS = 0x0001;

/// Per-file block header within a DEBUG_S_LINES subsection.
/// Followed by `NumLines` line entries, then (if column flag is set) the
/// same count of column entries. Total block size is `BlockSize` bytes
/// including this header.
struct cv_c13_lines_file_block_t { align(1):
	/// Offset into the DEBUG_S_FILECHKSMS subsection identifying the file.
	uint FileChecksumOffset;
	uint NumLines;
	uint BlockSize;	/// Includes the header and all line/column entries.
}
static assert(cv_c13_lines_file_block_t.sizeof == 12);

/// One line entry in a DEBUG_S_LINES block. The line number and "end delta"
/// are packed into `LineAndFlags`.
struct cv_c13_line_entry_t { align(1):
	/// Offset within the subsection's code range
	/// (`cv_c13_lines_header_t.OffsetInSection`).
	uint Offset;
	/// bits 0-23  = start line number
	/// bits 24-30 = end-line delta (usually 0)
	/// bit  31    = is-statement flag
	uint LineAndFlags;
}
static assert(cv_c13_line_entry_t.sizeof == 8);

/// Extract the start line number from `cv_c13_line_entry_t.LineAndFlags`.
pragma(inline, true)
uint cv_c13_line_start(uint lineflags) { return lineflags & 0xff_ffff; }
/// Extract the end-line delta.
pragma(inline, true)
uint cv_c13_line_end_delta(uint lineflags) { return (lineflags >> 24) & 0x7f; }
/// True if the entry is marked as a statement boundary.
pragma(inline, true)
bool cv_c13_line_is_statement(uint lineflags) { return (lineflags & 0x8000_0000u) != 0; }

/// Optional column entry (one per line entry, when CV_LINES_HAS_COLUMNS).
struct cv_c13_column_entry_t { align(1):
	ushort StartColumn;
	ushort EndColumn;
}
static assert(cv_c13_column_entry_t.sizeof == 4);

/// DEBUG_S_FILECHKSMS entry header (6 bytes). Followed by `ChecksumSize`
/// bytes of checksum, then padding to 4 bytes.
struct cv_c13_filechksm_t { align(1):
	uint FileNameOffset;	/// Offset into the `/names` string stream.
	ubyte ChecksumSize;
	ubyte ChecksumKind;	/// 0=None, 1=MD5, 2=SHA1, 3=SHA256.
}
static assert(cv_c13_filechksm_t.sizeof == 6);

//
// CV C13 subsection iterator
//

/// Iterator over the C13 region of a module stream.
struct cv_c13_iter_t {
	ubyte *base;	/// Buffer start.
	uint length;	/// Buffer length.
	uint offset;	/// Current cursor (always 4-byte aligned).
}

/// Initialize an iterator over a C13 blob.
void adbg_type_cv_c13_open(cv_c13_iter_t *it, void *data, uint size) {
	if (it == null)
		return;
	it.base   = cast(ubyte*)data;
	it.length = size;
	it.offset = 0;
}

/// Advance to the next C13 subsection.
///
/// On success returns a pointer to the subsection header. The payload is
/// at `header + 1` (i.e., immediately after the 8-byte header) and is
/// `header.Length` bytes long. The cursor is advanced past the payload
/// and re-aligned to 4 bytes.
///
/// Params:
/// 	it = Iterator state.
/// Returns: Pointer to header, or null at end of buffer or on a
///          malformed entry (Length overflows the buffer).
cv_c13_subsection_header_t* adbg_type_cv_c13_next(cv_c13_iter_t *it) {
	if (it == null)
		return null;
	if (it.length - it.offset < cv_c13_subsection_header_t.sizeof)
		return null;

	cv_c13_subsection_header_t *h =
		cast(cv_c13_subsection_header_t*)(it.base + it.offset);
	uint avail = it.length - it.offset - cast(uint)cv_c13_subsection_header_t.sizeof;
	if (h.Length > avail)
		return null;

	uint advance = cast(uint)cv_c13_subsection_header_t.sizeof + h.Length;
	// 4-byte align the cursor for the next entry.
	import adbg.utils.bit : adbg_alignup;
	advance = cast(uint)adbg_alignup(advance, 4);
	if (advance > it.length - it.offset)
		advance = it.length - it.offset;
	it.offset += advance;
	return h;
}
