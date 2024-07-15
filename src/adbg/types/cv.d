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

enum CV_MMASK        = 0x700;       /// mode mask
enum CV_TMASK        = 0x0f0;       /// type mask

enum CV_SIGNATURE_C6         = 0;  // Actual signature is >64K
enum CV_SIGNATURE_C7         = 1;  // First explicit signature
enum CV_SIGNATURE_C11        = 2;  // C11 (vc5.x) 32-bit types
enum CV_SIGNATURE_C13        = 4;  // C13 (vc7.x) zero terminated names
enum CV_SIGNATURE_RESERVED   = 5;  // All signatures from 5 to 64K are reserved


// At least Leaf Records
struct cv_record_t {
	ushort length;
	ushort kind;
}

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