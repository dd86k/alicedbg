/// COFF symbol management.
///
/// Sources: See adbg.objects.coff
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.types.coff;

import adbg.error;
import adbg.symbols;
import adbg.objectserver;
import adbg.objects.coff;

// Use symbol list from adbg.symbol
int adbg_type_coff_populate(adbg_symbol_list_t *list, adbg_object_t *o) {
	if (list == null || o == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	if (adbg_object_format(o) != AdbgObject.coff)
		return adbg_oops(AdbgError.assertion);
	
	coff_symbol_entry_t *coffsym = adbg_object_coff_first_symbol(o);
	if (coffsym == null)
		return adbg_error_code();
		
	do with (coffsym) {
		switch (coffsym.e_sclass) {
		case C_EXT, C_STAT: // Public or private class
			// HACK: Labels/Functions filtering
			//       Not auxiliary entries and points to section 1 (typically .text)
			if (e_numaux || e_scnum != 1)
				continue;
			char *name = cast(char*)adbg_object_coff_symbol_name(o, coffsym);
			if (name == null)
				continue;
			adbg_symbol_t sym = adbg_symbol_init(AdbgSymbolType.label, name, 0, e_value);
			adbg_symbol_list_add(list, &sym);
			break;
		default:
		}
	} while ((coffsym = adbg_object_coff_next_symbol(o)) != null);
	
	return 0;
}