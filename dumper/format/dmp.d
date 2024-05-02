/// Windows memory dump dumper.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.dmp;

import adbg.disassembler;
import adbg.object.server;
import adbg.machines;
import adbg.object.format.dmp;
import adbg.object.format.pe : adbg_object_pe_machine_string;
import dumper;

extern (C):

int dump_dmp(adbg_object_t *o) {
	if (selected_headers())
		dump_dmp_header(o);
	
	return 0;
}

private:

void dump_dmp_header(adbg_object_t *o) {
	print_header("Header");
	
	if (o.i.dmp.header.ValidDumpInt == PAGEDUMP64_VALID) with (o.i.dmp.header64) {
		print_x32l("Signature", SignatureInt, Signature.ptr, 4);
		print_x32l("ValidDump", ValidDumpInt, ValidDump.ptr, 4);
		print_u32("MajorVersion", MajorVersion);
		print_u32("MinorVersion", MinorVersion);
		print_x32("DirectoryTableBase", DirectoryTableBase);
		print_x32("PfnDatabase", PfnDatabase);
		print_x32("PsLoadedModuleList", PsLoadedModuleList);
		print_x32("PsActiveProcessHead", PsActiveProcessHead);
		print_x32("MachineImageType", MachineImageType,
			adbg_object_pe_machine_string(cast(ushort)MachineImageType));
		print_u32("NumberProcessors", NumberProcessors);
		print_x32("BugCheckCode", BugCheckCode);
		print_x32("BugCheckParameter1", BugCheckParameters[0]);
		print_x32("BugCheckParameter2", BugCheckParameters[1]);
		print_x32("BugCheckParameter3", BugCheckParameters[2]);
		print_x32("BugCheckParameter4", BugCheckParameters[3]);
		print_x64("KdDebuggerDataBlock", KdDebuggerDataBlock);
	} else with (o.i.dmp.header) {
		print_x32l("Signature", SignatureInt, Signature.ptr, 4);
		print_x32l("ValidDump", ValidDumpInt, ValidDump.ptr, 4);
		print_u32("MajorVersion", MajorVersion);
		print_u32("MinorVersion", MinorVersion);
		print_x32("DirectoryTableBase", DirectoryTableBase);
		print_x32("PfnDatabase", PfnDatabase);
		print_x32("PsLoadedModuleList", PsLoadedModuleList);
		print_x32("PsActiveProcessHead", PsActiveProcessHead);
		print_x32("MachineImageType", MachineImageType,
			adbg_object_pe_machine_string(cast(ushort)MachineImageType));
		print_u32("NumberProcessors", NumberProcessors);
		print_x32("BugCheckCode", BugCheckCode);
		print_x32("BugCheckParameter1", BugCheckParameters[0]);
		print_x32("BugCheckParameter2", BugCheckParameters[1]);
		print_x32("BugCheckParameter3", BugCheckParameters[2]);
		print_x32("BugCheckParameter4", BugCheckParameters[3]);
		print_u8("PaeEnabled", PaeEnabled);
		print_x32("KdDebuggerDataBlock", KdDebuggerDataBlock);
	}
}