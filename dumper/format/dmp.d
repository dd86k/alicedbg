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
import adbg.object.format.pe : adbg_object_pe_machine_value_string;
import dumper;
import common.utils;

extern (C):

int dump_dmp(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_dmp_header(o);
	
	return 0;
}

private:

void dump_dmp_header(adbg_object_t *o) {
	print_header("Header");
	
	void *header = adbg_object_dmp_header(o);
	
	char[16] realbuf = void;
	
	if (adbg_object_dmp_is_64bit(o)) {
		dmp64_header_t *header64 = cast(dmp64_header_t*)header;
		with (header64) {
		int l = realstring(realbuf.ptr, 16, Signature.ptr, Signature.sizeof);
		print_x32l("Signature", Signature32, realbuf.ptr, l);
		l = realstring(realbuf.ptr, 16, ValidDump.ptr, ValidDump.sizeof);
		print_x32l("ValidDump", ValidDump32, realbuf.ptr, l);
		print_u32("MajorVersion", MajorVersion);
		print_u32("MinorVersion", MinorVersion);
		print_x32("DirectoryTableBase", DirectoryTableBase);
		print_x32("PfnDatabase", PfnDatabase);
		print_x32("PsLoadedModuleList", PsLoadedModuleList);
		print_x32("PsActiveProcessHead", PsActiveProcessHead);
		print_x32("MachineImageType", MachineImageType,
			adbg_object_pe_machine_value_string(cast(ushort)MachineImageType));
		print_u32("NumberProcessors", NumberProcessors);
		print_x32("BugCheckCode", BugCheckCode);
		print_x32("BugCheckParameter1", BugCheckParameters[0]);
		print_x32("BugCheckParameter2", BugCheckParameters[1]);
		print_x32("BugCheckParameter3", BugCheckParameters[2]);
		print_x32("BugCheckParameter4", BugCheckParameters[3]);
		print_x64("KdDebuggerDataBlock", KdDebuggerDataBlock);
		}
	} else {
		dmp32_header_t *header32 = cast(dmp32_header_t*)header;
		with (header32) {
		int l = realstring(realbuf.ptr, 16, Signature.ptr, Signature.sizeof);
		print_x32l("Signature", Signature32, realbuf.ptr, l);
		l = realstring(realbuf.ptr, 16, ValidDump.ptr, ValidDump.sizeof);
		print_x32l("ValidDump", ValidDump32, realbuf.ptr, l);
		print_u32("MajorVersion", MajorVersion);
		print_u32("MinorVersion", MinorVersion);
		print_x32("DirectoryTableBase", DirectoryTableBase);
		print_x32("PfnDatabase", PfnDatabase);
		print_x32("PsLoadedModuleList", PsLoadedModuleList);
		print_x32("PsActiveProcessHead", PsActiveProcessHead);
		print_x32("MachineImageType", MachineImageType,
			adbg_object_pe_machine_value_string(cast(ushort)MachineImageType));
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
}