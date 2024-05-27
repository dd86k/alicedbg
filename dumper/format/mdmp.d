/// Minidump dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.mdmp;

import adbg.disassembler;
import adbg.object.server;
import adbg.machines;
import adbg.object.format.mdmp;
import adbg.utils.date : ctime32;
import adbg.include.windows.winnt;
import dumper;
import common.utils : realstring;
import common.error;

int dump_minidump(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_minidump_headers(o);
	
	//if (SELECTED(Select.debug_))
	//	dump_minidump_debug(o);
	
	return 0;
}

private:

void dump_minidump_headers(adbg_object_t *o) {
	print_header("Header");
	with (o.i.mdmp.header) {
	print_x32("Signature", Signature);
	print_x16("Magic", Magic);
	print_u16("Version", Version);
	print_x32("StreamCount", StreamCount);
	print_x32("StreamRva", StreamRva);
	print_x32("Checksum", Checksum);
	print_x32("Timestamp", Timestamp, ctime32(Timestamp));
	print_flags64("Flags", Flags,
		"WithDataSegs".ptr, MiniDumpWithDataSegs,
		"WithFullMemory".ptr, MiniDumpWithFullMemory,
		"WithHandleData".ptr, MiniDumpWithHandleData,
		"FilterMemory".ptr, MiniDumpFilterMemory,
		"ScanMemory".ptr, MiniDumpScanMemory,
		"WithUnloadedModules".ptr, MiniDumpWithUnloadedModules,
		"WithIndirectlyReferencedMemory".ptr, MiniDumpWithIndirectlyReferencedMemory,
		"FilterModulePaths".ptr, MiniDumpFilterModulePaths,
		"WithProcessThreadData".ptr, MiniDumpWithProcessThreadData,
		"WithPrivateReadWriteMemory".ptr, MiniDumpWithPrivateReadWriteMemory,
		"WithoutOptionalData".ptr, MiniDumpWithoutOptionalData,
		"WithFullMemoryInfo".ptr, MiniDumpWithFullMemoryInfo,
		"WithThreadInfo".ptr, MiniDumpWithThreadInfo,
		"WithCodeSegs".ptr, MiniDumpWithCodeSegs,
		"WithoutAuxiliaryState".ptr, MiniDumpWithoutAuxiliaryState,
		"WithFullAuxiliaryState".ptr, MiniDumpWithFullAuxiliaryState,
		"WithPrivateWriteCopyMemory".ptr, MiniDumpWithPrivateWriteCopyMemory,
		"IgnoreInaccessibleMemory".ptr, MiniDumpIgnoreInaccessibleMemory,
		"WithTokenInformation".ptr, MiniDumpWithTokenInformation,
		"WithModuleHeaders".ptr, MiniDumpWithModuleHeaders,
		"FilterTriage".ptr, MiniDumpFilterTriage,
		"WithAvxXStateContext".ptr, MiniDumpWithAvxXStateContext,
		"WithIptTrace".ptr, MiniDumpWithIptTrace,
		"ScanInaccessiblePartialPages".ptr, MiniDumpScanInaccessiblePartialPages,
		"FilterWriteCombinedMemory".ptr, MiniDumpFilterWriteCombinedMemory,
		null);
	}
}

void dump_minidump_debug(adbg_object_t *o) {
	print_header("Debug");
	
	uint cnt = o.i.mdmp.header.StreamCount;
	uint off = o.i.mdmp.header.StreamRva;
	mdmp_directory_entry *dir = void;
	if (adbg_object_offsetl(o, cast(void**)&dir, off, cnt * mdmp_directory_entry.sizeof))
		panic(1, "Directory outside file bounds");
	
	for (uint i; i < cnt; ++i) {
		mdmp_directory_entry *entry = &dir[i];
		
		with (entry) {
		print_x32("StreamType", StreamType);
		print_x32("Size", Size);
		print_x32("Rva", Rva);
		}
		
		switch (entry.StreamType) {
		case ThreadListStream:
			print_header("Threadlist");
			
			mdmp_threadlist *tlist = void;
			if (adbg_object_offsetl(o, cast(void**)&tlist,
				entry.Rva, uint.sizeof + mdmp_thread.sizeof)) {
				print_warningf("Threadlist.Rva points outbound");
				continue;
			}
			for (uint ti; ti < tlist.Count; ++ti) {
				mdmp_thread *thread = &tlist.Threads.ptr[ti];
				print_section(ti);
				print_x32("ID", thread.ID);
				print_x32("SuspendCount", thread.SuspendCount);
				print_x32("PriorityClass", thread.PriorityClass);
				print_x32("Priority", thread.Priority);
				print_x64("Teb", thread.Teb);
				
				X86_NT_CONTEXT *context = void;
				if (adbg_object_offsetl(o, cast(void**)&context,
					thread.ThreadContext.Rva, thread.ThreadContext.Size)) {
					print_warningf("Thread.Context.Rva points outbound");
					continue;
				}
				
				print_x32("Eip", context.Eip);
			}
			break;
		case ModuleListStream:
			break;
		case MemoryListStream:
			break;
		case ExceptionStream:
			break;
		case SystemInfoStream:
			break;
		case ThreadExListStream:
			break;
		case Memory64ListStream:
			break;
		case CommentStreamA:
			break;
		case CommentStreamW:
			break;
		case HandleDataStream:
			break;
		case FunctionTableStream:
			break;
		case UnloadedModuleListStream:
			break;
		case MiscInfoStream:
			break;
		case MemoryInfoListStream:
			break;
		case ThreadInfoListStream:
			break;
		case HandleOperationListStream:
			break;
		case TokenStream:
			break;
		case JavaScriptDataStream:
			break;
		case SystemMemoryInfoStream:
			break;
		case ProcessVmCountersStream:
			break;
		case IptTraceStream:
			break;
		case ThreadNamesStream:
			break;
		default: continue;
		}
	}
}