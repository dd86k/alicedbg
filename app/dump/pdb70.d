/// PDB 7.00 dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.pdb70;

import adbg.disassembler.core;
import adbg.object.server;
import adbg.object.machines;
import adbg.object.format.pdb;
import adbg.utils.uid;
import adbg.utils.date;
import dumper;

extern (C):

int dump_pdb70(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers())
		dump_pdb70_header(dump, o);
	
	//if (dump.selected_debug())
	//	dump_pdb70_debug(dump, o);
	
	return 0;
}

private:

void dump_pdb70_header(ref Dumper dump, adbg_object_t *o) {
	print_header("Header");
	
	pdb70_file_header *header = adbg_object_pdb70_header(o);
	
	if (header.PageCount * header.PageSize != o.file_size) {
		print_string("error", "Reported size isn't same as actual file size.");
		return;
	}
	
	print_stringl("Magic", header.Magic.ptr, 24);
	print_x32("PageSize", header.PageSize);
	print_x32("FreeIndex", header.FreeIndex);
	print_x32("PageCount", header.PageCount);
	print_x32("DirectorySize", header.DirectorySize);
	print_x32("Unknown", header.Unknown2);
	print_x32("DirectoryOffset", header.DirectoryOffset);
}
/+
void dump_pdb70_debug(ref Dumper dump, adbg_object_t *o) {
	print_header("Debug");
	
	pdb70_file_header *header = adbg_object_pdb70_header(o);
	
	uint diroff = header.DirectoryOffset * header.PageSize;
	uint dircnt = (header.DirectorySize / header.PageSize) + 1;
	
	uint *dir = void;
	if (adbg_object_offset(o, cast(void**)&dir, diroff)) {
		print_string("error", "Directory offset out of bounds.");
		return;
	}
	
	uint nstreams = *dir; /// Number of stream sizes
	uint *psize = dir + 1; // Start at first size
	uint *ploc = psize + nstreams; // Start at first loc
	
	for (size_t i; i < nstreams; ++i) {
		int stream_size = cast(int)psize[i];
		
		print_section(cast(uint)i);
		print_x32("Size", stream_size);
		
		if (stream_size > 0) {
			print_x32("Page", ploc[i]);
			
			uint sloc = ploc[i] * header.PageSize;
			void *stream = void; // Stream count
			if (adbg_object_offsetl(o, &stream, sloc, 4)) {
				print_string("warning", "Stream directory outside of bounds.");
				continue;
			}
			
			int type = cast(int)i + 1;
			switch (type) {
			case 1:
				print_string("Stream Type", "PDB Header");
				uint dataoff = (*cast(uint*)stream) * header.PageSize;
				
				pdb70_stream_header *pdbhdr = void;
				if (adbg_object_offsetl(o, cast(void**)&pdbhdr, dataoff, 4)) {
					print_string("warning", "Stream outside of bounds.");
					continue;
				}
				with (pdbhdr) {
				char[UID_TEXTLEN] guid = void;
				uid_text(pdbhdr.UniqueId, guid, UID_GUID);

				print_x32("Version", Version);
				print_x32("Signature", Signature, ctime32(Signature));
				print_u32("Age", Age);
				print_stringl("UniqueId", guid.ptr, UID_TEXTLEN);
				}
				break;
			case 2:
				print_string("Stream Type", "Type manager");
				break;
			case 3:
				print_string("Stream Type", "Debug information");
				break;
			case 4:
				print_string("Stream Type", "NameMap");
				break;
			default: // >4 -> symbol
				print_string("Stream Type", "Unknown");
			}
		}
		
		uint nlocs = (stream_size / header.PageSize) + 1;
		for (size_t n; n < nlocs; ++n) {
			++ploc;
		}
	}
}
+/