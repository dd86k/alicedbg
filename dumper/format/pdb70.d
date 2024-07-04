/// PDB 7.00 dumper
///
/// Sources:
/// - https://github.com/Microsoft/microsoft-pdb/
/// - http://www.godevtool.com/Other/pdb.htm
/// - http://www.debuginfo.com/articles/debuginfomatch.html
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.pdb70;

import adbg.disassembler;
import adbg.objectserver;
import adbg.machines;
import adbg.objects.pdb;
import adbg.objects.pe : adbg_object_pe_machine_value_string;
import adbg.utils.uid;
import adbg.utils.date;
import adbg.include.c.stdio : printf, snprintf, putchar;
import dumper;
import common.errormgmt;

extern (C):

int dump_pdb70(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_pdb70_header(o);
	if (SELECTED(Select.debug_))
		dump_pdb70_debug(o);
	return 0;
}

private:

void dump_pdb70_header(adbg_object_t *o) {
	print_header("Header");
	
	pdb70_file_header_t *header = adbg_object_pdb70_header(o);
	
	print_stringl("Magic", header.Magic.ptr, 24);
	print_u32("BlockSize", header.BlockSize);
	print_u32("FreeIndex", header.FreeIndex);
	print_u32("BlockCount", header.BlockCount);
	print_u32("DirectorySize", header.DirectorySize);
	print_x32("Unknown", header.Unknown);
	print_x32("DirectoryOffset", header.DirectoryOffset);
	
	//TODO: Consider moving this information to another selector
	print_header("FPM information");
	ubyte *fpm      = adbg_object_pdb70_fpm(o);
	size_t fpmcount = adbg_object_pdb70_fpmcount(o);
	for (size_t fpmi; fpmi < fpmcount; ++fpmi) {
		char[48] buf = void;
		uint blocknum = cast(uint)fpmi * 8;
		snprintf(buf.ptr, 48, "Block %u-%u", blocknum, blocknum + 7);
		print_x8(buf.ptr, fpm[fpmi]);
	}
	
	print_header("Stream information");
	uint count = adbg_object_pdb70_total_count(o);
	print_u32("Stream count", count);
	for (uint i; i < count; ++i, putchar('\n')) {
		// Print stream number
		char[48] buf = void;
		snprintf(buf.ptr, 48, "Stream %u", i);
		print_name(buf.ptr);
		
		uint size = adbg_object_pdb70_stream_size(o, i);
		
		// Skip if empty
		if (size == 0 || size == PDB_BLOCK_SIZE_UNUSED)
			continue;
		
		uint *blocks  = adbg_object_pdb70_stream_blocks(o, i);
		if (blocks == null)
			continue;
		
		// Print stream size + associated blocks
		uint blkcount = adbg_object_pdb70_stream_block_count(o, i);
		printf("%u\t(", size);
		for (uint bi; bi < blkcount; ++bi) {
			if (bi) putchar(',');
			printf("%u", blocks[bi]);
		}
		printf(")");
	}
}

//TODO: Eventually print PDB stream module name or purpose
const(char)* pdb_stream_name(size_t i) {
	static immutable string[] StreamNames = [
		"Old MSF Directory",
		"PDB Stream",
		"TPI Stream",
		"DBI Stream",
		"IPI Stream",
	];
	return StreamNames[i].ptr;
}

void dump_pdb70_debug(adbg_object_t *o) {
	print_header("Debug");
	
	pdb70_stream_t *stream = void;
	const(char) *vcver = void;
	
	// Stream 0 - Old MSF directory
	
	/*
	stream = adbg_object_pdb70_stream_open(o, 0);
	if (stream == null)
		panic_adbg("Failed to open Steam 0");
	print_section(0, StreamNames[0].ptr, cast(int)StreamNames[0].length);
	if (stream)
		print_hexdump("Stream 0 Data", buffer, strsize);
	adbg_object_pdb70_stream_close(stream);
	*/
	
	// Stream 1 - PDB
	
	stream = adbg_object_pdb70_stream_open(o, PdbStream.pdb);
	if (stream == null)
		panic_adbg("Failed to open Steam 1");
	
	print_section(PdbStream.pdb, pdb_stream_name(PdbStream.pdb));
	
	pdb70_pdb_header_t *pdb = cast(pdb70_pdb_header_t*)stream.data;
	switch (pdb.Version) with (PdbRaw_PdbVersion) {
	case vc2:	vcver = "VC2"; break;
	case vc4:	vcver = "VC4"; break;
	case vc41:	vcver = "VC41"; break;
	case vc50:	vcver = "VC50"; break;
	case vc98:	vcver = "VC98"; break;
	case vc70_old:	vcver = "VC70_OLD"; break;
	case vc70:	vcver = "VC70"; break;
	case vc80:	vcver = "VC80"; break;
	case vc110:	vcver = "VC110"; break;
	case vc140:	vcver = "VC140"; break;
	default:	vcver = "Unknown";
	}
	char[UID_TEXTLEN] uidstr = void;
	int uidlen = uid_string(pdb.UniqueId, uidstr.ptr, UID_TEXTLEN, UID_GUID);
	print_u32("Version", pdb.Version, vcver);
	print_x32("Signature", pdb.Signature);
	print_u32("Age", pdb.Age);
	print_stringl("UniqueID", uidstr.ptr, uidlen);
	/*void *leftover = buffer + pdb70_pdb_header.sizeof;
	size_t leftlen = strsize - pdb70_pdb_header.sizeof;
	print_raw("Stream 1 Data", leftover, leftlen);*/
	adbg_object_pdb70_stream_close(stream);
	
	// Stream 2 - TPI
	
	stream = adbg_object_pdb70_stream_open(o, PdbStream.tpi);
	if (stream == null)
		panic_adbg("Failed to open Steam 1");
	
	print_section(PdbStream.tpi, pdb_stream_name(PdbStream.tpi));
	pdb70_tpi_header_t *tpi = cast(pdb70_tpi_header_t*)stream.data;
	switch (tpi.Version) with (PdbRaw_TpiVer) {
	case v40:	vcver = "v40"; break;
	case v41:	vcver = "v41"; break;
	case v50:	vcver = "v50"; break;
	case v70:	vcver = "v70"; break;
	case v80:	vcver = "v80"; break;
	default:	vcver = "Unknown";
	}
	
	print_u32("Version", tpi.Version, vcver);
	print_u32("HeaderSize", tpi.HeaderSize);
	print_u32("TypeIndexBegin", tpi.TypeIndexBegin);
	print_u32("TypeIndexEnd", tpi.TypeIndexEnd);
	print_u32("TypeRecordBytes", tpi.TypeRecordBytes);
	print_u16("HashStreamIndex", tpi.HashStreamIndex);
	print_u16("HashAuxStreamIndex", tpi.HashAuxStreamIndex);
	print_u32("HashKeySize", tpi.HashKeySize);
	print_u32("NumHashBuckets", tpi.NumHashBuckets);
	print_u32("HashValueBufferOffset", tpi.HashValueBufferOffset);
	print_u32("HashValueBufferLength", tpi.HashValueBufferLength);
	print_u32("IndexOffsetBufferOffset", tpi.IndexOffsetBufferOffset);
	print_u32("IndexOffsetBufferLength", tpi.IndexOffsetBufferLength);
	print_u32("HashAdjBufferOffset", tpi.HashAdjBufferOffset);
	print_u32("HashAdjBufferLength", tpi.HashAdjBufferLength);
	
	/*void *leftover = buffer + pdb70_tpi_header.sizeof;
	size_t leftlen = strsize - pdb70_tpi_header.sizeof;
	print_raw("Stream 2 Data", leftover, leftlen);*/
	adbg_object_pdb70_stream_close(stream);
	
	// Stream 3 - DBI
	
	stream = adbg_object_pdb70_stream_open(o, PdbStream.dbi);
	if (stream == null)
		panic_adbg("Failed to open Steam 1");
	
	print_section(PdbStream.dbi, pdb_stream_name(PdbStream.dbi));
	
	pdb70_dbi_header_t *dbi = cast(pdb70_dbi_header_t*)stream.data;
	
	switch (dbi.VersionHeader) with (PdbRaw_DbiVer) {
	case v41:	vcver = "v41"; break;
	case v50:	vcver = "v50"; break;
	case v60:	vcver = "v60"; break;
	case v70:	vcver = "v70"; break;
	case v110:	vcver = "v110"; break;
	default:	vcver = "Unknown";
	}
	
	// 255.127-1
	char[16] buildnum = void;
	snprintf(buildnum.ptr, 16, "%u.%u-%u",
		dbi.BuildNumber >> 8 & 0x7f,	// MajorVersion
		cast(ubyte)dbi.BuildNumber,	// MinorVersion
		dbi.BuildNumber >> 15);	// NewVersionFormat
	
	print_x32("VersonSignature", dbi.VersonSignature);
	print_u32("VersionHeader", dbi.VersionHeader, vcver);
	print_u32("Age", dbi.Age);
	print_u16("GlobalStreamIndex", dbi.GlobalStreamIndex);
	print_x16("BuildNumber", dbi.BuildNumber, buildnum.ptr);
	print_u16("PublicStreamIndex", dbi.PublicStreamIndex);
	print_u16("PdbDllVersion", dbi.PdbDllVersion);
	print_u16("SymRecordStream", dbi.SymRecordStream);
	print_u16("PdbDllRbld", dbi.PdbDllRbld);
	print_u32("ModInfoSize", dbi.ModInfoSize);
	print_u32("SectionContributionSize", dbi.SectionContributionSize);
	print_u32("SectionMapSize", dbi.SectionMapSize);
	print_u32("SourceInfoSize", dbi.SourceInfoSize);
	print_u32("TypeServerMapSize", dbi.TypeServerMapSize);
	print_u32("MFCTypeServerIndex", dbi.MFCTypeServerIndex);
	print_u32("OptionalDbgHeaderSize", dbi.OptionalDbgHeaderSize);
	print_u32("ECSubstreamSize", dbi.ECSubstreamSize);
	print_flags16("Flags", dbi.Flags,
		"IncrementallyLinked".ptr,	PdbRaw_DbiFlags.IncrementallyLinked,
		"PrivateSymbolsStripped".ptr,	PdbRaw_DbiFlags.PrivateSymbolsStripped,
		"ConflictingTypes".ptr,	PdbRaw_DbiFlags.ConflictingTypes,
		null);
	print_x16("Machine", dbi.Machine, adbg_object_pe_machine_value_string(dbi.Machine));
	print_u32("Padding", dbi.Padding);
	/*void *leftover = buffer + pdb70_dbi_header.sizeof;
	size_t leftlen = strsize - pdb70_dbi_header.sizeof;
	print_raw("Stream 3 Data", leftover, leftlen);*/
	adbg_object_pdb70_stream_close(stream);
	
	// Stream 4 - IPI
	/+print_section(4, StreamNames[4].ptr, cast(int)StreamNames[4].length);
	if (adbg_object_pdb70_stream_open(o, &buffer, &strsize, PdbStream.dbi))
		panic_adbg("Failed to open Steam 4");
	if (strsize >= pdb70_subsection_header.sizeof) {
		pdb70_subsection_header *ipi = cast(pdb70_subsection_header*)buffer;
		
		enum LIMIT = 200; // Arbitrary
		
		size_t i;
	Lr:
		print_x32("Kind", ipi.Kind);
		print_x32("Length", ipi.Length);
		
		ipi = cast(pdb70_subsection_header*)((cast(void*)ipi) + ipi.Length);
		if (ipi.Kind && ipi.Length && ++i < LIMIT) goto Lr;
	}
	adbg_object_pdb70_stream_close(o, &buffer);+/
	
	/*uint strcnt = o.i.pdb70.strcnt;
	for (uint stridx = 5; stridx < strcnt; ++stridx) {
		char[32] buf = void;
		int l = snprintf(buf.ptr, 32, "Stream %u", stridx);
	}*/
}