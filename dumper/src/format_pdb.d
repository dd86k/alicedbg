/// PDB 2.0 and 7.0 dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format_pdb;

import adbg.error;
import adbg.objectserver;
import adbg.objects.pdb;
import adbg.objects.pe : adbg_object_pe_machine_value_string, pe_section_entry_t;
import adbg.utils.uid;
import adbg.utils.date;
import adbg.utils.strings;
import adbg.utils.math;
import adbg.utils.bit;
import adbg.include.c.stdio : printf, snprintf, putchar, puts;
import adbg.types.cv;
import core.stdc.stdlib : atoi;
import dumper;
import common.errormgmt;

extern (C):

int dump_pdb(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_pdb_header(o);
	if (SELECTED_OBJ(SelectObj.pdbModules))
		dump_pdb_modules(o);
	if (SELECTED_OBJ(SelectObj.pdbSecContribs))
		dump_pdb_seccontribs(o);
	if (SELECTED_OBJ(SelectObj.pdbSyms))
		dump_pdb_syms(o);
	if (SELECTED_OBJ(SelectObj.pdbLines))
		dump_pdb_lines(o);
	// can be 0
	if (opt_pdb_stream)
		dump_pdb_stream(o, atoi(opt_pdb_stream));
	return 0;
}

private:

void dump_pdb_header(adbg_object_t *o) {
	print_header("Header");
	
	uint max = void;
	PdbVersion pdbversion = adbg_object_pdb_version(o);
	final switch (pdbversion) with(PdbVersion) {
	case pdb20:
		pdb20_file_header_t *header = adbg_object_pdb20_header(o);
		
		with (header) {
		print_rstring("Magic",  Magic.ptr, Magic.sizeof);
		print_u32("BlockSize",  BlockSize);
		print_u16("StartPage",  StartPage);
		print_u16("BlockCount", BlockCount);
		print_u32("RootSize",   RootSize);
		print_x32("Reserved",   Reserved);
		}
		
		max = 0xffff; // or 0x7fff with 4K pages
		break;
	case pdb70:
		pdb70_file_header_t *header = adbg_object_pdb70_header(o);
		
		with (header) {
		print_rstring("Magic",       Magic.ptr, Magic.sizeof);
		print_u32("BlockSize",       BlockSize);
		print_u32("FreeIndex",       FreeIndex);
		print_u32("BlockCount",      BlockCount);
		print_u32("DirectorySize",   DirectorySize);
		print_x32("Unknown",         Unknown);
		print_x32("DirectoryOffset", DirectoryOffset);
		}
		
		print_header("FPM information");
		ubyte *fpm      = adbg_object_pdb70_fpm(o);
		size_t fpmcount = adbg_object_pdb70_fpmcount(o);
		for (size_t fpmi; fpmi < fpmcount; ++fpmi) {
			char[48] buf = void;
			uint blocknum = cast(uint)fpmi * 8;
			snprintf(buf.ptr, 48, "Block %u-%u", blocknum, blocknum + 7);
			print_x8(buf.ptr, fpm[fpmi]);
		}
		
		max = PDB_BLOCK_SIZE_UNUSED;
		break;
	}
	
	print_header("Block allocation");
	uint count = adbg_object_pdb_stream_count(o);
	for (uint i; i < count; ++i, putchar('\n')) {
		// Print stream number
		char[48] buf = void;
		snprintf(buf.ptr, 48, "Stream %u", i);
		print_name(buf.ptr);
		
		pdb_stream_t *stream = adbg_object_pdb_stream_info(o, i);
		if (stream == null) {
			print_warningf("Stream %u failed to load: %s", i, adbg_error_message());
			continue;
		}
		
		// If size zero of unused, it's unmapped
		if (stream.size == 0 || stream.size >= max)
			continue;
		
		printf("%u\t(", stream.size);
		final switch (pdbversion) {
		case PdbVersion.pdb20:
			for (uint bi; bi < stream.blkcnt; ++bi) {
				if (bi) putchar(',');
				printf("%u", stream.blocks16[bi]);
			}
			break;
		case PdbVersion.pdb70:
			for (uint bi; bi < stream.blkcnt; ++bi) {
				if (bi) putchar(',');
				printf("%u", stream.blocks32[bi]);
			}
			break;
		}
		printf(")");
	}
}

//TODO: Eventually print PDB stream module name or purpose
const(char)* pdb_stream_name(size_t i) {
	static immutable string[] StreamNames = [
		"Old MSF Directory",
		"PDB information",
		"TPI stream",
		"DBI stream",
		"IPI stream",
	];
	if (i >= StreamNames.length)
		return "Unknown";
	return StreamNames[i].ptr;
}

void dump_pdb_stream(adbg_object_t *o, int num) {
	pdb_stream_t *stream = adbg_object_pdb_open_stream(o, num);
	if (stream == null)
		panic_adbg("Failed to open PDB stream");
	scope(exit) adbg_object_pdb_close_stream(stream);
	
	// If by preference we want to extract the stream data
	if (SETTING(Setting.extractAny)) {
	Lextract:
		char[64] b = void;
		snprintf(b.ptr, 64, "Stream %d", num);
		print_data(b.ptr, stream.data, stream.size);
		return;
	}
	
	PdbVersion pdbver = adbg_object_pdb_version(o);
	// If Stream number has any special meaning
	switch (num) {
	case 1: // pdb info
		if (pdbver == PdbVersion.pdb70)
			dump_pdb70_stream_pdb(o, stream);
		else
			dump_pdb20_stream_pdb(o, stream);
		return;
	case 2, 4:
		dump_pdb_stream_tpi_ipi(o, stream, num);
		return;
	case 3:
		dump_pdb_stream_dbi(o, stream);
		return;
	case 7: // pdb public symbols (at least for pdb 2.0?)
		if (pdbver == PdbVersion.pdb20)
			dump_pdb20_stream_pubsym(o, stream);
		return;
	default:
	}
	
	// No special meaning, go hexdump it
	// Assume no other bit set since another check is done earlier
	opt_settings |= Setting.hexdump;
	goto Lextract;
}

void dump_pdb20_stream_pdb(adbg_object_t *o, pdb_stream_t *stream) {
	print_section(1, "PDB information");
	
	if (stream.size < pdb20_pdb_stream_t.sizeof) {
		print_warningf("Stream smaller than PDB header");
		return;
	}
	
	pdb20_pdb_stream_t *pdb = cast(pdb20_pdb_stream_t*)stream.data;
	
	print_u32("Version", pdb.Version, adbg_object_pdb_pdbversion_string(pdb.Version));
	print_x32("Signature", pdb.Signature);
	print_u32("Age", pdb.Age);
}

void dump_pdb20_stream_pubsym(adbg_object_t *o, pdb_stream_t *stream) {
	print_section(7, "Public symbols");
	
	if (stream.size <= 0 || stream.size >= 0xffff) {
		print_warningf("Stream too small or unused");
		return;
	}
	
	// CodeView information
	cv_record_t *rec = cast(cv_record_t*)(stream.data + 4);
	for (int tpioffset; tpioffset < stream.size; tpioffset += rec.length) {
		print_u16("Length", rec.length);
		print_x16("Kind", rec.kind, SAFEVAL( adbg_type_cv_leaf_enum_string(rec.kind) ));
		
		if (rec.kind == 0 || rec.length == 0)
			break;
		
		// Get next leaf record
		rec = cast(cv_record_t*)(cast(void*)rec + rec.length + ushort.sizeof);
	}
}

void dump_pdb70_stream_pdb(adbg_object_t *o, pdb_stream_t *stream) {
	print_section(Pdb70Stream.pdb, pdb_stream_name(Pdb70Stream.pdb));
	
	if (stream.size < pdb_pdb_header_t.sizeof) {
		print_warningf("Stream smaller than PDB header");
		return;
	}
	
	pdb_pdb_header_t *pdb = cast(pdb_pdb_header_t*)stream.data;
	
	char[UID_TEXTLEN] uidstr = void;
	int uidlen = uid_string(pdb.UniqueId, uidstr.ptr, UID_TEXTLEN, UID_GUID);
	print_u32("Version", pdb.Version, adbg_object_pdb_pdbversion_string(pdb.Version));
	print_x32("Signature", pdb.Signature);
	print_u32("Age", pdb.Age);
	print_stringl("UniqueID", uidstr.ptr, uidlen);
}

void dump_pdb_stream_tpi_ipi(adbg_object_t *o, pdb_stream_t *stream, int num) {
	print_section(num, pdb_stream_name(num));
	
	if (stream.size < pdb_dbi_header_t.sizeof) {
		print_warningf("Stream smaller than TPI/IPI header");
		return;
	}
	
	pdb_tpi_header_t *tpi = cast(pdb_tpi_header_t*)stream.data;
	
	const(char) *vcver = void;
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
	
	cv_record_t *rec = cast(cv_record_t*)(stream.data + pdb_tpi_header_t.sizeof);
	for (int tpioffset; tpioffset < stream.size; tpioffset += rec.length) {
		print_u16("Length", rec.length);
		print_x16("Kind", rec.kind, SAFEVAL( adbg_type_cv_leaf_enum_string(rec.kind) ));
		
		if (rec.kind == 0 || rec.length == 0)
			break;
		
		// Get next leaf record
		rec = cast(cv_record_t*)(cast(void*)rec + rec.length + ushort.sizeof);
	}
}

void dump_pdb_stream_dbi(adbg_object_t *o, pdb_stream_t *stream) {
	print_section(Pdb70Stream.dbi, pdb_stream_name(Pdb70Stream.dbi));
	
	if (stream.size < pdb_dbi_header_t.sizeof) {
		print_warningf("Stream smaller than DBI header");
		return;
	}
	
	pdb_dbi_header_t *dbi = cast(pdb_dbi_header_t*)stream.data;
	
	const(char) *vcver = void;
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
	
	// Module Info Substream containing object entries
	if (dbi.ModInfoSize > pdb_dbi_modinfo_t.sizeof) {
		print_header("Module info substream");
		
		uint count;
		size_t size;
		for (size_t offset; offset < dbi.ModInfoSize; offset += size) {
			pdb_dbi_modinfo_t *mod = cast(pdb_dbi_modinfo_t*)
				(stream.data + pdb_dbi_header_t.sizeof + offset);
			
			print_section(count++);
			print_x32("Unused1", mod.Unused1);
			print_x32("SectionContr.Section", mod.SectionContr.Section);
			print_x16("SectionContr.Padding1", mod.SectionContr.Padding1);
			print_u32("SectionContr.Offset", mod.SectionContr.Offset);
			print_u32("SectionContr.Size", mod.SectionContr.Size);
			print_x32("SectionContr.Characteristics", mod.SectionContr.Characteristics);
			print_u16("SectionContr.ModuleIndex", mod.SectionContr.ModuleIndex);
			print_x16("SectionContr.Padding2", mod.SectionContr.Padding2);
			print_x32("SectionContr.DataCrc", mod.SectionContr.DataCrc);
			print_x32("SectionContr.RelocCrc", mod.SectionContr.RelocCrc);
			print_flags16("Flags", mod.Flags,
				"DIRTY".ptr, PDB_DBI_MOD_DIRTY,
				"EC".ptr, PDB_DBI_MOD_EC,
				null);
			print_u16("ModuleSysStream", mod.ModuleSysStream);
			print_u32("SymByteSize", mod.SymByteSize);
			print_u32("C11ByteSize", mod.C11ByteSize);
			print_u32("C13ByteSize", mod.C13ByteSize);
			print_u16("SourceFileCount", mod.SourceFileCount);
			print_x16("Padding", mod.Padding);
			print_x32("Unused2", mod.Unused2);
			// NOTE: SourceFileNameIndex is usually zero these days.
			print_u32("SourceFileNameIndex", mod.SourceFileNameIndex);
			// NOTE: Usually only non-zero for "* Linker *" module
			print_u32("PdbFilePathNameIndex", mod.PdbFilePathNameIndex);
			
			// Print ModuleName, usually associated *.obj/*.exp files
			char *modname = cast(char*)mod + pdb_dbi_modinfo_t.sizeof;
			int modlen = cast(int)adbg_nstrlen(modname, 4096);
			print_stringl("ModuleName", modname, modlen);
			
			// If non-zero, then it has null-terminator, include for total length
			if (modlen) ++modlen;
			
			// Print ObjFileName, usually associated static library
			char* objname = modname + modlen;
			int objlen = cast(int)adbg_nstrlen(objname, 4096);
			print_stringl("ObjFileName", objname, objlen);
			
			// Ditto
			if (objlen) ++objlen;
			
			size = adbg_alignup(pdb_dbi_modinfo_t.sizeof + modlen + objlen, 4);
		}
	}
	
	// TODO: Section Contribution Substream
	
	// TODO: Section Map Substream
	
	// File Info Substream
	if (dbi.SourceInfoSize > pdb_dbi_fileinfo_t.sizeof) {
		print_header("File Info substream");
		
		pdb_dbi_fileinfo_t *fi = cast(pdb_dbi_fileinfo_t*)
			(stream.data +
			dbi.ModInfoSize +
			dbi.SectionContributionSize +
			dbi.SectionMapSize);
		
		// TODO: Fix hack with string-check-like function
		enum fimin = 20; // Some arbitrary amount for FileInfo minimum
		if (adbg_bits_boundchk(fi, pdb_dbi_fileinfo_t.sizeof + fimin, stream.data, stream.size)) {
			print_warningf("FileInfo substream fileinfo outside stream data");
			return;
		}
		
		print_u16("NumModules", fi.NumModules);
		print_u16("NumSourceFiles", fi.NumSourceFiles);
		
		ushort *ModIndices = cast(ushort*)(cast(void*)fi + pdb_dbi_fileinfo_t.sizeof);
		ushort *NumSourceFiles = ModIndices + fi.NumModules;
		uint *FileNameOffsets = cast(uint*)(NumSourceFiles + fi.NumModules);
		char *NamesBuffer = cast(char*)(FileNameOffsets + fi.NumSourceFiles);
		
		/+
		// empty + null, only check last
		if (adbg_bits_boundchk(NamesBuffer, fi.NumSourceFiles * 2, stream.data, stream.size)) {
			print_warningf("FileInfo substream NamesBuffer outside stream data");
			return;
		}
		
		if (fi.NumModules) {
			/*
			print_name("ModIndices");
			for (size_t i; i < fi.NumModules; ++i) {
				if (i) printf(", ");
				printf("%02x", ModIndices[i]);
			}
			putchar('\n');
			*/
			
			uint tsrccnt; // total src count
			print_name("NumSourceFiles");
			for (size_t i; i < fi.NumModules; ++i) {
				if (i) printf(", ");
				//printf("%02x", NumSourceFiles[i]);
				tsrccnt += NumSourceFiles[i];
			}
			putchar('\n');
		}
		
		if (fi.NumSourceFiles) {
			print_name("FileNameOffsets");
			for (size_t i; i < tsrccnt; ++i) {
				if (i) printf(", ");
				printf("%04x:%s", FileNameOffsets[i], NamesBuffer + FileNameOffsets[i]);
			}
			putchar('\n');
		}
		+/
	}
	
	// TODO: Type Server Map Substream
	
	// TODO: EC Substream
	
	// TODO: Optional Debug Header Stream
}

// IMAGE_SECTION_HEADER.Characteristics bits relevant for a compact rwxc summary.
enum : uint {
	IMAGE_SCN_CNT_CODE       = 0x00000020,
	IMAGE_SCN_MEM_EXECUTE    = 0x20000000,
	IMAGE_SCN_MEM_READ       = 0x40000000,
	IMAGE_SCN_MEM_WRITE      = 0x80000000,
}

// Format Characteristics as a 4-char rwxc string into buf[5].
void format_sc_chars(uint c, char *buf) {
	buf[0] = (c & IMAGE_SCN_MEM_READ)    ? 'r' : '-';
	buf[1] = (c & IMAGE_SCN_MEM_WRITE)   ? 'w' : '-';
	buf[2] = (c & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-';
	buf[3] = (c & IMAGE_SCN_CNT_CODE)    ? 'c' : '-';
	buf[4] = 0;
}

const(char)* pdb_seccontrib_ver_string(uint v) {
	switch (v) with (PdbRaw_DbiSecContribVer) {
	case ver60: return "ver60";
	case v2:    return "v2";
	default:    return "Unknown";
	}
}


void dump_pdb_seccontribs(adbg_object_t *o) {
	print_header("PDB section contributions");

	pdb_dbi_seccontrib_iter_t *it = adbg_object_pdb_dbi_seccontrib_open(o);
	if (it == null) {
		print_warningf("Failed to open SecContrib iterator: %s", adbg_error_message());
		return;
	}
	scope(exit) adbg_object_pdb_dbi_seccontrib_close(it);

	// Resolve section-name table once. May be absent (older PDBs); we'll just
	// leave that column blank in that case.
	size_t sh_count;
	pe_section_entry_t *sh = adbg_object_pdb_section_headers(o, &sh_count);

	// Header line: version + record count.
	uint total = it.length / it.entrysize;
	printf("Version: %08x (%s), %u entries\n",
		it.vermark, pdb_seccontrib_ver_string(it.vermark), total);

	// Column header. ISectCoff appears only for v2.
	if (it.entrysize == pdb_dbi_seccontrib2_entry_t.sizeof)
		puts("    #    Sec:Off       Size       Mod   Chars  Name      ICoff");
	else
		puts("    #    Sec:Off       Size       Mod   Chars  Name");

	uint i;
	pdb_dbi_seccontrib_entry_t *e = void;
	while ((e = adbg_object_pdb_dbi_seccontrib_next(it)) != null) {
		// Sentinel entries (Section==0, or ModuleIndex==0xffff) occasionally
		// appear as terminators; tag rather than skip silently.
		const(char) *tag = "";
		if (e.Section == 0 || e.ModuleIndex == 0xffff)
			tag = " *sentinel*";

		char[5] rwxc = void;
		format_sc_chars(e.Characteristics, rwxc.ptr);

		// Section name. pe_section_entry_t.Name is char[8], possibly not
		// NUL-terminated, so use %.*s with the field length.
		const(char) *sname_ptr = "".ptr;
		int sname_len;
		pe_section_entry_t *psh = adbg_object_pdb_section_lookup(sh, sh_count, e.Section);
		if (psh) {
			sname_ptr = psh.Name.ptr;
			sname_len = cast(int)pe_section_entry_t.Name.sizeof;
		}

		if (it.entrysize == pdb_dbi_seccontrib2_entry_t.sizeof) {
			auto e2 = cast(pdb_dbi_seccontrib2_entry_t*)e;
			printf("  %4u   %02u:%08x  %10d  %4u   %s  %-8.*s  %u%s\n",
				i, e.Section, e.Offset, e.Size,
				e.ModuleIndex, rwxc.ptr, sname_len, sname_ptr, e2.ISectCoff, tag);
		} else {
			printf("  %4u   %02u:%08x  %10d  %4u   %s  %-8.*s%s\n",
				i, e.Section, e.Offset, e.Size,
				e.ModuleIndex, rwxc.ptr, sname_len, sname_ptr, tag);
		}
		++i;
	}
}

void dump_pdb_syms(adbg_object_t *o) {
	print_header("PDB symbols (per-module)");

	pdb_dbi_modinfo_iter_t *mit = adbg_object_pdb_dbi_modinfo_open(o);
	if (mit == null) {
		print_warningf("Failed to open ModInfo iterator: %s", adbg_error_message());
		return;
	}
	scope(exit) adbg_object_pdb_dbi_modinfo_close(mit);

	uint mod_index;
	const(char) *modname;
	const(char) *objname;
	pdb_dbi_modinfo_t *mod = void;
	while ((mod = adbg_object_pdb_dbi_modinfo_next(mit, &modname, &objname)) != null) {
		uint this_mod = mod_index++;

		// Skip modules with no symbol blob entirely — keeps output focused
		// on modules that actually contribute usable function data.
		if (mod.ModuleSysStream == 0xffff || mod.SymByteSize == 0)
			continue;

		pdb_module_stream_t layout = void;
		if (adbg_object_pdb_module_open(o, mod, &layout)) {
			print_warningf("Module %u (%s): %s", this_mod, modname, adbg_error_message());
			continue;
		}

		printf("\n## Module %u: %s\n", this_mod, modname);
		printf("Stream=%u Signature=%u SymBytes=%u C11=%u C13=%u\n",
			mod.ModuleSysStream, layout.signature,
			layout.symbols_size, layout.c11_size, layout.c13_size);

		cv_sym_iter_t sit = void;
		adbg_type_cv_sym_open(&sit, layout.symbols, layout.symbols_size);

		cv_record_t *rec = void;
		while ((rec = adbg_type_cv_sym_next(&sit)) != null) {
			if (adbg_type_cv_sym_is_proc32(rec.kind)) {
				cv_procsym32_t *p = cast(cv_procsym32_t*)rec;
				// Name is NUL-terminated immediately after the fixed
				// part. Use precision so a missing terminator can't
				// run off the buffer; record `length + 2` bounds it.
				int maxname = cast(int)rec.length + 2 - cast(int)cv_procsym32_t.sizeof;
				if (maxname < 0) maxname = 0;
				const(char) *name = cast(const(char)*)(p + 1);
				const(char) *kindstr = adbg_type_cv_sym_enum_string(rec.kind);
				printf("  %-12s %02u:%08x size=%*u type=%08x %.*s\n",
					kindstr ? kindstr : "S_?",
					p.Segment, p.CodeOffset, -5, p.CodeSize, p.TypeIndex,
					maxname, name);
			}
		}
	}
}

// Walk a DEBUG_S_LINES subsection payload and print each per-file block.
void dump_c13_lines_subsection(ubyte *payload, uint paylen) {
	if (paylen < cv_c13_lines_header_t.sizeof) {
		print_warningf("LINES subsection truncated");
		return;
	}
	cv_c13_lines_header_t *hdr = cast(cv_c13_lines_header_t*)payload;
	bool has_columns = (hdr.Flags & CV_LINES_HAS_COLUMNS) != 0;
	printf("  range=%02u:%08x..%08x  flags=%04x%s\n",
		hdr.Segment, hdr.OffsetInSection,
		hdr.OffsetInSection + hdr.CodeSize,
		hdr.Flags, has_columns ? " HAS_COLUMNS".ptr : "".ptr);

	uint p = cast(uint)cv_c13_lines_header_t.sizeof;
	while (p + cv_c13_lines_file_block_t.sizeof <= paylen) {
		cv_c13_lines_file_block_t *fb = cast(cv_c13_lines_file_block_t*)(payload + p);
		if (fb.BlockSize < cv_c13_lines_file_block_t.sizeof ||
			p + fb.BlockSize > paylen) {
			print_warningf("Malformed file block");
			return;
		}
		printf("    fileChksm=%u  lines=%u\n",
			fb.FileChecksumOffset, fb.NumLines);

		uint lp = p + cast(uint)cv_c13_lines_file_block_t.sizeof;
		uint entries_size = fb.NumLines * cast(uint)cv_c13_line_entry_t.sizeof;
		if (lp + entries_size > p + fb.BlockSize) {
			print_warningf("Line entries overflow block");
			return;
		}
		cv_c13_line_entry_t *line_entries = cast(cv_c13_line_entry_t*)(payload + lp);
		cv_c13_column_entry_t *col_entries = null;
		if (has_columns) {
			uint cp = lp + entries_size;
			uint col_size = fb.NumLines * cast(uint)cv_c13_column_entry_t.sizeof;
			if (cp + col_size <= p + fb.BlockSize)
				col_entries = cast(cv_c13_column_entry_t*)(payload + cp);
		}

		for (uint i; i < fb.NumLines; ++i) {
			cv_c13_line_entry_t *le = line_entries + i;
			uint sec_off = hdr.OffsetInSection + le.Offset;
			uint line = cv_c13_line_start(le.LineAndFlags);
			char stmt = cv_c13_line_is_statement(le.LineAndFlags) ? 'S' : '-';
			if (col_entries) {
				printf("      %02u:%08x  L%u  col=%u..%u  %c\n",
					hdr.Segment, sec_off, line,
					col_entries[i].StartColumn,
					col_entries[i].EndColumn, stmt);
			} else {
				printf("      %02u:%08x  L%u  %c\n",
					hdr.Segment, sec_off, line, stmt);
			}
		}

		p += fb.BlockSize;
	}
}

// Walk a DEBUG_S_FILECHKSMS subsection and print each entry's offset (in
// the subsection) along with the file-name offset into /names. The string
// table lookup is deferred until the named-stream map is wired up.
void dump_c13_filechksms_subsection(ubyte *payload, uint paylen) {
	uint p;
	while (p + cv_c13_filechksm_t.sizeof <= paylen) {
		cv_c13_filechksm_t *e = cast(cv_c13_filechksm_t*)(payload + p);
		uint reclen = cast(uint)cv_c13_filechksm_t.sizeof + e.ChecksumSize;
		import adbg.utils.bit : adbg_alignup;
		uint aligned = cast(uint)adbg_alignup(reclen, 4);
		if (p + reclen > paylen) {
			print_warningf("Truncated checksum entry");
			return;
		}
		printf("  [@%*u] file=/names+%u  kind=%u  csumlen=%u\n",
			-6, p, e.FileNameOffset, e.ChecksumKind, e.ChecksumSize);
		p += aligned;
	}
}

void dump_pdb_lines(adbg_object_t *o) {
	print_header("PDB line info (per-module)");

	pdb_dbi_modinfo_iter_t *mit = adbg_object_pdb_dbi_modinfo_open(o);
	if (mit == null) {
		print_warningf("Failed to open ModInfo iterator: %s", adbg_error_message());
		return;
	}
	scope(exit) adbg_object_pdb_dbi_modinfo_close(mit);

	uint mod_index;
	const(char) *modname;
	pdb_dbi_modinfo_t *mod = void;
	while ((mod = adbg_object_pdb_dbi_modinfo_next(mit, &modname, null)) != null) {
		uint this_mod = mod_index++;
		if (mod.ModuleSysStream == 0xffff || mod.C13ByteSize == 0)
			continue;

		pdb_module_stream_t layout = void;
		if (adbg_object_pdb_module_open(o, mod, &layout)) {
			print_warningf("Module %u: %s", this_mod, adbg_error_message());
			continue;
		}
		if (layout.c13_size == 0)
			continue;

		printf("\n## Module %u: %s (C13=%u bytes)\n", this_mod, modname, layout.c13_size);

		cv_c13_iter_t it = void;
		adbg_type_cv_c13_open(&it, layout.c13, layout.c13_size);

		cv_c13_subsection_header_t *sub = void;
		while ((sub = adbg_type_cv_c13_next(&it)) != null) {
			uint kind = sub.Kind & ~DEBUG_S_IGNORE;
			const(char) *kstr = adbg_type_cv_c13_kind_string(kind);
			printf("\n[kind=%08x %s, len=%u]\n", sub.Kind, kstr ? kstr : "?", sub.Length);

			if (sub.Kind & DEBUG_S_IGNORE)
				continue;

			ubyte *payload = cast(ubyte*)(sub + 1);
			switch (kind) {
			case DEBUG_S_LINES:
				dump_c13_lines_subsection(payload, sub.Length);
				break;
			case DEBUG_S_FILECHKSMS:
				dump_c13_filechksms_subsection(payload, sub.Length);
				break;
			default:
				// Unhandled kinds — header alone gives a useful summary.
				break;
			}
		}
	}
}

void dump_pdb_modules(adbg_object_t *o) {
	print_header("PDB modules");

	pdb_dbi_modinfo_iter_t *it = adbg_object_pdb_dbi_modinfo_open(o);
	if (it == null) {
		print_warningf("Failed to open ModInfo iterator: %s", adbg_error_message());
		return;
	}
	scope(exit) adbg_object_pdb_dbi_modinfo_close(it);

	uint index;
	const(char) *modname;
	const(char) *objname;
	pdb_dbi_modinfo_t *mod = void;
	while ((mod = adbg_object_pdb_dbi_modinfo_next(it, &modname, &objname)) !is null) {
		print_section(index++);
		print_string("ModuleName", modname);
		print_string("ObjFileName", objname);
		print_u16("ModuleSysStream", mod.ModuleSysStream);
		print_u32("SymByteSize", mod.SymByteSize);
		print_u32("C11ByteSize", mod.C11ByteSize);
		print_u32("C13ByteSize", mod.C13ByteSize);
		print_u16("SourceFileCount", mod.SourceFileCount);
		print_flags16("Flags", mod.Flags,
			"DIRTY".ptr, PDB_DBI_MOD_DIRTY,
			"EC".ptr, PDB_DBI_MOD_EC,
			null);
	}
}
