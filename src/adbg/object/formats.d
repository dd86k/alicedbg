/// Meta package of all the object formats.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.object.formats;

public import
	adbg.object.format.elf,
	adbg.object.format.macho,
	adbg.object.format.mz,
	adbg.object.format.ne,
	adbg.object.format.lx,
	adbg.object.format.pe,
	adbg.object.format.pdb,
	adbg.object.format.mdmp,
	adbg.object.format.dmp,
	adbg.object.format.ar,
	adbg.object.format.coff,
	adbg.object.format.mscoff;