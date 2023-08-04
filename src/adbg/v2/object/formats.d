/// Meta package of all the object formats.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.formats;

public import
	adbg.v2.object.format.elf,
	adbg.v2.object.format.macho,
	adbg.v2.object.format.mz,
	adbg.v2.object.format.pe;