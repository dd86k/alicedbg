/// Object name definitions.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.names;

//TODO: Machine names and aliases

enum AdbgMachine {
	unknown,
}

struct adbg_machine_name_t {
	/// Machine type.
	AdbgMachine machine;
	/// Machine alias.
	/// Example: x86
	const(char) *alias_;
	/// Machine full name.
	/// Example: Intel x86
	const(char) *name;
}