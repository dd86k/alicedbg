/// Application utilities.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module utils;

/// Unformat text number.
/// Params:
///   result = Long pointer.
///   str = Input.
/// Returns: True if could not parse number.
bool unformat(int *result, const(char) *str) {
	import core.stdc.stdio : sscanf;
	return sscanf(str, "%i", result) != 1;
}

/// Unformat text number.
/// Params:
///   result = Long pointer.
///   str = Input.
/// Returns: True if could not parse number.
bool unformat64(long *result, const(char) *str) {
	import core.stdc.stdio : sscanf;
	return sscanf(str, "%lli", result) != 1;
}