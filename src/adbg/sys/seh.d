/**
 * SEH package
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.sys.seh;

version (Windows) {
	public import adbg.sys.windows.seh;
} else
version (Posix) {
	public import adbg.sys.posix.seh;
}