/// Minimal example using the Easy API.
///
/// Spawns a process and prints debug events until exit or first fault.
/// The Easy API handles the debugger loop on a separate thread.
///
/// Use `dub build :easy-example` (from parent dir) to build.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module examples.easy;

import core.stdc.stdio;
import core.stdc.stdlib : exit, EXIT_FAILURE;
import adbg;
import adbg.easy;

extern (C): __gshared: private:

int done;

void oops(int code = 0, const(char) *reason = null) {
	printf("* error=\"%s\" code=\"%d\"\n",
		reason ? reason : adbg_error_message(),
		code ? code : adbg_error_code()
	);
	exit(EXIT_FAILURE);
}

void event_handler(adbg_process_t *process, adbg_event_t *event, void *udata) {
	switch (event.type) {
	case AdbgEvent.exception:
		adbg_exception_t *exc = &event.exception;
		adbg_process_thread_t *thread = adbg_exception_thread(exc);
		long tid = thread ? adbg_process_thread_id(thread) : 0;

		printf(`* pid=%d tid=%lld event="exception" name="%s" oscode=`~ERR_OSFMT~"\n",
			adbg_process_id(process), tid,
			adbg_exception_name(exc), adbg_exception_orig_code(exc));

		switch (adbg_exception_type(exc)) with (AdbgException) {
		case Breakpoint, Step:
			// Initial breakpoint or single-step: continue
			adbg_easy_continue(cast(adbg_easy_t*)udata);
			break;
		default:
			// First real fault: stop
			done = 1;
		}
		break;
	case AdbgEvent.processCreated:
		printf("* event=\"created\" pid=%d\n", adbg_process_id(process));
		break;
	case AdbgEvent.processContinue:
		printf("* event=\"continued\" pid=%d\n", adbg_process_id(process));
		break;
	case AdbgEvent.processExit:
		printf("* event=\"exited\" pid=%d code=%d\n", adbg_process_id(process), event.exitcode);
		done = 1;
		break;
	default:
	}
}

int main(int argc, const(char) **argv) {
	if (argc < 2)
		oops(1, "Missing path to executable");

	// 1. Create easy instance
	adbg_easy_t *ez = adbg_easy_create();
	if (ez == null)
		oops;

	// 2. Set event handler (pass ez as user data so we can call continue)
	adbg_easy_set_event_handler(ez, &event_handler);
	adbg_easy_set_user_data(ez, ez);

	// 3. Spawn executable
	if (adbg_easy_spawn(ez, argv[1]))
		oops;

	// 4. Wait until done (event handler sets the flag)
	while (!done) {}

	// 5. Clean up
	puts("* quitting");
	adbg_easy_destroy(ez);
	return 0;
}
