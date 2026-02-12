/// 
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.easy;

import adbg.debugger;
public import adbg.error;
import adbg.os.mutex;
import adbg.os.threads;
import adbg.process.base;
import adbg.utils.mailbox;
import core.stdc.stdlib : calloc, free;

extern (C):

// TODO: Multithread test
//
//       Right now, this assumes one thread caller, but real-world environments,
//       this could be multiple callers, which will need better sync mechanics.
//
//       One example being if a second thread calls a request fonctions and
//       gets the incorrect response (Request 3 finishing before Reuqest 2).

/// Message capacity for mailboxes
private enum CAPACITY = 10;

/// Represents an Easy instance.
struct adbg_easy_t {
	os_mutex_t     lock;
	
	__osthread_t *debugger_thread;
	__osthread_t *event_thread;
	
	// NOTE: list_t
	//       list_t was initially created to add non-existing items to a list
	//       It wasn't really meant as a static buffer, so it is not used here
	//       to hold a dynamically sized buffer of items, only fixed (at
	//       creation time).
	
	mailbox_t          request_box;

	mailbox_t          reply_box;
	adbg_easy_reply_t  reply;
	
	mailbox_t      event_box;
	adbg_event_t  *event_buffer;

	adbg_process_t *process;
	
	// TODO: Event callbacks here
}

/// Create a new Easy instance for use with the Easy API.
/// Returns: Easy instance; Or null on error.
adbg_easy_t* adbg_easy_create() {
	version (Trace) trace("adbg_easy_t.sizeof=%d", cast(int)adbg_easy_t.sizeof);
	
	// 
	adbg_easy_t *ez = cast(adbg_easy_t*)calloc(1, adbg_easy_t.sizeof);
	if (ez == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Create buffers
	ez.event_buffer = cast(adbg_event_t*)calloc(CAPACITY, adbg_event_t.sizeof);
	if (ez.event_buffer == null) {
		adbg_oops(AdbgError.crt);
		goto Lerror;
	}
	
	// Create mailboxes
	if (adbg_mailbox_create(&ez.request_box, CAPACITY) ||
		adbg_mailbox_create(&ez.reply_box, CAPACITY) ||
		adbg_mailbox_create(&ez.event_box, CAPACITY)) { // error already set
		goto Lerror;
	}
	
	//
	if (os_mutex_init(&ez.lock)) {
		adbg_oops(AdbgError.os);
		goto Lerror;
	}

	// Start debugger thread (blocks waiting for requests)
	ez.debugger_thread = os_thread_new(&adbg_easy_thread_debugger, ez);
	if (ez.debugger_thread == null) {
		adbg_oops(AdbgError.os);
		goto Lerror;
	}

	return ez;
Lerror:
	if (ez.event_buffer)   free(ez.event_buffer);
	free(ez);
	return null;
}

/// Destroy the Easy instance.
///
/// If the target process was spawned, it is terminated.
/// If the target process was attached, the debugger detaches.
/// Params: ez = Easy instance.
void adbg_easy_destroy(adbg_easy_t *ez) {
	version (Trace) trace("ez=%p", ez);
	
	if (ez == null) return;
	
	// Windows need to terminate process in debugger thread
	adbg_easy_request_t req = adbg_easy_request_t(Request.quit);
	if (adbg_easy_request(ez, &req))
		return; // error, so can't continue cleanup, fuck!
	
	//adbg_mailbox_send(&ez.request_box, message_t(0, &quit_req, 0));
	if (ez.debugger_thread) os_thread_join(ez.debugger_thread); // cleanup
	if (ez.event_thread)    os_thread_join(ez.event_thread);    // cleanup

	// Threads are gone, time to clean up
	if (ez.process) adbg_process_free(ez.process);
	adbg_mailbox_destroy(&ez.request_box);
	adbg_mailbox_destroy(&ez.reply_box);
	adbg_mailbox_destroy(&ez.event_box);
	os_mutex_destroy(&ez.lock);

	if (ez.event_buffer)   free(ez.event_buffer);

	free(ez);
}

/// Spawn a new process to be tracked by the debugger.
/// Params:
/// 	ez = Easy instance.
/// 	path = Null-terminated path pointer.
/// Returns: Zero on success; Non-zero on error.
int adbg_easy_spawn(adbg_easy_t *ez, const(char) *path) {
	version (Trace) trace("ez=%p path=%p", ez, path);
	
	if (ez == null)
		return adbg_oops(AdbgError.invalidArgument);

	adbg_easy_request_t req = void;
	req.type = Request.spawn;
	req.spawn.path = path;
	return adbg_easy_request(ez, &req);
}

/// Attaches to an existing process to be tracked by the debugger.
/// Params:
/// 	ez = Easy instance.
/// 	pid = Process ID.
/// Returns: Zero on success; Non-zero on error.
int adbg_easy_attach(adbg_easy_t *ez, int pid) {
	version (Trace) trace("ez=%p pid=%d", ez, pid);
	
	if (ez == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	adbg_easy_request_t req = void;
	req.type = Request.attach;
	req.attach.pid = pid;
	return adbg_easy_request(ez, &req);
}

/// Ask if the process is still alive.
/// Params: ez = Easy instance.
/// Returns: Zero on success; Non-zero on error.
int adbg_easy_process_is_alive(adbg_easy_t *ez) {
	version (Trace) trace("ez=%p", ez);
	
	if (ez == null || ez.process == null)
		return adbg_oops(AdbgError.invalidArgument);
	return adbg_process_is_alive(ez.process);
}

// NOTE: Debugger events
//       Because this is multithreaded, obviously, callbacks are much better suited
//       for Easy API than Multi API.
//       adbg_debugger_on_EVENT(callback) advantages over adbg_debugger_on(enum, callback):
//       - Callback type checking (when source compiling)
//       - Access to attributes (like `deprecated`) per function
//       - No need to map and update enumeration values
//       - Better documentation per function

private:

/* Easy API architecture (DRAFT)

  Windows model
  Debug API & WaitForDebugEvent functions MUST be on the same thread
  
  User Thread
    [Request Mailbox]
      Debugger Thread + Event polling
        On Attach/Spawn: Spawn event thread
        On Event: [Event Mailbox] -> Event Thread -> User Callback
  
  POSIX model
  On Linux, ptrace.2 & wait.2 can be called from different threads
  Don't know for BSDs at the moment
  
  User Thread
    [Request Mailbox]
      Debugger Thread
        On Attach/Spawn: Spawn event thread
	On Event: Event Thread -> User Callback

  Requests: See Request enum
  Response: 0 for success or AdbgError
  Event: AdbgEvent
*/

enum { // Easy instance status flags
	EASY_ATTACHED = 1 << 0,
}

//
// Requests
//

enum Request {
	quit       = 1,
	
	spawn      = 100,
	attach     = 101,
	
	continue_  = 200,
	pause      = 201,
	
	readmemory = 500,
	writememory= 501,
}

struct adbg_easy_request_spawn_t {
	const(char) *path;
}

struct adbg_easy_request_attach_t {
	int pid;
}

// Buffer entry
struct adbg_easy_request_t {
	Request type;
	union {
	adbg_easy_request_spawn_t spawn;
	adbg_easy_request_attach_t attach;
	} // union
}

//
// Replies/Responses
//

enum Reply {
	success,
	error,
}

// 
struct adbg_easy_reply_t {
	Reply type;
	union {
	adbg_error_t error;
	}
}

//
// Easy API: Request helper
//

/// Send a request to the debugger thread and wait for a reply.
/// Optionally returns the reply pointer for callers that need response data.
/// Params:
/// 	ez = Easy instance.
/// 	req = Request instance.
/// 	reply_out = (Optional) If caller needs to check reply of debugging function.
/// Returns: Error code for request.
int adbg_easy_request(adbg_easy_t *ez, adbg_easy_request_t *req,
		adbg_easy_reply_t **reply_out = null) {
	// Send request (mailbox handles blocking if full)
	int rc = adbg_mailbox_send(&ez.request_box, message_t(0, req, 0));
	if (rc) return rc;

	// Wait for reply
	uint timeout_ms = 5000; // TODO: timeout setting
	message_t *msg = adbg_mailbox_receivefor(&ez.reply_box, timeout_ms);
	if (msg == null)
		return adbg_oops(AdbgError.timeout);

	adbg_easy_reply_t *reply = cast(adbg_easy_reply_t*)msg.data;
	assert(reply, "reply==NULL");

	if (reply_out)
		*reply_out = reply;

	if (reply.type == Reply.error) {
		adbg_error_paste(&reply.error);
		return reply.error.code;
	}

	return 0;
}

//
// Easy API: Debug loop
//

enum EVENT_MSG_QUIT = 1;

int adbg_easy_thread_debugger(__osthread_t *thread, void *data) {
	assert(data);
	adbg_easy_t *ez = cast(adbg_easy_t*)data;
	
	version (Windows) uint timeout_ms = 100;
Lwait:
	// Wait for a request
	version (Windows)
		message_t *msg = adbg_mailbox_receivefor(&ez.request_box, timeout_ms);
	else
		message_t *msg = adbg_mailbox_receive(&ez.request_box);
	if (msg) { // null: timeout
		adbg_easy_request_t *req = cast(adbg_easy_request_t*)msg.data;
		if (req.type == Request.quit) {
			// Signal event thread to stop
			if (ez.event_thread)
				adbg_mailbox_send(&ez.event_box, message_t(EVENT_MSG_QUIT));
			adbg_mailbox_send(&ez.reply_box, message_t(0, &ez.reply));
			return 0;
		}

		int err = adbg_easy_handle_request(ez, msg);
		if (err) {
			ez.reply.type = Reply.error;
			adbg_error_copy(&ez.reply.error);
		} else {
			ez.reply.type = Reply.success;
		}

		adbg_mailbox_send(&ez.reply_box, message_t(0, &ez.reply));
	}
	
	// Windows: Poll for debugging events, and send them to event thread
	// TODO: Check if process is attached
	//       Would make more sense, but it is an more expensive call to do in a loop
	version (Windows)
	if (ez.process) {
		adbg_event_t event = void;
		adbg_process_t *process = adbg_debugger_wait(ez.process, &event);
		if (process == null) // TODO: Should we error?
			goto Lwait;
		
		adbg_mailbox_send(&ez.event_box, message_t(0, &event, adbg_event_t.sizeof));

		// HACK: Continue so next WaitForDebugEvent doesn't block
		if (event.type == AdbgEvent.exception)
			adbg_debugger_continue(ez.process, event.exception.thread.id);
	}
	goto Lwait;
}

// Just handle the request here, the caller (debugger thread) handles
// sending the message back to the caller
int adbg_easy_handle_request(adbg_easy_t *ez, message_t *msg) {
	adbg_easy_request_t *req = cast(adbg_easy_request_t*)msg.data;
	
	version (Trace) trace("ez=%p msg=%p req=%p", ez, msg, req);
	
	version (Windows) uint timeout_ms = 100; // default timeout
	switch (req.type) {
	case Request.spawn:
		version (Trace) trace("request:spawn path=%p", req.spawn.path);
		
		if (ez.process && adbg_process_is_attached(ez.process))
			return adbg_oops(AdbgError.debuggerPresent);

		ez.process = adbg_debugger_spawn(
			req.spawn.path,
			0);
		if (ez.process == null)
			return adbg_error_code();

		// Hacks to make multi-threaded events work
		version (Windows)
			adbg_debugger_option_wait_timeout(ez.process, timeout_ms);

		// Make event thread
		version (Windows)
		ez.event_thread =
			os_thread_new(&adbg_easy_thread_events_windows, ez);
		version (Posix)
		ez.event_thread =
			os_thread_new(&adbg_easy_thread_events_posix, ez);
		if (ez.event_thread == null)
			return adbg_oops(AdbgError.os);
		break;
	case Request.attach:
		version (Trace) trace("request:spawn pid=%p", req.attach.pid);
		
		if (ez.process && adbg_process_is_attached(ez.process))
			return adbg_oops(AdbgError.debuggerPresent);
		
		ez.process = adbg_debugger_attach(req.attach.pid, 0);
		if (ez.process == null)
			return adbg_error_code();

		// Hack to make multi-threaded events work
		version (Windows)
			adbg_debugger_option_wait_timeout(ez.process, timeout_ms);
		
		// Make event thread
		version (Windows)
			ez.event_thread = os_thread_new(&adbg_easy_thread_events_windows, ez);
		version (Posix)
			ez.event_thread = os_thread_new(&adbg_easy_thread_events_posix, ez);
		if (ez.event_thread == null)
			return adbg_oops(AdbgError.os);
		break;
	case Request.quit:
		version (Trace) trace("request:quit");
		
		// Signal threads to exit and wait for them to finish
		//
		// Terminate/detach first to unblock event threads:
		// - POSIX: unblocks waitpid in event thread
		// - Windows: produces processExit via WaitForDebugEvent,
		//   which the debugger thread forwards to event_box
		//
		// If this doesn't work (ie, on Windows), then switch to request instead
		if (ez.process && adbg_process_is_alive(ez.process)) {
			int attached = adbg_process_is_attached(ez.process);
			if (attached > 0)
				adbg_debugger_detach(ez.process);
			else if (attached == 0)
				adbg_debugger_terminate(ez.process);
			else // error
				return attached;
		}
		break;
	default:
		version (Trace) trace("request:unknown req.type=%d", req.type);
		return adbg_oops(AdbgError.assertion);
	}
	return 0;
}

//
// Event loops
//

// Called from Event thread (adbg_easy_thread_events_windows or adbg_easy_thread_events_posix)
// 
//void adbg_easy_send_event(

// Windows event thread
//
// Windows' Win32 Debugger API requires that both debugging requests and events
// be done on the same thread. So, we create a thread that listens to events
// through the event mailbox.
version (Windows)
int adbg_easy_thread_events_windows(__osthread_t *thread, void *data) {
	assert(data);
	adbg_easy_t *ez = cast(adbg_easy_t*)data;

Lwait:
	message_t *msg = adbg_mailbox_receive(&ez.event_box);
	// HACK: msg.type==1 is sent by debugger thread when quitting
	if (msg == null || msg.type == EVENT_MSG_QUIT)
		return 0;

	// TODO: Send event to user callback
	adbg_event_t *event = cast(adbg_event_t*)msg.data;
	adbg_process_t *process = &event.process;

	switch (event.type) {
	case AdbgEvent.exception:
		// TODO: if event callback set, call it
		break;
	// If the process exits, quit loop. Nothing else to wait on
	case AdbgEvent.processExit:
		return 0;
	default:
		version (Trace) trace("not implemented: %d", event.type);
	}
	goto Lwait;
}

// POSIX event thread
//
// It has been observed that on Linux, the wait call can be called from another
// thread. Assuming this is correct for other POSIX-complient (need to check specs),
// we created a thread that only waits for events.
//
// Currently, this handles one process. If this process quits, this loop terminates.
// We could poll for other events through the event mailbox (for better control), but
// this should do the trick as a basic implementation.
version (Posix)
int adbg_easy_thread_events_posix(__osthread_t *thread, void *data) {
	assert(data);
	adbg_easy_t *ez = cast(adbg_easy_t*)data;
	
	// NOTE: When terminating, the detach/exit event makes this thread quit
	adbg_event_t event = void;
Lwait:
	adbg_process_t *process = adbg_debugger_wait(ez.process, &event);
	if (process == null)
		return adbg_error_code();
	
	// TODO: Send event to user callback
	
	switch (event.type) {
	case AdbgEvent.exception:
		// TODO: if event callback set, call it
		adbg_debugger_continue(ez.process, event.exception.thread.id);
		break;
	// If the process exits, quit loop. Nothing else to wait on
	case AdbgEvent.processExit:
		return 0;
	default:
		version (Trace) trace("not implemented: %d", event.type);
	}
	goto Lwait;
}
