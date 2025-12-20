/// 
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.easy;

import adbg.debugger;
import adbg.error;
import adbg.os.mutex;
import adbg.os.semaphore;
import adbg.os.threads;
import adbg.process.base;
import adbg.utils.list;
import adbg.utils.mailbox;
import core.stdc.stdlib : calloc, free;

extern (C):

// Buffer entry
private
struct adbg_easy_request_t {
	int id;
	
	union {
	
	} // union
}

/// Represents an "easy" instance.
///
/// This can also be seen as a Debugger instance, too.
struct adbg_easy_t {
	__osthread_t   debugger_thread;
	mailbox_t      debugger_mbox;
	mailbox_t      replies; // OK/ERROR
	
	__osthread_t   events_thread;
	mailbox_t      events_mbox;
	list_t        *events_buffer;
	
	os_mutex_t     lock;
	
	adbg_process_t *process;
}

adbg_easy_t* adbg_easy_create() {
	// 
	adbg_easy_t *ez = cast(adbg_easy_t*)calloc(1, adbg_easy_t.sizeof);
	if (ez == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	if (adbg_mailbox_create(&ez.debugger_mbox, 10) ||
		adbg_mailbox_create(&ez.replies, 10) ||
		adbg_mailbox_create(&ez.events_mbox, 10)) {
		free(ez);
		return null;
	}
	
	if (os_mutex_init(&ez.lock)) {
		adbg_oops(AdbgError.os);
		free(ez);
		return null;
	}
	
	return ez;
}

void adbg_easy_destroy(adbg_easy_t *ez) {
	if (ez == null) return;

	// TODO: Send Quit messages
	
	
}

int adbg_easy_spawn(adbg_easy_t *ez, const(char) *path) {
	if (ez == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	int rc = adbg_mailbox_send(&ez.debugger_mbox,
		message_t(Request.spawn, cast(void*)path, 0));
	if (rc) return rc;
	
	message_t *msg = adbg_mailbox_receivefor(&ez.replies, 5000); // TODO: timeout option
	if (msg == null)
		return adbg_oops(AdbgError.assertion); // TODO: timeout error
	
	// Set error on this thread since error stuff is TLS now
	if (msg.type)
		return adbg_oops(cast(AdbgError)msg.type);
	
	return 0;
}

int adbg_easy_attach(adbg_easy_t *ez, int pid) {
	return -1;
}

// NOTE: adbg_debugger_on_* advantages over adbg_debugger_on(enum)
//       - Callback type checking (when source compiling)
//       - Access to attributes (like `deprecated`) per function
//       - No need to map and update enumeration values
//       - Better documentation per function

//
// Implementation
//

/* Easy API implementation details (DRAFT)

  Windows model
  Debug API & WaitForDebugEvent functions MUST be on the same thread
  
  User Thread <-> [Mailbox] <-> Debugger Thread + Event polling
                                  v
                                [Mailbox]
                                  v
                                Event Thread -> User Callback
  
  POSIX model
  On Linux, ptrace.2 & wait.2 can be called from different threads
  Don't know for BSDs at the moment
  
  User Thread <-> [Mailbox] <-> Debugger Thread
                                  v
                                <Spawns thread on spawn/attach>
                                  v
                                Event Thread -> User Callback

  Requests: See Request enum
  Response: 0 for success or AdbgError
  Event: AdbgEvent
*/

private:

enum Request {
	quit       = 1,
	
	spawn      = 100,
	attach     = 101,
	
	continue_  = 200,
	pause      = 201,
	
	readmemory = 500,
	writememory= 501,
}

struct request_spawn_t {
	char *path;
}

enum REPLY_OK  = 0;

//
// Easy API: Debug loop
//

void adbg_easy_thread_debugger(void *data) {
	assert(data);
	adbg_easy_t *ez = cast(adbg_easy_t*)data;
	
	version (Windows) uint timeout_ms = 100;
Lwait:
	// Wait for a request
	version (Windows)
		message_t *msg = adbg_mailbox_receivefor(&ez.debugger_mbox, timeout_ms);
	else
		message_t *msg = adbg_mailbox_receive(&ez.debugger_mbox);
	if (msg) {
		cast(void)os_mutex_acquire(&ez.lock);
		int err = adbg_easy_handle_request(ez, msg);
		cast(void)os_mutex_release(&ez.lock);
		if (err)
			adbg_mailbox_send(&ez.replies, message_t(err));
		else
			adbg_mailbox_send(&ez.replies, message_t(REPLY_OK));
	}
	
	// Check for debugging events, and send them to event thread
	// TODO: Check if process attached, not if exists
	version (Windows)
	if (ez.process) {
		adbg_event_t event = void;
		adbg_process_t *process = adbg_debugger_wait(ez.process, &event);
		if (process == null) {
			goto Lwait;
		}
		
		
	}
	goto Lwait;
}

// Just handle the request here, the caller (debugger thread) handles
// sending the message back to the caller
int adbg_easy_handle_request(adbg_easy_t *ez, message_t *msg) {
	switch (msg.type) {
	case Request.spawn:
		request_spawn_t *req = cast(request_spawn_t*)msg.data;
		
		adbg_process_t *proc = adbg_debugger_spawn(
			req.path,
			0);
		if (proc == null) {
			return adbg_error_code();
		}
		
		adbg_debugger_option_wait_timeout(ez.process, 100);
		break;
	default:
		return adbg_oops(AdbgError.assertion);
	}
	return 0;
}

//
// Event loops
//

// Easy API event handler thread
version (Windows)
void adbg_easy_thread_events_windows(void *data) {
	assert(data);
	adbg_easy_t *ez = cast(adbg_easy_t*)data;
	
Lwait:
	message_t *msg = adbg_mailbox_receive(&ez.events_mbox);
	if (msg == null)
		goto Lwait;
	
	// TODO: Send event to user callback
	adbg_event_t *event = cast(adbg_event_t*)msg.data;
	adbg_process_t *process = &event.process;
	
	// If the process exits, quit loop. Nothing else to wait on
	if (event.type == AdbgEvent.processExit)
		return;
	goto Lwait;
}

version (Posix)
void adbg_easy_thread_events_posix(void *data) {
	assert(data);
	adbg_easy_t *ez = cast(adbg_easy_t*)data;
	
	adbg_event_t event = void;
Lwait:
	adbg_process_t *process = adbg_debugger_wait(ez.process, &event);
	if (process == null)
		return;
	
	// TODO: Send event to user callback
	
	// If the process exits, quit loop. Nothing else to wait on
	if (event.type == AdbgEvent.processExit)
		return;
	goto Lwait;
}
