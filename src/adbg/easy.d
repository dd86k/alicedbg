/// 
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.easy;

import adbg.debugger;
public import adbg.error;
import adbg.os.mutex;
import adbg.os.semaphore;
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

/// Represents an "easy" instance.
///
/// This can also be seen as a Debugger instance, too.
struct adbg_easy_t {
	os_mutex_t     lock;
	
	__osthread_t *debugger_thread;
	__osthread_t *event_thread;
	
	// NOTE: list_t
	//       list_t was initially created to add non-existing items to a list
	//       It wasn't really meant as a static buffer, so it is not used here
	//       to hold a dynamically sized buffer of items, only fixed (at
	//       creation time).
	
	mailbox_t            request_box;
	adbg_easy_request_t *request_buffer;
	size_t               request_count;
	
	mailbox_t          reply_box;
	adbg_easy_reply_t *reply_buffer;
	size_t             reply_count;
	
	mailbox_t      event_box;
	adbg_event_t  *event_buffer;
	
	int status;
	
	adbg_process_t *process;
}

adbg_easy_t* adbg_easy_create() {
	// 
	adbg_easy_t *ez = cast(adbg_easy_t*)calloc(1, adbg_easy_t.sizeof);
	if (ez == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Create buffers
	ez.request_buffer = cast(adbg_easy_request_t*)calloc(CAPACITY, adbg_easy_request_t.sizeof);
	if (ez.request_buffer == null) {
		adbg_oops(AdbgError.crt);
		goto Lerror;
	}
	ez.reply_buffer = cast(adbg_easy_reply_t*)calloc(CAPACITY, adbg_easy_reply_t.sizeof);
	if (ez.reply_buffer == null) {
		adbg_oops(AdbgError.crt);
		goto Lerror;
	}
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
	
	return ez;
Lerror:
	if (ez.reply_buffer)   free(ez.reply_buffer);
	if (ez.request_buffer) free(ez.request_buffer);
	if (ez.event_buffer)   free(ez.event_buffer);
	free(ez);
	return null;
}

void adbg_easy_destroy(adbg_easy_t *ez) {
	if (ez == null) return;

	// TODO: Send Quit messages to threads and wait for them to exit

	if (ez.event_thread)    os_thread_join(ez.event_thread);
	if (ez.debugger_thread) os_thread_join(ez.debugger_thread);

	adbg_mailbox_destroy(&ez.request_box);
	adbg_mailbox_destroy(&ez.reply_box);
	adbg_mailbox_destroy(&ez.event_box);

	os_mutex_destroy(&ez.lock);

	if (ez.request_buffer) free(ez.request_buffer);
	if (ez.reply_buffer)   free(ez.reply_buffer);
	if (ez.event_buffer)   free(ez.event_buffer);

	free(ez);
}

int adbg_easy_spawn(adbg_easy_t *ez, const(char) *path) {
	if (ez == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	os_mutex_acquire(&ez.lock);
	
	//
	if (ez.process && adbg_process_is_attached(ez.process)) {
		os_mutex_release(&ez.lock);
		return adbg_oops(AdbgError.debuggerPresent);
	}
	
	// Stuff request in buffer
	if (ez.request_count >= CAPACITY) {
		// Can't really do anything here yet
		// Need a mailbox function to check number of items or status (ie, full)
		os_mutex_release(&ez.lock);
		return adbg_oops(AdbgError.assertion);
	}
	
	adbg_easy_request_t *req = ez.request_buffer + ez.request_count++;
	req.type = Request.spawn;
	req.spawn.path = path;
	os_mutex_release(&ez.lock);
	
	// If the debugger thread hasn't started, start it
	if (ez.debugger_thread == null) {
		ez.debugger_thread = os_thread_new(&adbg_easy_thread_debugger, ez);
		if (ez.debugger_thread == null) {
			--ez.request_count;
			return adbg_oops(AdbgError.os);
		}
	}
	
	// Send it
	int rc = adbg_mailbox_send(&ez.request_box, message_t(0, req, 0));
	if (rc) return rc;
	
	// Get reply
	message_t *msg = adbg_mailbox_receivefor(&ez.reply_box, 5000); // TODO: timeout option
	if (msg == null)
		return adbg_oops(AdbgError.assertion); // TODO: "operation timed out" error
	
	os_mutex_acquire(&ez.lock); // should replies have their own locks?
	
	ez.reply_count--;
	
	adbg_easy_reply_t *reply = cast(adbg_easy_reply_t*)msg.data;
	assert(reply, "reply==NULL");
	if (reply.type == Reply.error) {
		adbg_error_paste(&reply.error);
		os_mutex_release(&ez.lock);
		return reply.error.code;
	}

	os_mutex_release(&ez.lock);

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

enum {
	/// Debugger is attached.
	EASY_ATTACHED = 1,
	/// Process has stopped.
	EASY_STOPPED  = 1 << 1,
	/// Process has exited.
	EASY_EXITED   = 1 << 2,
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

// Buffer entry
struct adbg_easy_request_t {
	Request type;
	union {
	adbg_easy_request_spawn_t spawn;
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
// Easy API: Debug loop
//

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
	if (msg) {
		cast(void)os_mutex_acquire(&ez.lock);

		// Stuff reply in buffer
		if (ez.reply_count >= CAPACITY) {
			assert(false); // HACK: BAD but i need to know
		}

		adbg_easy_reply_t *reply = ez.reply_buffer + ez.reply_count++;

		int err = adbg_easy_handle_request(ez, msg);
		if (err) {
			reply.type = Reply.error;
			adbg_error_copy(&reply.error);
		} else {
			reply.type = Reply.success;
		}

		cast(void)os_mutex_release(&ez.lock);

		adbg_mailbox_send(&ez.reply_box, message_t(0, reply));
	}
	
	// Windows: Poll for debugging events, and send them to event thread
	// TODO: Check if process attached, not if exists
	version (Windows)
	if (ez.process) {
		adbg_event_t event = void;
		adbg_process_t *process = adbg_debugger_wait(ez.process, &event);
		if (process == null) // TODO: Should we error?
			goto Lwait;
		
		adbg_mailbox_send(&ez.event_box, message_t(0, &event, adbg_event_t.sizeof));
	}
	goto Lwait;
}

// Just handle the request here, the caller (debugger thread) handles
// sending the message back to the caller
int adbg_easy_handle_request(adbg_easy_t *ez, message_t *msg) {
	adbg_easy_request_t *req = cast(adbg_easy_request_t*)msg.data;
	
	switch (req.type) {
	case Request.spawn:
		adbg_process_t *proc = adbg_debugger_spawn(
			req.spawn.path,
			0);
		if (proc == null) {
			return adbg_error_code();
		}

		ez.process = proc;

		version (Windows)
			adbg_debugger_option_wait_timeout(ez.process, 100);

		version (Windows)
		ez.event_thread =
			os_thread_new(&adbg_easy_thread_events_windows, ez);
		version (Posix)
		ez.event_thread =
			os_thread_new(&adbg_easy_thread_events_posix, ez);
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
int adbg_easy_thread_events_windows(__osthread_t *thread, void *data) {
	assert(data);
	adbg_easy_t *ez = cast(adbg_easy_t*)data;
	
Lwait:
	message_t *msg = adbg_mailbox_receive(&ez.event_box);
	if (msg == null)
		goto Lwait;
	
	// TODO: Send event to user callback
	adbg_event_t *event = cast(adbg_event_t*)msg.data;
	adbg_process_t *process = &event.process;
	
	// If the process exits, quit loop. Nothing else to wait on
	if (event.type == AdbgEvent.processExit)
		return 0;
	goto Lwait;
}

version (Posix)
int adbg_easy_thread_events_posix(__osthread_t *thread, void *data) {
	assert(data);
	adbg_easy_t *ez = cast(adbg_easy_t*)data;
	
	adbg_event_t event = void;
Lwait:
	adbg_process_t *process = adbg_debugger_wait(ez.process, &event);
	if (process == null)
		return adbg_error_code();
	
	// TODO: Send event to user callback
	
	// If the process exits, quit loop. Nothing else to wait on
	if (event.type == AdbgEvent.processExit)
		return 0;
	goto Lwait;
}
