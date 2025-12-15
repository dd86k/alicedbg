/// 
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.easy;

import adbg;
import adbg.utils.list;
import adbg.os.threads;
import core.sys.openbsd.stdlib;
import core.stdc.stdlib : calloc, free;

/*
Main Thread <-> [Mailbox] <-> Debugger Thread
                                v
                              [Mailbox]
                                v
                              Event Thread -> Client Callback


1. Client requests action/info
2. Adbg creates request internally
3. Adbg Thread handles request, ownership transferred
4. Done, handler calls client callback
*/

enum EasyReq {
	spawn      = 100,
	attach     = 101,
	
	continue_  = 200,
	stop       = 201,
	
	readmem    = 500,
	writemem   = 501,
}

enum EasyOpt {
	dwawddawadw
}

// Buffer entry
private
struct adbg_easy_request_t {
	int id;
	
	union {
	
	adbg_process_t *proc;
	
	} // union
}

// Instance with buffer
struct adbg_easy_t {
	
	
	list_t buffer;
	
	__osthread_t thread_debugger;
	__osthread_t thread_events;
	
	// EVENT: On exception.
	void function() ev_exception;
	// EVENT: On breakpoint.
	void function() ev_breakpoint;
}

adbg_easy_t* adbg_easy_create() {
	
	
	
	return null;
}

int adbg_easy_option(adbg_easy_t *e, int opt, void *val) {
	return -1;
}

int adbg_easy(EasyReq req, void *data, void function(void*) callback) {
	return -1;
}

//
// Implementation
//

private:

void adbg_easy_thread_debugger(adbg_easy_t *e) {
	
}

version (Posix)
void adbg_easy_thread_posix_events() {
	
}