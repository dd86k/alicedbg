/**
 * (Not implemented) Provides status messaging for up-to-date information from
 * the debugger, useful for UIs (users) to know what the debugger is working on.
 *
 * License: BSD 3-Clause
 */
module debugger.status;

private void function(const(char)*) status_handler;

/**
 * Set status handler (from UI).
 * Params: h = UI Status message handler
 */
void status_set(void function(const(char)*) h) {
	status_handler = h;
}

/**
 * Update status. If the handler is set, this calls the UI's handler; Otherwise
 * it's a NO-OP.
 * Params: m = Status update messages
 */
void status_update(const(char) *m) {
	if (status_handler)
		status_handler(m);
}