/// Provides a Mailbox API.
///
/// Uses a lock and two condition variables (not_empty / not_full) to implement
/// a bounded producer-consumer queue. Senders block when the mailbox is full;
/// receivers block when it is empty.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.utils.mailbox;

import adbg.error;
import adbg.os.lock;
import adbg.os.condvar;
import core.stdc.stdlib : calloc, malloc, free;
import core.stdc.string : memset, memcpy, memmove;

struct message_t {
	int type;
	void *data;
	/// Size of data excluding this structure
	size_t size;
}

struct mailbox_t {
	// queue
	message_t *messages;
	size_t capacity;
	size_t count; // current count (index)

	os_lock_t    lock;
	os_condvar_t not_empty; // signaled when count > 0
	os_condvar_t not_full;  // signaled when count < capacity
}

// capacity=mailbox size
int adbg_mailbox_create(mailbox_t *box, size_t capacity) {
	if (box == null || capacity == 0)
		return adbg_oops(AdbgError.invalidArgument);

	box.messages = cast(message_t*)malloc(message_t.sizeof * capacity);
	if (box.messages == null)
		return adbg_oops(AdbgError.crt);

	box.capacity = capacity;
	box.count    = 0;

	if (os_lock_init(&box.lock)) {
		free(box.messages);
		return adbg_oops(AdbgError.os);
	}
	if (os_condvar_init(&box.not_empty)) {
		free(box.messages);
		return adbg_oops(AdbgError.os);
	}
	if (os_condvar_init(&box.not_full)) {
		free(box.messages);
		return adbg_oops(AdbgError.os);
	}

	return 0;
}

void adbg_mailbox_destroy(mailbox_t *box) {
	if (box == null) return;

	free(box.messages);
	os_condvar_destroy(&box.not_full);
	os_condvar_destroy(&box.not_empty);
	os_lock_destroy(&box.lock);

	memset(box, 0, mailbox_t.sizeof);
}

int adbg_mailbox_send(mailbox_t *box, message_t msg) {
	if (box == null)
		return adbg_oops(AdbgError.invalidArgument);

	cast(void)os_lock_acquire(&box.lock);

	// Block until space is available
	while (box.count >= box.capacity)
		os_condvar_wait(&box.not_full, &box.lock);

	memcpy(box.messages + box.count, &msg, message_t.sizeof);
	box.count++;

	os_condvar_signal(&box.not_empty);
	cast(void)os_lock_release(&box.lock);

	return 0;
}

int adbg_mailbox_send_priority(mailbox_t *box, message_t msg) {
	if (box == null)
		return adbg_oops(AdbgError.invalidArgument);

	cast(void)os_lock_acquire(&box.lock);

	// Block until space is available
	while (box.count >= box.capacity)
		os_condvar_wait(&box.not_full, &box.lock);

	// Move items by one message
	memmove(
		box.messages + 1, // to
		box.messages,     // from
		message_t.sizeof * box.count); // size

	// Copy to [0]
	memcpy(box.messages, &msg, message_t.sizeof);
	box.count++;

	os_condvar_signal(&box.not_empty);
	cast(void)os_lock_release(&box.lock);

	return 0;
}

message_t* adbg_mailbox_receive(mailbox_t *box) {
	if (box == null)
		return null;

	cast(void)os_lock_acquire(&box.lock);

	// Block until a message is available
	while (box.count == 0)
		os_condvar_wait(&box.not_empty, &box.lock);

	message_t *msg = &box.messages[--box.count];

	os_condvar_signal(&box.not_full);
	cast(void)os_lock_release(&box.lock);

	return msg;
}

message_t* adbg_mailbox_receivefor(mailbox_t *box, uint ms) {
	if (box == null)
		return null;

	cast(void)os_lock_acquire(&box.lock);

	while (box.count == 0) {
		int status = void;
		if (os_condvar_waitfor(&box.not_empty, &box.lock, ms, &status) || status) {
			// error or timeout
			cast(void)os_lock_release(&box.lock);
			return null;
		}
	}

	message_t *msg = &box.messages[--box.count];

	os_condvar_signal(&box.not_full);
	cast(void)os_lock_release(&box.lock);

	return msg;
}
