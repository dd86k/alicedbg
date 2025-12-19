/// Provides a Mailbox API.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.utils.mailbox;

import adbg.error;
import adbg.os.mutex;
import adbg.os.semaphore;
import adbg.os.threads;
import core.stdc.stdlib : calloc, malloc, free;
import core.stdc.string : memset, memcpy;

struct message_t {
	int type;
	void *data;
	size_t size;
}

struct mailbox_t {
	// queue
	message_t *messages;
	size_t capacity;
	size_t count; // current count (index)
	
	os_mutex_t mutex;
	os_semaphore_t sem;
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
	
	os_mutex_init(&box.mutex);
	os_sem_create(&box.sem);
	
	return 0;
}
void adbg_mailbox_destroy(mailbox_t *box) {
	if (box == null) return;
	
	// TODO: wait/close stuff
	
	free(box.messages);
	os_mutex_destroy(&box.mutex);
	os_sem_close(&box.sem);
	
	memset(box, 0, mailbox_t.sizeof);
}

int adbg_mailbox_send(mailbox_t *box, message_t msg) {
	// TODO: adbg_oops is not thread safe
	if (box == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	cast(void)os_mutex_acquire(&box.mutex);
	if (box.count >= box.capacity) {
		cast(void)os_mutex_release(&box.mutex);
		// TODO: Wait until capacity available again
		//       Or make it a stategy
		// TODO: adbg_oops is not thread safe
		return adbg_oops(AdbgError.assertion);
	}
	memcpy(box.messages + box.count, &msg, message_t.sizeof);
	box.count++;
	cast(void)os_mutex_release(&box.mutex);
	
	os_sem_notify(&box.sem);
	return 0;
}

message_t* adbg_mailbox_receive(mailbox_t *box) {
	if (box == null)
		return null;
	
	os_sem_wait(&box.sem);
	
	os_mutex_acquire(&box.mutex);
	if (box.count == 0) {
		cast(void)os_mutex_release(&box.mutex);
		return null;
	}
	message_t *msg = &box.messages[box.count--];
	os_mutex_release(&box.mutex);
	
	return msg;
}

message_t* adbg_mailbox_receivefor(mailbox_t *box, uint ms) {
	if (box == null)
		return null;
	
	int status = void;
	if (os_sem_waitfor(&box.sem, ms, &status) || status)
		return null;
	
	os_mutex_acquire(&box.mutex);
	if (box.count == 0) {
		cast(void)os_mutex_release(&box.mutex);
		return null;
	}
	message_t *msg = &box.messages[box.count--];
	os_mutex_release(&box.mutex);
	
	return msg;
}
