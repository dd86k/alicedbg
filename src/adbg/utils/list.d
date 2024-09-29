/// List utilities.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.utils.list;

import core.stdc.stdlib : malloc, calloc, realloc, free;
import core.stdc.string : memcpy;
import adbg.error : adbg_oops, AdbgError;

extern (C):

struct list_t {
	size_t capacity; /// Capacity in number of items
	size_t itemsize; /// Size of one item
	size_t count;    /// Current item count
	void *buffer;    /// Item buffer
}

/// Allocate a new dynamic list.
/// Params:
/// 	itemsize = Size of one item, in bytes.
/// 	capacity = Initial capacity size, in number of items.
/// Returns: List instance. On error, null is returned.
list_t* adbg_list_new(size_t itemsize, size_t capacity) {
	if (itemsize == 0) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	list_t *list = cast(list_t*)malloc(list_t.sizeof + (itemsize * capacity));
	if (list == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	list.capacity = capacity;
	list.itemsize = itemsize;
	list.count = 0;
	list.buffer = cast(void*)list + list_t.sizeof;
	return list;
}
unittest {
	// new
	list_t *list = adbg_list_new(int.sizeof, 4);
	assert(list);
	assert(list.capacity == 4);
	assert(list.count == 0);
	assert(list.itemsize == int.sizeof);
	assert(adbg_list_get(list, 0) == null);
	adbg_list_free(list);
}

/// Add an item to the list.
///
/// Item data is copied into the list.
///
/// If the returned list pointer is null, no content was changed, but an error occured.
/// You are free to either close the list or continue with the current, unchanged list.
///
/// Due to realloc(3), it is important to set the new list pointer.
/// Params:
/// 	list = List instance.
/// 	item = Item.
/// Returns: List instance pointer. On error, null is returned.
list_t* adbg_list_add(list_t *list, void *item) {
	if (list == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	assert(list.buffer);
	assert(list.itemsize);
	
	// Increase capacity
	if (list.count >= list.capacity) {
		size_t newcapacity = list.capacity << 1; // double capacity
		// NOTE: MSVC will always assign a new memory block
		list = cast(list_t*)realloc(list, list_t.sizeof + (list.itemsize * newcapacity));
		if (list == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		
		// realloc(3) should have copied data to new block
		// Only need to readjust buffer pointer
		list.capacity = newcapacity;
		list.buffer = cast(void*)list + list_t.sizeof;
	}
	
	// Copy item into buffer
	void *loc = list.buffer + (list.itemsize * list.count++);
	memcpy(loc, item, list.itemsize);
	return list;
}
unittest {
	// new
	list_t *list = adbg_list_new(int.sizeof, 4);
	
	// add
	int id = 25;
	adbg_list_add(list, &id); // count=1
	assert(list.capacity == 4);
	assert(list.count == 1);
	assert(list.itemsize == int.sizeof);
	assert(adbg_list_get(list, 0));
	assert(*cast(int*)adbg_list_get(list, 0) == 25);
	assert((list = adbg_list_add(list, &id)) != null); // count=2
	assert((list = adbg_list_add(list, &id)) != null); // count=3
	assert((list = adbg_list_add(list, &id)) != null); // count=4
	assert(list.capacity == 4);
	assert(list.count == 4);
	assert(list.itemsize == int.sizeof);
	
	// more add+get
	id = 333;
	assert((list = adbg_list_add(list, &id)) != null); // count=5
	assert((list = adbg_list_add(list, &id)) != null); // count=6
	assert((list = adbg_list_add(list, &id)) != null); // count=7
	assert(list.capacity > 4);
	assert(list.count == 7);
	assert(list.itemsize == int.sizeof);
	
	adbg_list_free(list);
}

/// Get an item at this index.
/// Params:
/// 	list = List instance.
/// 	index = Item index.
/// Returns: Item pointer. On error, null is returned.
void* adbg_list_get(list_t *list, size_t index) {
	if (list == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (index >= list.count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	assert(list.buffer);
	return list.buffer + (list.itemsize * index);
}
unittest {
	// new
	list_t *list = adbg_list_new(int.sizeof, 4);
	
	int a = 1; list = adbg_list_add(list, &a);
	a = 2;     list = adbg_list_add(list, &a);
	int *a1p = cast(int*)adbg_list_get(list, 0);
	int *a2p = cast(int*)adbg_list_get(list, 1);
	int *anp = cast(int*)adbg_list_get(list, 2);
	assert(a1p);
	assert(a2p);
	assert(anp == null);
	assert(*a1p == 1);
	assert(*a2p == 2);
	
	adbg_list_free(list);
}

/// Set the counter to zero.
///
/// For performance reasons, this function does not clear memory.
/// Params: list = List instance.
void adbg_list_clear(list_t *list) {
	if (list == null)
		return;
	list.count = 0;
}
unittest {
	// new
	list_t *list = adbg_list_new(int.sizeof, 4);
	
	adbg_list_clear(list);
	assert(list.count == 0);
	
	adbg_list_free(list);
}

/// Remove an item from the list by its index.
/// Params:
/// 	list = List instance.
/// 	index = Index.
/// Returns: List instance, in case its memory location changes.
list_t* adbg_list_remove_at(list_t *list, size_t index) {
	if (list == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	assert(list.buffer);
	assert(list.itemsize);
	
	if (list.count == 0) // Nothing to remove
		return list;
	if (index >= list.count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	// Decrement entry count
	list.count--;
	
	// Move items if necessary
	// This means if there are items higher in the buffer than the index
	// Since count was decreased, it is a soft guarantee that we won't run it over
	if (index < list.count) { // 0 < 0 -> false
		void *buffer = list.buffer + (list.itemsize * index);
		for (size_t i = index; i < list.count; ++i) {
			memcpy(buffer, buffer + list.itemsize, list.itemsize);
			buffer += list.itemsize;
		}
	}
	
	return list;
}
unittest {
	// new
	list_t *list = adbg_list_new(int.sizeof, 4);
	
	int a = 5; list = adbg_list_add(list, &a); // 0
	a = 10;    list = adbg_list_add(list, &a); // 1
	a = 15;    list = adbg_list_add(list, &a); // 2
	a = 20;    list = adbg_list_add(list, &a); // 3
	
	list = adbg_list_remove_at(list, 3);
	
	assert(adbg_list_get(list, 3) == null); // No longer available
	assert(adbg_list_get(list, 2));         // Still available
	
	list = adbg_list_remove_at(list, 0);
	
	assert(adbg_list_get(list, 2) == null); // No longer available
	assert(adbg_list_get(list, 1));         // Still available
	
	// So far, values 20 and 5 have been removed,
	// so only 10 and 15 should be here at positions 0 and 1
	assert(*cast(int*)adbg_list_get(list, 0) == 10);
	assert(*cast(int*)adbg_list_get(list, 1) == 15);
	
	adbg_list_free(list);
}

/// Free the list.
/// Params: list = List instance.
void adbg_list_free(list_t *list) {
	if (list == null)
		return;
	free(list);
}