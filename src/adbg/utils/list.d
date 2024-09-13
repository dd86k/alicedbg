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
	void *buffer;
}

list_t* adbg_list_new(size_t itemsize, size_t capacity) {
	size_t isize = itemsize * capacity; // initial size
	list_t *list = cast(list_t*)malloc(list_t.sizeof + isize);
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

/// Add an item to the list.
///
/// Item data is copied into the list.
///
/// If the returned list pointer is null, no content was changed, but an error occured.
/// You are free to either close the list or continue with the current, unchanged list.
/// Params:
/// 	list = List instance.
/// 	item = Item.
/// Returns: List instance pointer.
list_t* adbg_list_add(list_t *list, void *item) {
	if (list == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	// Increase capacity
	if (list.count >= list.capacity) {
		size_t newcapacity = list.capacity << 1; // double capacity
		list = cast(list_t*)realloc(list, list_t.sizeof + (list.itemsize * newcapacity));
		if (list == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		
		// Assuming realloc(3) copied data to new region if address changes...
		// Only need to readjust buffer pointer
		list.capacity = newcapacity;
		list.buffer = cast(void*)list + list_t.sizeof;
	}
	
	// Copy item into buffer
	void *loc = list.buffer + (list.itemsize * list.count++);
	memcpy(loc, item, list.itemsize);
	return list;
}

void* adbg_list_get(list_t *list, size_t index) {
	if (list == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (index >= list.count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	return list.buffer + (list.itemsize * index);
}

void adbg_list_free(list_t *list) {
	if (list == null)
		return;
	free(list);
}

unittest {
	list_t *list = adbg_list_new(int.sizeof, 4);
	assert(list);
	assert(list.capacity == 4);
	assert(list.count == 0);
	assert(list.itemsize == int.sizeof);
	
	assert(adbg_list_get(list, 0) == null);
	
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
	
	assert(adbg_list_get(list, 1));
	assert(adbg_list_get(list, 2));
	assert(adbg_list_get(list, 3));
	
	assert(*cast(int*)adbg_list_get(list, 1) == 25);
	assert(*cast(int*)adbg_list_get(list, 2) == 25);
	assert(*cast(int*)adbg_list_get(list, 3) == 25);
	
	id = 333;
	assert((list = adbg_list_add(list, &id)) != null); // count=5
	assert((list = adbg_list_add(list, &id)) != null); // count=6
	assert((list = adbg_list_add(list, &id)) != null); // count=7
	
	assert(list.capacity >= 8);
	assert(list.count == 7);
	assert(list.itemsize == int.sizeof);
	
	assert(adbg_list_get(list, 4));
	assert(adbg_list_get(list, 5));
	assert(adbg_list_get(list, 6));
	
	assert(*cast(int*)adbg_list_get(list, 4) == 333);
	assert(*cast(int*)adbg_list_get(list, 5) == 333);
	assert(*cast(int*)adbg_list_get(list, 6) == 333);
}