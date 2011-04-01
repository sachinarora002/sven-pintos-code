#include "vm/swap.h"
#include "devices/block.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "lib/kernel/hash.h"
#include <stdio.h>
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"

int SECPP = (PGSIZE/BLOCK_SECTOR_SIZE);

struct lock swap_lock;

struct block * swap;
struct bitmap * swap_table;

void init_swap () {

	lock_init(&swap_lock);

	swap = block_get_role(BLOCK_SWAP);
	//number of sectors each sector is 512kb so we need 8 sectors for one page
	uint32_t size = block_size (swap);

	//create a bitmap that represents the swap table, each entry refers to consecutive blocks that represent one page
	swap_table = bitmap_create (size/SECPP);
}

//adds a page to swap space, gets called with the physical memory position
size_t add_swap (void * addr) {
	//init swap if necessary
	if (swap == NULL)   //init the swap table
  		init_swap ();

	//lock the swap table
	lock_acquire(&swap_lock);

	//find a free entry in the bitmap table
	size_t free = bitmap_scan (swap_table, 0, 1, false);
	//if the swap table is full panic the kernel
	if (free == BITMAP_ERROR) PANIC ("Swaptable is full\n");

	int i;
	//get frame and the memory position and write it to swap
	for (i = 0; i< SECPP; i++)
		//write block to swap, free * SECPP is the correct block position and + i because a page has a different size, same for addr
		block_write (swap, free * SECPP + i, addr + BLOCK_SECTOR_SIZE * i);

	//set the corresponding entry in the swap_table to true
	bitmap_set (swap_table, free, true);

	//release the lock for the swap table
	lock_release(&swap_lock);

	return free;

}

//get a page from the swap table and save it to a memory position
void get_swap (size_t idx, void * addr) {

	//check if bitmap is set correctly
	ASSERT(bitmap_test (swap_table,idx));
	
	int i;
	//get frame and the memory position and write it to swap
	for (i = 0; i< SECPP; i++) 
		//read the value from swap to addr
		block_read (swap, idx * SECPP + i, addr + BLOCK_SECTOR_SIZE * i);
	
	//lock the swap table
	lock_acquire(&swap_lock);

	//remove the swap entry at position idx
	bitmap_set (swap_table, idx, false);

	//release the lock for the swap table
	lock_release(&swap_lock);
}

void swap_remove(size_t idx) {

	//lock the swap table
	lock_acquire(&swap_lock);
	//remove the swap entry at position idx
	bitmap_set (swap_table, idx, false);
	//release the lock for the swap table
	lock_release(&swap_lock);

}


