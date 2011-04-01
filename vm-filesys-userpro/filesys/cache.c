#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "lib/string.h"

#include "threads/thread.h"

#define cache_size 64

void evict_cache (void);
void add_readahead(block_sector_t next);


struct cache_block {
  //block sector on disk
  block_sector_t bid;
  //corresponding kernel page
  void * kpage;
  //fields to check access and if someone wrote to the page
  bool dirty; 
  bool accessed;
  int reader;
  int writer;

};


//how many blocks is one page
extern int SECPP;

//cache array
struct cache_block * cache[cache_size];
//bitmap to identify free entries
struct bitmap * cache_table;

struct lock cache_globallock;

void init_cache () {

	int i,j;

	for (i = 0; i < (cache_size / SECPP); i++) {
		//get a page from kernel memory
		void * kpage = palloc_get_page (PAL_ZERO);
		for (j = 0; j < SECPP; j++) {
			//init the block			
			struct cache_block * c = (struct cache_block *)malloc(sizeof(struct cache_block));

			c->reader = 0;
			c->writer = 0;
			c->bid = -1;
			c->kpage = kpage + BLOCK_SECTOR_SIZE * j;
			c->dirty = false;
			c->accessed = false;

			cache[i * SECPP + j] = c;
		}
	}

	lock_init(&cache_globallock);

	//create a bitmap that represents the free entries in the cache table
	cache_table = bitmap_create (cache_size);
}

//adds a block to cache
size_t add_cache (block_sector_t bid) {

	//lock the swap table
	lock_acquire(&cache_globallock);

	//find a free entry in the bitmap table
	size_t free = bitmap_scan (cache_table, 0, 1, false);
	//if the swap table is full panic the kernel
	if (free == BITMAP_ERROR) { 
		evict_cache ();
		free = bitmap_scan (cache_table, 0, 1, false);
	}

	ASSERT(free != BITMAP_ERROR);
//printf("add cache block %d\n",bid);
	//write block to swap, free * SECPP is the correct block position and + i because a page has a different size, same for addr
	block_read (fs_device, bid, cache[free]->kpage);
	cache[free]->dirty = false;
	cache[free]->accessed = false;
	cache[free]->bid = bid;

	//set the corresponding entry in the swap_table to true
	bitmap_set (cache_table, free, true);

	//release the lock for the swap table
	lock_release(&cache_globallock);

	return free;

}

//write the cache entry back to disk
void writeback_cache (int idx) {

	if(bitmap_test (cache_table,idx) == false) return;
	//register as writer
	cache[idx]->writer++;
	//if cache block is dirty right it back
	if (cache[idx]->dirty == true)
		block_write(fs_device, cache[idx]->bid, cache[idx]->kpage);
	//unregister as writer
	cache[idx]->writer--;

}

//finds the block in the cache table returns -1 if it isn't in cache
//the rw flag is to increase the read ( 0 ) or write ( 1 ) variable in order to avoid race conditions 
//between reading the cache block and reading or writing to it
int find_sector (block_sector_t bid, int rw) {

	lock_acquire(&cache_globallock);

	int i;
	for (i = 0; i < cache_size ; i++) {
		if (cache[i]->bid == bid) {
			if ( rw == 0 ) cache[i]->reader++;
			if ( rw == 1 ) cache[i]->writer++;

			lock_release(&cache_globallock);			
			return i;
		}	
	}

	lock_release(&cache_globallock);

	return -1;
}

//reads from a block which is in cache to a buffer, buffer has to be at the correct position
void read_cache (block_sector_t bid, void * buffer, int offset, int readsize) {

	ASSERT( offset < BLOCK_SECTOR_SIZE);

	int get = find_sector(bid,0);
	
	//if not found load into cache
	if(get == -1) { 
		get = add_cache(bid);
		//ASSERT(get != -1);
		cache[get]->reader++;
		//add_readahead(bid + 1);
	}

	//copy the corresponding section into buffer
	memcpy (buffer,(cache[get]->kpage + offset), readsize);

	cache[get]->accessed = true;

	cache[get]->reader--;

}

//write into cache from buffer, buffer has to be at the correct position
void write_cache (block_sector_t bid, void * buffer, int offset, int writesize) {

	ASSERT( offset < BLOCK_SECTOR_SIZE);

	int get = find_sector(bid,1);
	
	//if not found load into cache
	if(get == -1) { 
		get = add_cache(bid);
		cache[get]->writer++;
	}

	//copy the corresponding section into buffer
	memcpy (cache[get]->kpage + offset, buffer, writesize);
	cache[get]->accessed = true;
	cache[get]->dirty = true;

	cache[get]->writer--;

}

//evicts a block in cache with the second chance algorithm
void evict_cache () {

	int i,idx = - 1;
	while (idx == -1) {
		for ( i = 0; i < cache_size; i++ ) {
			//trying the second chance algo
			if (cache[i]->writer == 0 && cache[i]->reader == 0) {
				if (cache[i]->accessed == false) {
					idx = i;
					writeback_cache(idx);
					bitmap_set (cache_table, idx, false);
					return;
				} else cache[i]->accessed = false;
			}
		}
	}

}

//this function destroys the cache table and writes back all the entries if necessary
void save_cachetable() {

	lock_acquire(&cache_globallock);
	
	int i;
	for (i = 0; i < cache_size; i++){ 	
		writeback_cache(i);
	}

	lock_release(&cache_globallock);
}

//this function destroys the cache table and writes back all the entries if necessary
void add_readahead(block_sector_t next) {

	lock_acquire(&lock_readahead);
	
	struct readahead * r = (struct readahead *) malloc ( sizeof(struct readahead));

	r->bid = next;
	//add to list
	list_push_back (&list_readahead, &r->elem);
	//signal wake up to thread
	cond_signal(&cond_readahead,&lock_readahead);
	lock_release(&lock_readahead);
}
//loads the read ahead block
void do_readahead (block_sector_t next) {

	if (find_sector(next,-1) == -1) {
		add_cache (next);
	}
}





