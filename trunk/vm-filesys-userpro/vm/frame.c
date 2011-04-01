#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "vm/page.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include <stdio.h>

void * swap_frame (void);
bool frame_less (const struct hash_elem *, const struct hash_elem *,void * UNUSED);
unsigned frame_hash (const struct hash_elem *, void * UNUSED);
struct frame * frame_lookup (const void *);

struct frame {
	//pointer to the user memory page in the frame
	uint8_t *addr;
	struct hash_elem hash_elem;
	struct thread * thread;
	bool lock;
};

/* Returns a hash value for frame p. */
unsigned
frame_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct frame *p = hash_entry (p_, struct frame, hash_elem);
  return hash_bytes (&p->addr, sizeof p->addr);
}

/* Returns true if frame a precedes page b. */
bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct frame *a = hash_entry (a_, struct frame, hash_elem);
  const struct frame *b = hash_entry (b_, struct frame, hash_elem);

  return a->addr < b->addr;
}

//hash table for the frames	
struct hash frame_table;

void init_frame () {
	hash_init (&frame_table, frame_hash, frame_less, NULL);
	lock_init(&frame_lock);
}

/* Returns the frame containing the given address,
   or a null pointer if no such page exists. */
struct frame *
frame_lookup (const void *address)
{
  struct frame p;
  struct hash_elem *e;

  p.addr = (void *)address;
  
  e = hash_find (&frame_table, &p.hash_elem);
  
  return e != NULL ? hash_entry (e, struct frame, hash_elem) : NULL;
}


//this functions gets a new frame and returns the corresponding memory page
uint8_t * get_frame (void ) {
	//frame for the table
	struct frame * f = NULL;
	//try to get a page
	//lock the frame table
	lock_acquire(&frame_lock);
	uint8_t * kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	
	//check if hash table is full
	if (kpage == NULL) {
		//now we have to evict a page
		kpage = swap_frame();
	} 
	
	//create a new frame otherwise
	f = (struct frame *) malloc (sizeof(struct frame));

	//in case there was a problem with getting a page
	ASSERT(kpage);
	
	//save the threads id and the physical address in the new frame struct
	f->thread = thread_current();
	f->addr = kpage;
	f->lock = false;

	hash_insert (&frame_table, &f->hash_elem);

	//release the lock for the frame table
	lock_release(&frame_lock);

	return kpage;
}

//for the eviction policy
void * swap_frame (void) {
	//look through the frames in the table to find one to swap with the clock algorithm
	struct hash_iterator i;

	void * frame_swap = NULL;

	while (frame_swap == NULL) {
	hash_first (&i, &frame_table);
	while (hash_next (&i)) {
    		struct frame *f = hash_entry (hash_cur (&i), struct frame, hash_elem);
		void * vaddr = (void *)get_vaddr_page(f->addr,f->thread);
		//page is dirty then swap it otherwise set it to 0 and go for the next one
		//true case
		if (f->lock == false) {
			if (pagedir_is_accessed (f->thread->pagedir, vaddr) ) {
				//set dirty bit to false
				pagedir_set_accessed (f->thread->pagedir, vaddr, false);
			} else {
				//page is dirty so we can swap it
				page_swap_in(vaddr,f->thread);
				frame_remove(f->addr);
				frame_swap = palloc_get_page (PAL_USER | PAL_ZERO); 
				break;
			}
		}
  	}
	}

	ASSERT(frame_swap);
	return frame_swap;
}

//remove an element from the frame table
void frame_remove(void * kaddr) {
	//find frame in the hash
	struct frame * rem = frame_lookup(kaddr);
	//delete it
	hash_delete(&frame_table,&rem->hash_elem);
	//free its memory
	palloc_free_page (rem->addr);
	free(rem);
	
}

//lock a frame so it can't be evicted
void frame_lockdown (void * kaddr) {
	lock_acquire(&frame_lock);
	struct frame * f = frame_lookup(kaddr);
	lock_release(&frame_lock);
	f->lock = true;

}
//unlock a frame 
void frame_unlock (void * kaddr) {
	lock_acquire(&frame_lock);
	struct frame * f = frame_lookup(kaddr);
	lock_release(&frame_lock);
	f->lock = true;

}

