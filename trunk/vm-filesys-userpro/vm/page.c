#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "lib/kernel/hash.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <stdio.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <string.h>
#include "threads/synch.h"

void page_destroy (struct hash_elem *e, void *aux UNUSED);

//returns the name where the page is located
const char *
page_type_name (enum page_type type)
{
  static const char *page_type_names[3] =
    {
      "frame",
      "swap",
      "MMAP"
    };

  ASSERT (type < 3);
  return page_type_names[type];
}


/* Returns a hash value for frame p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->vaddr, sizeof p->vaddr);
}

/* Returns true if frame a precedes page b. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->vaddr < b->vaddr;
}

/* Returns the frame containing the given address,
   or a null pointer if no such page exists. */
struct page *
page_lookup (const void *address, struct thread * t)
{
  struct page p;
  struct hash_elem *e;
  //make sure the address is aligned
  p.vaddr = (void *) ((unsigned int)address - (unsigned int)address % PGSIZE);
  e = hash_find (t->page_table, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}
//add a page to the page table
void page_add (void * vaddr, void * paddr,bool writable, enum page_type type) {

	//create a new page
	struct page * p = (struct page *) malloc (sizeof(struct page));
	//in case there is no memory left in the kernel or malloc failed otherwise
	if(p == NULL) thread_exit();
	
	p->vaddr = vaddr;
	p->writable = writable;
	p->type = type;
	p->paddr = paddr;
	//use mapid as an identifier
	p->mapid = -1;

	lock_acquire(&thread_current()->page_lock);
	hash_insert (thread_current()->page_table, &p->hash_elem);
	lock_release(&thread_current()->page_lock);
}
//add a page for the mmap to the page table
void page_add_mmap (void * vaddr, void * paddr,bool writable,int mapid, off_t read, off_t offset) {

	//create a new page
	struct page * p = (struct page *) malloc (sizeof(struct page));
	//in case there is no memory left in the kernel or malloc failed otherwise
	if(p == NULL) thread_exit();
	
	p->vaddr = vaddr;
	p->writable = writable;
	p->type = PAGE_MMAP;
	p->paddr = paddr;
	p->mapid = mapid;
	p->offset = offset;
	p->readbytes = read;

	lock_acquire(&thread_current()->page_lock);
	hash_insert (thread_current()->page_table, &p->hash_elem);
	lock_release(&thread_current()->page_lock);
}


//this function will swap a page from memory to frame
//this function just gets called from the running thread
void page_swap_out (void * vaddr) {

	struct page *cur;
	//get the page
	cur = page_lookup(vaddr,thread_current());
	//look what kind of page it is
	switch (cur->type) {

	case (PAGE_FRAME):	//trigger a kernel panic this should not happen
		PANIC ("Userpage should be in frame table\n");
	case (PAGE_SWAP):	/* page is in swap so we have to pull it out and save it in a frame */
		{
		//get a free frame from the frame table		
		void * frame = (void *)get_frame();
		lock_acquire(&frame_lock);
		//swap the frame table and swap slot
		get_swap ((size_t)cur->paddr, frame);
		//set the variables in the page table
		cur->paddr = frame;
		cur->type=PAGE_FRAME;
		//reset the page table to the new physical address
		bool check = pagedir_set_page (thread_current()->pagedir, cur->vaddr, cur->paddr, cur->writable);
		ASSERT(check);
		lock_release(&frame_lock);
		}
		break;
	case (PAGE_MMAP): //load a page from a mmap file to the frame
		{
		void * kpage = (void *)get_frame();
		lock_acquire(&frame_lock);
	
		off_t offset = cur->offset;
		off_t readbytes = cur->readbytes;

		struct file * file = find_file(cur->mapid)->file;

		if (file == NULL) printf("problem\n");

		//set the correct offset that is hidden in paddr
		file_seek (file, offset);

		int val = 0;
      		if (readbytes > 0) val = file_read (file, kpage,readbytes);
       
		//put in the newly allocated
		if (pagedir_set_page (thread_current()->pagedir, cur->vaddr, kpage, cur->writable) == false) printf("couldnt put in page\n");
		//set type to frame since it is loaded now	
		cur->paddr = (void *)kpage;			
		cur->type = PAGE_FRAME;
		//reset the dirty bit of the kpage since it wasn't really changed anything in the page
		pagedir_set_dirty (thread_current()->pagedir, kpage, false);

		lock_release(&frame_lock);
		}
		break;
	default:
		break;

	}
	//lock_release(&thread_current()->page_lock);
}

//this function will swap a page from the frame table to the swap 
void page_swap_in (void * vaddr, struct thread * t) {

	struct page *cur;

	cur = page_lookup(vaddr,t);

	switch (cur->type) {

		case (PAGE_FRAME):
			{
			if(cur->mapid < 0) {
				cur->paddr = (size_t *)add_swap(cur->paddr);
				cur->type=PAGE_SWAP;
			} else {
				//we have a memory mapped file
				off_t offset = cur->offset;
				off_t writebytes = cur->readbytes;

				if (pagedir_is_dirty (t->pagedir, cur->vaddr) || pagedir_is_dirty (t->pagedir, cur->paddr)) {
					//the file is a zero page from exec 
					if(cur->mapid == 2) {
						cur->paddr = (size_t *)add_swap(cur->paddr);
						cur->type=PAGE_SWAP;
						break;
					}

					struct file * file = find_file(cur->mapid)->file;
		
					if (file == NULL) printf("problem\n");

					//set the correct offset that is hidden in paddr
					file_seek (file, offset);

      					if (file_write (file, cur->paddr, writebytes) != writebytes) {
						PANIC("Error writing to file");
					}
				} 	
				cur->type = PAGE_MMAP;
			}
			}	
			break;
		case (PAGE_SWAP):	/* shouldn't happen */
			PANIC ("Page is already in swap\n");
		default:
			break;
		}
		pagedir_clear_page (t->pagedir, cur->vaddr);
}

//finds the virtual memory address for a physical one
//needed for page eviction in frame.c
void * get_vaddr_page (void * kpage, struct thread * t) {

	//look through the frames in the table beginning at the end
	struct hash_iterator i;

	void * result = NULL;

	lock_acquire(&t->page_lock);

	hash_first (&i, t->page_table);
	while (hash_next (&i)) {
    		struct page *p = hash_entry (hash_cur (&i), struct page, hash_elem);
		if (p->type == PAGE_FRAME && p->paddr == kpage) { 
			result = p->vaddr;
			break;
		}
  	}
	//make sure result is not NULL
	ASSERT(result);

	lock_release(&t->page_lock);
	
	return result;
}

//I use this function on the hash_destroy function
void page_destroy (struct hash_elem *e, void *aux UNUSED) {

	struct page *p = hash_entry (e, struct page, hash_elem);
	free(p);
}

//clears all the memory for the page entries
void page_clean (void) {

	//look through the frames in the table beginning at the end
	struct hash_iterator i;

	lock_acquire(&frame_lock);

	hash_first (&i, thread_current()->page_table);
	while (hash_next (&i)) {
    		struct page *p = hash_entry (hash_cur (&i), struct page, hash_elem);
		//look where the pages are and free the ressources
		switch(p->type) {
			case (PAGE_FRAME):
				if (p->mapid == -1) {
					frame_remove(p->paddr);
					pagedir_clear_page (thread_current()->pagedir, p->vaddr);
				} else {
					void * pad = p->paddr;
					//we have a memory mapped file
				
					if ((p->mapid > 2) && ( pagedir_is_dirty (thread_current()->pagedir, p->vaddr) || pagedir_is_dirty (thread_current()->pagedir, p->paddr)) ) {
						off_t offset = p->offset;
						off_t writebytes = p->readbytes;

						struct file * file = find_file(p->mapid)->file;
		
						if (file == NULL) printf("problem\n");

						//set the correct offset that is hidden in paddr
						file_seek (file, offset);
	
      						if (file_write (file, p->paddr, writebytes) != writebytes) {
							PANIC("Error writing to file");
						}
					} 		
					pagedir_clear_page (thread_current()->pagedir, p->vaddr);
					frame_remove(pad);
				}
				break;
			case (PAGE_SWAP):
				swap_remove((size_t)p->paddr);
				pagedir_clear_page (thread_current()->pagedir, p->vaddr);
				break;
			default:
				break;
		}
  	}
	hash_destroy(thread_current()->page_table,page_destroy);
	//free hash
	free(thread_current()->page_table);
	lock_release(&frame_lock);
}

//remove a single page
void page_remove (void * vaddr) {

	struct page *cur;

	cur = page_lookup(vaddr,thread_current());

	switch(cur->type) {
		case(PAGE_FRAME):
			{
			lock_acquire(&frame_lock);
			if (cur->mapid == -1) {
				frame_remove(cur->paddr);
				pagedir_clear_page (thread_current()->pagedir, cur->vaddr);
			} else {
				void * pad = cur->paddr;
				if ((cur->mapid > 2) && (pagedir_is_dirty (thread_current()->pagedir, cur->vaddr) || pagedir_is_dirty (thread_current()->pagedir, cur->paddr) ) ) {
					off_t offset = cur->offset;
					off_t writebytes = cur->readbytes;

					struct file * file = find_file(cur->mapid)->file;
		
					if (file == NULL) printf("problem\n");

					//set the correct offset that is hidden in paddr
					file_seek (file, offset);

      					if (file_write (file, cur->paddr, writebytes) != writebytes) {
						PANIC("Error writing to file");
					}
				} 
				frame_remove(pad);
				pagedir_clear_page (thread_current()->pagedir, cur->vaddr);
			}

			lock_acquire(&thread_current()->page_lock);		
			hash_delete(thread_current()->page_table,&cur->hash_elem);
			lock_release(&thread_current()->page_lock);
			//free its memory
			free(cur);
			lock_release(&frame_lock);
			}
			break;
		case(PAGE_MMAP):
			hash_delete(thread_current()->page_table,&cur->hash_elem);
			//free its memory
			free(cur);
			break;
		default:
			break;
	}
}


