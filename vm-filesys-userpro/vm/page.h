#ifndef VM_PAGE_H
#define VM_PAGE_H

//to identify where the page should be
enum page_type
  {
	PAGE_FRAME,
	PAGE_SWAP,
	PAGE_MMAP
};

struct page {
	//pointer to the user memory page in the frame
	void * vaddr;
	// we use paddr to save the physical address or the SWAP slot
	void * paddr;
	struct hash_elem hash_elem;
	bool writable;
	enum page_type type;
 	//this is for memory mapped files
	int mapid;
	off_t readbytes;
	off_t offset;
};

bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
struct page *page_lookup (const void *address, struct thread *);
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
void page_add (void * , void * ,bool,enum page_type); 
const char * page_type_name (enum page_type type);
void * get_vaddr_page (void *,struct thread *);

void page_swap_in (void * ,struct thread *);
void page_swap_out (void * );
void page_clean (void);
void page_add_mmap (void * , void * ,bool ,int ,off_t,off_t);
void page_remove (void *);

#endif /* vm/page.h */
