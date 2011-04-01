#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "vm/frame.h"
#include "vm/page.h"


static void syscall_handler (struct intr_frame *);

//loads the value from the stack with esp,offset
void * value_stack (void * , int);
int * value_stack_int (void * , int );

//helper functions for the syscall handler
void exit (struct intr_frame *);
void write (struct intr_frame *);
void read (struct intr_frame *);
void open (struct intr_frame *);
void create (struct intr_frame *);
void filesize (struct intr_frame *);
void close (struct intr_frame *);
void tell (struct intr_frame *);
void seek (struct intr_frame *);
void halt (void );
void remove (struct intr_frame *);
void exec (struct intr_frame *);
void wait (struct intr_frame *);
void exit_mythread (int );
void mmap (struct intr_frame *f);
void munmap (struct intr_frame *f);


void exit_mythread (int status) {
	
	printf("%s: exit(%d)\n",thread_current()->name,status);
	thread_exit();	
}

/* this function reads out a value from esp +offset and checks if it is a valid pointer */
void * value_stack (void * esp, int offset) {
	void * ptr =  (void *)(esp + offset);
	void * result;	 

	if (is_user_vaddr(*(void **)ptr) && *(void **)ptr != NULL) {
		result = page_lookup (*(void **) ptr,thread_current());
		if (result != NULL) return ptr;
	}
	exit_mythread(-1);
	return NULL;

}

/* this function reads out a value from esp +offset and checks if it is a valid pointer */
int * value_stack_int (void * esp, int offset) {
	void * ptr =  (void *)(esp + offset);
	void * result;	

	if (is_user_vaddr((int *)ptr) && (int *)ptr != NULL ) {
		result = page_lookup((int *)ptr, thread_current());
		if (result != NULL) return (int *) ptr;
	}
	exit_mythread(-1);
	return NULL;
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void exit (struct intr_frame *f) {
	
	int status = *value_stack_int(f->esp,4);
	f->eax = status;

	lock_acquire(&child_lock);

	if (thread_current()->me != NULL)
		thread_current()->me->returnval = status;

	lock_release(&child_lock);

	exit_mythread(status);
}

void create (struct intr_frame *f) {
	
	char * filename = *(char **)value_stack(f->esp,4);
	unsigned size = *value_stack_int(f->esp,8);
	bool success = false;

	if (strnlen(filename,32) == 0) {
		f->eax = success;
		return;
	}

	success = filesys_create (filename, size,FILE_FILE);

	f->eax = success;
}


void open (struct intr_frame *f) {

	const char * filename = *(char **)value_stack(f->esp,4);
	int fd;

	struct file * file = filesys_open (filename);
  	if (file == NULL) {
		fd = -1;
  	} else {
		//if not a directory
		if(!file_direct(file)) { 
			fd = add_file(file);
		} else {
			//if a directory open it and save it in the pointer in the fd table so we can open it again
			struct inode * myinode = file_get_inode (file);
			struct dir * mydir = dir_open (myinode);		
			fd = add_filemmap(file,mydir);
		}
	}
	f->eax = fd;
}

void write (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);
	const void * buffer = *(void **)value_stack(f->esp,8);
	unsigned size = *value_stack_int(f->esp,12);

	if (fd == 1) {
		//break up the string in multilpe outputs if it is bigger than 256
		int split = 256;
		int i = size / split;
		for (;i>0;i--) { 
			putbuf(buffer,split);
			buffer += split;
		}
		putbuf(buffer,size % split);
	}	
	else {
		unsigned fl_length = 0;

		if (fd == 0 || fd < 0 ) {
			f->eax = 0 ;
			return ;
		}

		struct filed * filed = find_file(fd);
		if (filed == NULL) { 
			f->eax = 0 ;
			return ;
		}	

		struct file * writeto = find_file(fd)->file;

		//check if it is a directory
		if ( file_direct(writeto) ) {
			f->eax = -1;
			return;
		}
		
		fl_length = file_length (writeto);
		//check if the actual file length is smaller than size
		//if(fl_length < size) size = fl_length;

		void * npage = pg_round_down (buffer);
		unsigned readsize = (unsigned) (npage + PGSIZE - buffer);
			
		bool read = true;
		unsigned bytes_read_total=0,bytes_read=0;
		
		//the new pagewise writing
		while(read){
			struct page * p = page_lookup(buffer,thread_current());
			//if the page is not her, we have to swap it in
			if (pagedir_get_page(thread_current()->pagedir,p->vaddr) == NULL) {
				page_swap_out(p->vaddr);
			}

			frame_lockdown(p->paddr);

			//everything fits in with one read
			if(size <= readsize){
				bytes_read = file_write (writeto, buffer, size);
				read = false;
			} else {
			//now we have tos plit it up
				bytes_read= file_write (writeto, buffer, readsize);
				//couldn't read all the bytes
				if(bytes_read != readsize) read = false;
				size -= bytes_read;
				
				if(size == 0) read = false;
				else {
					buffer += bytes_read;
					if (size >= PGSIZE) readsize = PGSIZE;
					else readsize = size;
				}
			}	
			//unlock the frame again
			frame_unlock(p->paddr);
			bytes_read_total+=bytes_read;
		}
		size = bytes_read_total;	
	}

	//set eax to return value
	f->eax = size;
}

void read (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);
	void * buffer = *(void **)value_stack(f->esp,8);
	unsigned size = *value_stack_int(f->esp,12);
	int ret_val = 1;

	if (fd == 0) {
		//read from stdin
		ret_val = input_getc();	
	}	
	else {
		if (fd == 1 || fd < 0) {
			f->eax = 0;
			return ;
		}
		
		struct filed * filed = find_file(fd);
  	  	
		if (filed == NULL) ret_val = 0;
		else { 
			struct file * readfrom = find_file(fd)->file;

			void * npage = pg_round_down (buffer);
			unsigned readsize = (unsigned) (npage + PGSIZE - buffer);

			bool read = true;
			unsigned bytes_read_total=0,bytes_read=0;
			//the new pagewise reading
			while(read){
				struct page * p = page_lookup(buffer,thread_current());
				//if the page is not her, we have to swap it in
				if (pagedir_get_page(thread_current()->pagedir,p->vaddr) == NULL) {
					page_swap_out(p->vaddr);
				}

				if(!p->writable) exit_mythread(-1);

				frame_lockdown(p->paddr);

				//everything fits in with one read
				if(size <= readsize){
					bytes_read = file_read(readfrom, buffer, size);
					read = false;
				} else {
					//now we have tos plit it up
					bytes_read= file_read(readfrom, buffer, readsize);

					//couldn't read all the bytes
					if(bytes_read != readsize) read = false;
					size -= bytes_read;
				
					if(size == 0) read = false;
					else {
						buffer += bytes_read;
						if (size >= PGSIZE) readsize = PGSIZE;
						else readsize = size;
					}
				}		
				//unlock the frame again
				frame_unlock(p->paddr);
				bytes_read_total+=bytes_read;
			}
			ret_val = bytes_read_total;
		 }
	}

	//set eax to return value
	f->eax = ret_val;
}

void filesize (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);
	int size = 0;	

  	struct file * filename = find_file(fd)->file;
	//check the pointer and write in the file
	if (filename != NULL) 
		size = file_length (filename);
	//set eax to return value
	f->eax = size;
}

/* not nice fix it later */
void close (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);

  	struct filed * filename = find_file(fd);
	//check the pointer and close the file
	if (filename != NULL) {
		file_close (filename->file);
		//reset the position in the file table
		list_remove(&filename->filed);
		free(filename);
	} else 
		exit_mythread(-1);
	
}

void seek (struct intr_frame *f) {
	
	int fd = *value_stack_int(f->esp,4);
	unsigned position = *value_stack_int(f->esp,8);

  	struct file * filename = find_file(fd)->file;
	//check the filename and set the byte offset
	if (filename != NULL) 
		file_seek (filename,position);

}

void tell (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);
	unsigned byte=0;

  	struct file * filename = find_file(fd)->file;
	//check the filename and read out the byte offset
	if (filename != NULL) 
		byte = file_tell (filename);

	//set eax to return value
	f->eax = byte;

}

void halt () {

	shutdown_power_off();
}

void remove (struct intr_frame *f) {

	const char * filename = *(char **)value_stack(f->esp,4);
	bool success = false;

	//removes the file
	success = filesys_remove (filename);

	//set eax to return value
	f->eax = success;

}

void exec (struct intr_frame *f) {

	const char * cmd_line = *(char **)value_stack(f->esp,4);
	pid_t pid;

	lock_acquire(&child_lock);

	pid = process_execute(cmd_line);

	cond_wait(&cond_exec,&child_lock);
	lock_release(&child_lock);

	struct list_elem *e;
  	struct child * child = NULL;
  	//get child with pid
  	for (e = list_begin (&thread_current()->children); e != list_end (&thread_current()->children); e = list_next (e)) {
		struct child * temp = list_entry (e, struct child, parentelem);
		if (temp->pid == pid) {
			child = temp;
			break;
		}
	}

	if (child == NULL) {
		f->eax=-1;
		return;
	}
	
	pid = child->pid;

	f->eax=pid;

}

void wait (struct intr_frame *f) {

	pid_t pid = *value_stack_int(f->esp,4);
	//use process wait now
	f->eax = process_wait(pid);

}

void mmap (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);
	//void * addr = *(void **)value_stack(f->esp,8);
	void * addr = *(void **)(f->esp + 8);

	if (!is_user_vaddr(addr) ) exit_mythread(-1); 

	//fd 0 and 1 are not allowed ... MISSING PAGE ALIGN
	if(fd == 1 || fd == 0 || addr == 0 || (unsigned int)addr % PGSIZE != 0 ) { 
		f->eax = -1;
		return ;
	}

	struct filed * file = find_file(fd);
	if ( file == NULL ) {
		exit_mythread(-1);
	}

	struct file * mfile = file_reopen(file->file);

	//get the file from the threads file table
	if ( mfile == NULL ) {
		exit_mythread(-1);
	}

	int size = file_length(mfile);
	//get the number of pages we need for the file
	int numberpages = size/PGSIZE;

	if (file_length(mfile) % PGSIZE != 0) numberpages += 1;

	//check if the virtual memory pages are free
	int i;
	for (i = 0; i < numberpages;i++) {
		if (page_lookup(addr + i*PGSIZE, thread_current()) != NULL) {
			file_close(mfile);
			f->eax=-1;
			return ;
		}
	}

	//add to filetable
	fd = add_filemmap(mfile,addr);

	off_t length = 0;
	//add the pages to the supplemental page table
	for (i = 0; i < numberpages; i++) {
		if (size >= PGSIZE) length = PGSIZE;
		else length = size;
		page_add_mmap (addr + i*PGSIZE, (off_t *) (i*PGSIZE),true,fd,length,i*PGSIZE);
		size -= length;
	}

	f->eax = fd;

}

void munmap (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);
	
	struct filed * filed = find_file(fd);
	//get the number of pages we need for the file
	int numberpages = file_length(filed->file)/PGSIZE;
	if (file_length(filed->file) % PGSIZE != 0) numberpages += 1;
	int i;
	for (i = 0;i < numberpages; i++) {
		//remove the pages from the supplemental page table
		page_remove (filed->vaddr + i * PGSIZE);
	}

	file_close(filed->file);
	list_remove(&filed->filed);
	free(filed);

}

void chdir (struct intr_frame *f) {
	
	const char * dirname = *(char **)value_stack(f->esp,4);

	//if empty or root return
	if(strlen(dirname) ==  0 || strcmp( dirname, "/")) f->eax = 0;

	/* CLOSE FILE ? */
	struct file * file  = filesys_open(dirname);

	if ( file == NULL ) {
		f->eax = 0;
		return;
	}	
	struct inode * myinode = file_get_inode (file);

	enum file_type type = inode_type (myinode);

	//if the file is a dir open it and set pwd to it
	if(type == FILE_DIR) {
	 	f->eax = 1;
		dir_close(thread_current()->pwd);
		thread_current()->pwd = dir_open(inode_reopen(myinode));
		
	}
	else f->eax = 0;

	file_close(file);

}

void mkdir (struct intr_frame *f) {

	const char * dirname = *(char **)value_stack(f->esp,4);

	//if empty or root return
	if(strlen(dirname) ==  0 || strcmp( dirname, "/") == 0) { 
		f->eax = 0;
		return;
	}

	bool success = filesys_create(dirname, 0,FILE_DIR);
	
	if ( success ) f->eax = 1;
	else f->eax = 0;
	
}

void readdir (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);
	char * name = *(char **)value_stack(f->esp,8);

	//get the fd and check if fd is a directory
	struct filed * filed = find_file(fd);

	if ( filed == NULL ) {
		exit_mythread(-1);
	}
	
	struct file * file = filed->file;

	if ( file == NULL ) {
		exit_mythread(-1);
	}

	//check if it is a directory
	if ( !file_direct(file) ) {
		f->eax = 0;
		return;
	}
	//now we can start
	struct dir * mydir = (struct dir *)filed->vaddr;
	bool success = dir_readdir (mydir, name);

	if (success) f->eax = 1;
	else f->eax = 0;


}

void isdir (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);
	//get filed struct from open files
	struct filed * filed = find_file(fd);

	if ( filed == NULL ) {
		exit_mythread(-1);
	}
	
	struct file * file = filed->file;

	if ( file == NULL ) {
		exit_mythread(-1);
	}

	//check if it is a directory
	if ( file_direct(file) ) f->eax = 1;
	else f->eax = 0;

}

void inumber (struct intr_frame *f) {

	int fd = *value_stack_int(f->esp,4);
	//get filed struct from open files
	struct filed * filed = find_file(fd);

	if ( filed == NULL ) {
		exit_mythread(-1);
	}
	
	struct file * file = filed->file;

	if ( file == NULL ) {
		exit_mythread(-1);
	}

	struct inode * myinode = file_get_inode (file);

	f->eax = inode_id (myinode);

}

static void

syscall_handler (struct intr_frame *f UNUSED) 
{
  //get the interrupt number
  int int_num = *value_stack_int(f->esp,0);

  switch (int_num) {
	case SYS_HALT:                   /* Halt the operating system. */
		halt();    	
	case SYS_EXIT:                   /* Terminate this process and gives him the return value. */
		exit(f);
		break;
    	case SYS_EXEC:                   /* Start another process. */
		exec(f);
	    	break;
	case SYS_WAIT:                   /* Wait for a child process to die. */
		wait(f);    	
		break;
	case SYS_CREATE: 		 /* Create a file. */
		create(f); 
		break;    
    	case SYS_REMOVE:                 /* Delete a file. */
		remove(f);    	
		break;
	case SYS_OPEN:			 /* Open a file. */
		open(f); 
		break;         
    	case SYS_FILESIZE:               /* Obtain a file's size. */
		filesize(f);
		break;    	
	case SYS_READ: 	                 /* Read from a file. */
		read(f);
		break;
    	case SYS_WRITE: 	         /* Write to a file. */
		write(f); 
		break;
    	case SYS_SEEK:                   /* Change position in a file. */
		seek(f);    	
		break;
	case SYS_TELL:                   /* Report current position in a file. */
		tell(f);
		break;    	
	case SYS_CLOSE:   	          /* Close a file. */
		close(f);	
		break;
	case SYS_MMAP:                   /* Map a file into memory. */
   		mmap(f);
		break;
    	case SYS_MUNMAP:                 /* Remove a memory mapping. */
		munmap(f);
		break;
	case SYS_CHDIR:                  /* Change the current directory. */
		chdir(f);
		break;
	case SYS_MKDIR:                  /* Create a directory. */
		mkdir(f);
		break;
	case SYS_READDIR:                /* Reads a directory entry. */
		readdir(f);
		break;
	case SYS_ISDIR:                  /* Tests if a fd represents a directory. */
		isdir(f);
		break;
	case SYS_INUMBER:                 /* Returns the inode number for a fd. */
		inumber(f);
		break;
	}	
}


