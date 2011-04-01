#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define INODE_BLOCKS 124
int INODE_LIST = BLOCK_SECTOR_SIZE / sizeof(block_sector_t);

bool inode_allocblocks (int num, block_sector_t * blockarray);
static block_sector_t find_directblock (const struct inode *inode, off_t off);
void inode_resetlength (const struct inode *inode, off_t newlength);

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    unsigned number_blocks;             /* Number of blocks allocated sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t sector[INODE_BLOCKS]; /* for the block numbers */ 
    enum file_type type;
  };

/* On-disk inode list for linked and or double linked lists.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_list
  {
    block_sector_t sector[128];		/* for the block numbers */ 
  };



/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    //struct inode_disk data;             /* Inode content. */
    struct lock inode_lock;		/* a lock for multiple EOF writes and directories */
  };

//grow a file
bool file_grow (const struct inode *inode, off_t pos) {

	off_t number = pos / BLOCK_SECTOR_SIZE + 1;

	//get the number of blocks in the file
	unsigned number_blocks;
  	read_cache (inode->sector, (void *)(&number_blocks), 0, sizeof(unsigned));

	unsigned newblocks = number - number_blocks;
	unsigned loads;
	bool success = false;

	struct inode_disk * temp = calloc (1, sizeof(*temp));
	read_cache (inode->sector, (void *)(temp) , 0, BLOCK_SECTOR_SIZE);
	
	struct inode_list * linked = NULL;
	struct inode_list * dlinked = NULL;
	block_sector_t block;

	//check if we actually might have enough blocks and something is wrong
	if (newblocks == 0) return false;

	//if file end is in single block
	if ( number_blocks < INODE_BLOCKS - 2) {
	
		//allocate until direct blocks are full
		if (number_blocks + newblocks < INODE_BLOCKS - 2) loads = newblocks;
		else loads = (INODE_BLOCKS - 2) -  number_blocks;

		success = inode_allocblocks(loads,&(temp->sector[number_blocks]));

		newblocks -= loads;
		number_blocks += loads;
	}
	//if we are in singled list range and there are more blocks to allocate
	if( newblocks > 0 && number_blocks < (unsigned)(INODE_BLOCKS - 2 + INODE_LIST) ) {

		//allocate a linked list
		linked = calloc(1, sizeof *linked);

		unsigned index = number_blocks - (INODE_BLOCKS - 2);

		//if more to come we need a single linked block
		if ( index ==  0 ) { //get a block for the singled linked list
			//get the correct sector
			success = inode_allocblocks(1,&(temp->sector[INODE_BLOCKS -2]));
		} else {
			read_cache (temp->sector[INODE_BLOCKS -2], (void *)(linked) , 0, BLOCK_SECTOR_SIZE);
		}
			
		//and fill it up
		if ((int)(index + newblocks) > (INODE_LIST) ) loads = INODE_LIST;
		else loads = newblocks;

		success = inode_allocblocks(loads,&(linked->sector[index]) );
		newblocks -= loads;
		number_blocks += loads;

	}
	//if we are in double list range and there are more blocks to allocate
	if( newblocks > 0 && number_blocks < (unsigned)(INODE_BLOCKS - 2 + (1+INODE_LIST)*INODE_LIST) ){

		unsigned index = number_blocks - (INODE_BLOCKS - 2 + INODE_LIST);

		//allocate the double linked list
		dlinked = calloc(1, sizeof(*dlinked));
		//allocate the double linked list or read it out if the inode
		if  ( index ==  0 ) {	//get a block for the double linked list
			success = inode_allocblocks(1,&(temp->sector[INODE_BLOCKS - 1]));
		} else {
			read_cache (temp->sector[INODE_BLOCKS -1], (void *)(dlinked) , 0, BLOCK_SECTOR_SIZE);
		}
		
		struct inode_list * linkedtemp = (struct inode_list *)malloc(sizeof(struct inode_list));

		//index in the double linked list structure
		int i = index / INODE_LIST;

		//do we need to create a new single list in the double list
		if  ( index % INODE_LIST ==  0 ) {
			success = inode_allocblocks(1,&(dlinked->sector[i]));
		} else {
			read_cache (dlinked->sector[i], (void *)(linkedtemp) , 0, BLOCK_SECTOR_SIZE);
		}

		if (newblocks <= (unsigned)( INODE_LIST - index % INODE_LIST)) loads = newblocks;
		else loads = ( INODE_LIST - index % INODE_LIST);

		success = inode_allocblocks(loads,&(linkedtemp->sector[index % INODE_LIST]));
		write_cache (dlinked->sector[i], linkedtemp, 0, BLOCK_SECTOR_SIZE);

		i++;
		newblocks -= loads;
		number_blocks += loads;

		
		//fill up linked lists in the double linked list
		while ( newblocks > 0 ) {	

			success = inode_allocblocks(1,&(dlinked->sector[i]));
			if ((int)newblocks <= INODE_LIST) loads = newblocks;
			else newblocks = INODE_LIST;
				
			success = inode_allocblocks(loads,linkedtemp->sector);
			write_cache (dlinked->sector[i], linkedtemp, 0, BLOCK_SECTOR_SIZE);

			i++;
			newblocks -= loads;
			number_blocks += loads;

		}
		free(linkedtemp);
	}
	if(success) {
		write_cache (inode->sector, (void *)(temp) , 0, BLOCK_SECTOR_SIZE);

		//save to disk
		if (linked != NULL) { 
			//get the correct sector
			read_cache (inode->sector, (void *)(&block) , 3*sizeof(unsigned) + (INODE_BLOCKS - 2) * sizeof(block_sector_t), sizeof(block_sector_t));
			write_cache (block, linked, 0, BLOCK_SECTOR_SIZE);
			//if (debug) printf("DEBUG: Inode create save linked at %d\n",block);
			free(linked);
		}
		if (dlinked != NULL) { 
			read_cache (inode->sector, (void *)(&block) , 3*sizeof(unsigned) + (INODE_BLOCKS - 1) * sizeof(block_sector_t), sizeof(block_sector_t));
			write_cache (block, dlinked, 0, BLOCK_SECTOR_SIZE);
			free(dlinked);
		}
	} 
	free(temp);	
	return success;
}


//this function reads out a direct block number from an inode
static block_sector_t find_directblock (const struct inode *inode, off_t pos) {

	off_t off = pos / BLOCK_SECTOR_SIZE;

	ASSERT(off < INODE_BLOCKS - 2);

	block_sector_t blocknumber;
        read_cache (inode->sector, (void *)(&blocknumber), 3*sizeof(unsigned) + off * sizeof(block_sector_t), sizeof(block_sector_t));
	
	return blocknumber;
}

//this function reads out a block number from an indirect block
static block_sector_t find_indirectblock (const struct inode *inode, off_t pos) {

	off_t off = pos / BLOCK_SECTOR_SIZE;

	unsigned number_blocks;
  	read_cache (inode->sector, (void *)(&number_blocks), 0, sizeof(unsigned));

	//read out the correct block
	block_sector_t blocknumber;

	//now we have to locate the block in the indirect or double indirect list
	//single linked list
	if(off < INODE_BLOCKS - 2 + INODE_LIST) {
		//read out the block of the single linked list
		block_sector_t single;
		read_cache (inode->sector, (void *)(&single) , 3*sizeof(unsigned) + (INODE_BLOCKS -2) * sizeof(block_sector_t), sizeof(block_sector_t));

		//get offset into the single linked list
		off_t offset = off - (INODE_BLOCKS - 2);
       		read_cache (single, (void *)(&blocknumber), offset*sizeof(block_sector_t) , sizeof(block_sector_t));

	} else {
		//otherwise we have a double linked list
		//get the double linked list
		block_sector_t doublelinked;
		read_cache (inode->sector, (void *)(&doublelinked) , 3*sizeof(unsigned) + (INODE_BLOCKS -1) * sizeof(block_sector_t), sizeof(block_sector_t));
		//get the single linked list within that double linked list
		block_sector_t single;
		//now we get the offset to the single linked list inside the double
		off_t singleoff = (off - (INODE_BLOCKS - 2) - INODE_LIST) / INODE_LIST;

		read_cache (doublelinked, (void *)(&single) , singleoff * sizeof(block_sector_t), sizeof(block_sector_t));

		//get the correct block
		//read out the correct block
		//get offset into the single linked list
		off_t offset = off - (INODE_BLOCKS - 2) - INODE_LIST - singleoff*INODE_LIST;
       		read_cache (single, (void *)(&blocknumber), offset * sizeof(block_sector_t), sizeof(block_sector_t));
	}

	return blocknumber;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  //get the size of the file
  off_t file_length;
  read_cache (inode->sector, (void *)(&file_length), sizeof(unsigned), sizeof(off_t));

  if (pos < file_length) {
    if (  (pos / BLOCK_SECTOR_SIZE) < INODE_BLOCKS - 2) return find_directblock(inode,pos);
    else return find_indirectblock(inode,pos);
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, enum file_type type)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
	//size_t sectors = bytes_to_sectors (length) + 1;
        disk_inode->length = 0;
        disk_inode->magic = INODE_MAGIC;
	disk_inode->number_blocks = 1;
 	disk_inode->type = type;

	success = inode_allocblocks(1,disk_inode->sector);	

	write_cache (sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
	//if length of file is > 0 then just call write to inode
	//and write a 0 to the position length
	if (length > 0) { 
		static char zeros[1];
		struct inode * myinode = inode_open(sector);
		inode_write_at (myinode, zeros, 1, length-1); 
		inode_close(myinode);
	}

     free (disk_inode);

    }
  return success;
}

//allocated num blocks and puts them in blockarray, the array has to be big enough
bool inode_allocblocks (int num, block_sector_t * blockarray) {

	bool success = false;
	//block_sector_t * sectorptr;
	static char zeros[BLOCK_SECTOR_SIZE];
	int i;
	for (i = 0; i < num; i++){
		//allocate the blocks one by one
      		if (free_map_allocate (1, &blockarray[i])) {
			//write to the cache of the filesystem
			write_cache (blockarray[i], zeros, 0, BLOCK_SECTOR_SIZE);
			success = true;
		}
		else {
			success = false;
			break;
		}
	}

	return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->inode_lock);

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL) {
    return;
}

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
	//get all the blocks and remove them one by one
	struct inode_disk * temp = calloc (1, sizeof(*temp));
	read_cache (inode->sector, (void *)(temp) , 0, BLOCK_SECTOR_SIZE);

	//get the number of blocks in the file
	unsigned blocks;
  	read_cache (inode->sector, (void *)(&blocks), 0, sizeof(unsigned));

	struct inode_list * linked = NULL;
	struct inode_list * dlinked = NULL;

	int loads;
	unsigned i;
	if (blocks < INODE_BLOCKS - 2) loads = blocks;
	else loads = INODE_BLOCKS - 2;
	
	for (i = 0; i < blocks; i++) { 
		free_map_release (temp->sector[i], 1);
	}
	blocks -= loads;

	if ( blocks > 0 ) {
		//delete the single linked list
		read_cache (temp->sector[INODE_BLOCKS -2], (void *)(linked) , 0, BLOCK_SECTOR_SIZE);	

		if (blocks < (unsigned)INODE_LIST) loads = blocks;
		else loads = INODE_LIST;

		for (i = 0; i < (unsigned)loads; i++) free_map_release (linked->sector[i], 1);
		blocks -= loads;
		//free linked list	
		free_map_release (temp->sector[INODE_BLOCKS -2], 1);
	}
	//get doubled linked list
	if ( blocks > 0 ) {
		//load single linked list in double linked list
		read_cache (temp->sector[INODE_BLOCKS -1], (void *)(dlinked) , 0, BLOCK_SECTOR_SIZE);

		int j=0;

		while (blocks > 0 ) {
		
			read_cache (dlinked->sector[j], (void*)linked, 0, BLOCK_SECTOR_SIZE);

			if (blocks < (unsigned)INODE_LIST) loads = blocks;
			else loads = INODE_LIST;
	
			for (i = 0; i < (unsigned)loads; i++) free_map_release (linked->sector[i], 1);
			blocks -= loads;

			free_map_release (dlinked->sector[j], 1);
			j++;
		}
		//free linked list	
		free_map_release (temp->sector[INODE_BLOCKS -1], 1);
	}
          free_map_release (inode->sector, 1);
	  if (linked != NULL) free(linked);
	  if (dlinked != NULL) free(dlinked);
	  free(temp);
        }
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
//if(sector_idx == -1) printf("sector onvalid\n");

      if (chunk_size <= 0 || sector_idx == -1) 
        break;

	//read from the cache of the filesystem
	read_cache (sector_idx, buffer + bytes_read, sector_ofs, chunk_size);
//printf("read from inode sector %d\n",sector_idx);
 
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{

  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  block_sector_t sector_idx = -1;
  unsigned number_blocks = 0;
  bool EOF = false;

  if (inode->deny_write_cnt)
    return 0;

  //do we have to grow the file?
  if ( size > 0 ) {
  	read_cache (inode->sector, (void *)(&number_blocks), 0, sizeof(unsigned));
	//check if we have to extend the file
	if( (unsigned)( (offset + size) /  BLOCK_SECTOR_SIZE) >= number_blocks) {
		//since we are at EOF we have to make sure no one else is trying to write when he is at EOF
		//just acquire the lock if it is a file directories are locked out already
		if(inode_type(inode) == FILE_FILE) {
			lock_acquire(&inode->inode_lock);
			EOF = true;
		}
		//grow the file
		file_grow (inode, offset + size);
	}
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
	//get the correct block in the file
      if (  (offset / BLOCK_SECTOR_SIZE) < INODE_BLOCKS - 2) sector_idx = find_directblock(inode,offset);
    		else sector_idx = find_indirectblock(inode,offset);	

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
 
      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;

      if (chunk_size <= 0)
        break;

	//write to the cache of the filesystem
    	write_cache (sector_idx, (void *) (buffer + bytes_written), sector_ofs, chunk_size);

//printf("write to inode sector %d\n",sector_idx);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;

    }
  //do we have to reset the file length and number of blocks
  //we change it that late so no reading proces can see the changes at EOF until they are finished
  off_t inode_size = inode_length (inode);
  if ( inode_size < (offset) ) {
	inode_resetlength(inode,offset);
	unsigned newsize = (offset / BLOCK_SECTOR_SIZE + 1);
	write_cache (inode->sector, (void *)&newsize, 0, sizeof(unsigned));
  }

  //did we acquire the lock?
  if (EOF) lock_release(&inode->inode_lock);

  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE. */
off_t
inode_length (const struct inode *inode)
{
  //get the size of the file
  off_t file_length;
  read_cache (inode->sector, (void *)(&file_length), sizeof(unsigned), sizeof(off_t));

  return file_length;
}

/* Returns the length, in bytes, of INODE. */
void
inode_resetlength (const struct inode *inode, off_t newlength)
{
  //get the size of the file
  write_cache (inode->sector, (void *)(&newlength), sizeof(unsigned), sizeof(off_t));

}

//returns the enum of the inode
enum file_type
inode_type (const struct inode *inode)
{
  //get the file type
  enum file_type type;

  read_cache (inode->sector, (void *)(&type), sizeof(struct inode_disk) - sizeof(type), sizeof(type));
  return type;

}

//returns the id of the inode which is the sector
block_sector_t
inode_id (const struct inode *inode)
{
  return inode->sector;
}

int
inode_opencnt (const struct inode * inode) {

	return inode->open_cnt;
}

void
inode_lock (struct inode * inode) {

	lock_acquire(&inode->inode_lock);
}

void
inode_unlock (struct inode * inode) {

	lock_release(&inode->inode_lock);
}

