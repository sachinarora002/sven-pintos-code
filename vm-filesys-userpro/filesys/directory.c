#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

char * getfilename (const char * name);

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry),FILE_DIR);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);


  //we have to stop / lookup in /
  if( strcmp(name,"/") == 0 && inode_id(dir->inode) == ROOT_DIR_SECTOR)
	*inode = inode_reopen(dir->inode);
  else {
  //lock the directory for the rest of the lookup operation
  inode_lock(dir->inode);
  name = getfilename(name);
 
  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;
 //unlock the dir again
 inode_unlock(dir->inode);
 }

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  name = getfilename(name);

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX) {
    return false;
  }
  //lock the directory for the operation
  inode_lock(dir->inode);

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  //unlock the directory again
  inode_unlock(dir->inode);
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  //lock the directory for the rest of the lookup operation
  inode_lock(dir->inode);
  name = getfilename(name);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  //if it is still open don't allow deletion
  if(inode_type(inode) == FILE_DIR) {
	//is file in use?
	if(inode_opencnt(inode) > 1)
		goto done;
	char * temp = (char *)malloc(sizeof(char) * (NAME_MAX + 1) );
	struct dir * dirtemp = dir_open(inode);
	//is dir empty?
	if (dir_readdir(dirtemp,temp)) {
		free(temp);
		dir_close(dirtemp);
		goto done;
	}
	free(temp);
	dir_close(dirtemp);	
  }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  //unlock the directory
  inode_unlock(dir->inode);
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use && strcmp(e.name,".") != 0 && strcmp(e.name,"..") != 0 )
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}

//returns the inode of the last dir in name before the last /
//the user has to check for existing file after the /
struct dir *
dir_lookup_rec (const char *name) {

	//printf("lookup path is %s\n",name);

	//if the string starts with / it is an absolut path
	//root dir
	if ( strcmp( name, "/") == 0 ) return dir_open_root();

	//for the return value
	int success = 0;
	char *token ,*save_ptr;
	char * temp = (char *)malloc(strlen(name) + 1 );
	strlcpy (temp, name, strlen(name) + 1); 

	//open root and start 
	struct dir * current;

	//if it is relative make it absolute 
	if ( name[0] != '/' ) {
		current = dir_reopen(thread_current()->pwd);
	} else {
		current = dir_open_root();
	}
	
	struct inode * nextdir = dir_get_inode(current);

	//go through and check that the previous direcrtories exist
	for (token = strtok_r (temp, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr)) {

		//somethings wrong if this hapens	
		if (current == NULL ) break;
		//last round has to be not existing
		if (strlen(save_ptr) == 0) {
			success = 1;
			break;
				
		}

		//goto next if token is empty in case of //a/
		if(strlen(token) !=  0) {
			//check if this directory exists true if exists
			if ( dir_lookup (current, token,&nextdir) ) {
				//check if it is a directory and then open it
				enum file_type type =  inode_type (nextdir);
				//is it a dir
				if(type == FILE_DIR) {
					dir_close(current);
					current = dir_open(nextdir);
				}
				else break;
			}
			else break;
		}
	}

  if( success == 1) return current; else return NULL;
}

char * getfilename (const char * name)
{

  //make sure that we just get the filename not the entrie path
  char *temp = (char *)malloc(strlen(name) + 1);
  strlcpy (temp, name, strlen(name) + 1);

  if( strcmp(temp,"/") == 0) return temp;

  char *token ,*save_ptr;
  //go through and check that the previous direcrtories exist
  for (token = strtok_r (temp, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr)) {

	if (strlen(save_ptr) == 0) {
			break;
	}
  }
  //free(temp);
  return token;

}
