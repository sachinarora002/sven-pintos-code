#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/malloc.h"


/* Partition that contains the file system. */
struct block *fs_device;

char * parse_filename (const char * name);

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  //initiaize the cache filesystem
  init_cache ();
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  save_cachetable();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, enum file_type type) 
{
  block_sector_t inode_sector = 0;

  char * parse = parse_filename (name); 
  //get the correct dir

  struct dir *dir = dir_lookup_rec (parse);

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, type)
                  && dir_add (dir, parse, inode_sector));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  if( success == true && type == FILE_DIR ) {
	//we want to add . and .. as well if it is a dir
		//open the created directory
		struct file * created = filesys_open(parse);
		struct dir * mydir = dir_open(file_get_inode (created));
		//add . to it
		dir_add (mydir, ".", inode_sector);
		struct inode * parent = dir_get_inode (dir);
		block_sector_t inode_sector_parent = inode_id(parent);
		//add .. to it
		dir_add (mydir, "..", inode_sector_parent);
		dir_close(mydir);
		file_close(created);
  }
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{

  char * parse = parse_filename (name); 
  //get the correct dir
  struct dir *dir = dir_lookup_rec (parse);

  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, parse, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char * parse = parse_filename (name); 
  //get the correct dir
  struct dir *dir = dir_lookup_rec (parse);

  bool success = dir != NULL && dir_remove (dir, parse);
  dir_close (dir); 

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  //add . and .. for root
  struct dir * root = dir_open_root();
  dir_add(root,".",ROOT_DIR_SECTOR);
  dir_add(root,"..",ROOT_DIR_SECTOR);
  dir_close(root);

  free_map_close ();
  printf ("done.\n");
}

char * parse_filename (const char * name) {

	char * temp = (char *)malloc(strlen(name) + 1 );
	char *token ,*save_ptr;

	char * parse = (char *)malloc(strlen(name) + 1 );
	strlcpy (parse, name, strlen(name) + 1); 

	//if the string starts with / it is an absolut path
	if ( name[0] == '/' ) {
		memcpy(temp,"/\0",2);
	} else {
		memcpy(temp,"\0",1);
	}
	
	//parse the original name to remove multiple //
	for (token = strtok_r (parse, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr)) {

		if(strlen(token) != 0) {
			memcpy(temp + strlen(temp),token,strlen(token)+1);
			memcpy(temp + strlen(temp),"/\0",2);
		}		

	}

	//if last one is / remove it
	if ( strlen(temp) > 1 && strcmp( &(temp[strlen(temp)-1]), "/") == 0 ) 
		memcpy(temp + strlen(temp) - 1,"\0",1);

	return temp;	

}
