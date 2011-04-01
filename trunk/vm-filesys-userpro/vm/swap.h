#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

void init_swap (void);
void get_swap (size_t , void *);
size_t add_swap (void *);
void swap_remove(size_t );

#endif /* vm/swap.h */
