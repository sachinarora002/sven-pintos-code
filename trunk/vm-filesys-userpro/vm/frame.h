#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <stdint.h>

void init_frame (void);
uint8_t * get_frame (void);
void frame_remove(void *);
void frame_lockdown (void *);
void frame_unlock (void *);

struct lock frame_lock;

#endif /* vm/frame.h */
