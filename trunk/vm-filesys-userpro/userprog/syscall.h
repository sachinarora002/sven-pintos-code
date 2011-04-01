#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdio.h>
#include "threads/interrupt.h"

void syscall_init (void);
void exit_mythread (int);

#endif /* userprog/syscall.h */
