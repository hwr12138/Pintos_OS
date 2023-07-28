#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stddef.h>

void syscall_init (void);
int munmap (int md);

/* The maximum size of stack is 256K. */
#define MAX_STACK_SIZE (PHYS_BASE - PGSIZE * 64)

/* A memory map struct to keep track of useful information */
struct mem_map
{
  void *upage;     /* Starting address of the file mapping. */
  size_t mpd_pgs;   /* The number of mapped pages */
  struct file *file;    /* Pointer to the mapped file */
};

#endif /* userprog/syscall.h */
