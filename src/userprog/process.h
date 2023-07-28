#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct aux_info
{
  tid_t ptid;
  char *name;
  char *p_arguments;
  struct thread *th_chd;
  struct semaphore wait_sema;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
