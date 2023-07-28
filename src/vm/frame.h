#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <hash.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

/* THe basic frame data structure */
struct frame
{
  void *kpage;  /* Virtual page addr of kernel associated with its physical frame */
  struct list information; /* List of pages that maps to this frame */
  struct condition processing; /* Indicates whether frame is getting processed */
  unsigned short perm_to_evict; /* Keep track whether frame is locked for eviction */
  struct hash_elem hash_elem; /* A hash element for frames with only read access */
  struct list_elem list_elem; /* A list elem to keep track of this frame */
};

void frame_init(void);
void frame_unload (uint32_t *pd, const void *upage);
void frame_unlock(struct page *page);
bool frame_load (uint32_t *pd, const void *upage, bool write, bool keep_locked);

#endif /* vm/frametable.h */
