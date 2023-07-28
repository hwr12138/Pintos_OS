#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdio.h>
#include <list.h>
#include <string.h>
#include <hash.h>
#include <stdbool.h>
#include <debug.h>
#include <bitmap.h>
#include "vm/frame.h"

/* Page types. */
#define TYPE_ZERO    0x01  /* Page content is zero. */
#define TYPE_KERNEL  0x02  /* Page content is from the kernel memory. */
#define TYPE_FILE    0x04  /* Page has association with a file. */

/* If a page is writable, it will be written back to a file or to swap. */
#define CAN_WRITE_FILE  0x01
#define CAN_WRITE_SWAP  0x02

/* Size and offset macros */
#define OFFS(A) (off_t)(A > 0  ? (A - 1) & ~PGMASK : 0)
#define SIZE(A) ((off_t) A - OFFS (A))

#define BLOCK_SEC_P_PG (PGSIZE / BLOCK_SECTOR_SIZE)

/* A struct to keep necessary info for a user page */
struct page
{
  uint8_t type;
  uint8_t writable;

  uint32_t *pg_dir;  /* The page directory this page got mapped to */
  const void *upage;  /* The page's user virtual page address */

  bool swapped;  /* Indicates whether the page is a swap page or not */

  struct frame *frame;  /* Pointer to the frame of the page */
  /* The rest of the things are for either info of the page's file, swap block 
     if it is a swap type or kernel address for initialization */
  struct file *file;  /* Pointer to the file mapped by the page */
  off_t offset; /* End of the mapped space, which we can get the start offset and size from */
  block_sector_t swp_loc; /* Sector of the address for swap space */
  const void *kpage;
  
  struct list_elem elem; /* An element for the frame to keep track of this page's info */
};

bool pagedir_set_info (uint32_t *pd, const void *upage, struct page *info);
struct page *pagedir_get_info (uint32_t *pd, const void *upage);

#endif /* vm/page.h */
