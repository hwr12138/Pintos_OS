#include <stdio.h>
#include <list.h>
#include <string.h>
#include <hash.h>
#include <stdbool.h>
#include <debug.h>
#include <bitmap.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

static void frame_remove_elem (struct page *page, struct frame *frame);
static void frame_write_and_free (struct page *page, struct frame *frame, 
                                  const void *upage);
static void *frame_alloc_helper (void *kpage);
static void *frame_evict_clean (void);
static void *frame_evict_help (void);
static void frame_adjust_clock_h (void);
static unsigned frame_hash (const struct hash_elem *e, void *aux UNUSED);
static bool frame_less (const struct hash_elem *a, const struct hash_elem *b,
                        void *aux UNUSED);

/* We keep this list of frames that can get evicted, and we use 
   the clock algorithm to keep track of the order */
static struct list frame_list;
/* The clock hand for the eviction process algorithm, pointing
   to which frame next we should see */
static struct list_elem *clock_hand;
/* Hash table for frames with no write access, we choose to keep 
   track of them with this hash struct */
static struct hash read_only_frames;
/* Global lock for frames for VM synchronization */
static struct lock frame_lock;

void
frame_init (void)
{
  lock_init (&frame_lock);
  hash_init (&read_only_frames, frame_hash, frame_less, NULL);
  list_init (&frame_list);
  clock_hand = list_end (&frame_list);
}

/* Unloads the frame of upage, frees the correct resources of the frame
   and page directory*/
void
frame_unload (uint32_t *pd, const void *upage)
{
  bool f = false, ind = false;
  struct frame *frame;
  struct page *page = pagedir_get_info (pd, upage);
  if (page == NULL)
    return;
  lock_acquire (&frame_lock);
  if (page->frame == NULL)
    lock_release (&frame_lock);
  else
  {
    frame = page->frame;
    page->frame = NULL;
    f = true;
    if (list_size (&frame->information) > 1)
      ind = true;
  }
  if (f && ind)
  {
    struct list_elem *e = list_begin (&frame->information);
    while (e != list_end (&frame->information))
    {
      struct page *p = list_entry (e, struct page, elem);
      if (page == p)
      {
        list_remove (e);
        break;
      }
      e = list_next (e);
    }
  }
  else if (f)
    frame_remove_elem (page, frame);
  if (f)
  {
    pagedir_clear_page (page->pg_dir, upage);
    /* Release the global lock since we are done dealing with any possible
        shared data belonging to the frame and we move on to freeing resources*/
    lock_release (&frame_lock);
    if (list_empty (&frame->information))
      frame_write_and_free (page, frame, upage);
  }
  if (page->type & TYPE_KERNEL)
  {
    /* For kernel pages, only the kpage needs to get freed */
    void *kpage = (void *) page->kpage;
    palloc_free_page (kpage);
    page->kpage = NULL;
  }
  else if (page->swapped)
  {
    /* Update the bitmap to indicate it is now free again and not in use */
    static struct bitmap *bitmap;  
    bitmap_set_multiple (bitmap, page->swp_loc / BLOCK_SEC_P_PG, 
                         1, false);
    page->swapped = false;
  }
  pagedir_set_info (page->pg_dir, upage, NULL);
  free (page);
}

/* Unlocks the frame by decrementing its lock */
void
frame_unlock(struct page *page)
{  

  lock_acquire (&frame_lock);
  page->frame->perm_to_evict = 0;
  lock_release (&frame_lock);
}

static void
frame_remove_elem (struct page *page, struct frame *frame)
{
  if (page->type & TYPE_FILE && page->writable == 0)
    hash_delete (&read_only_frames, &frame->hash_elem);
  if (clock_hand == &frame->list_elem)
    clock_hand = list_next (clock_hand);
  list_remove (&page->elem);
  list_remove (&frame->list_elem);
}

static void
frame_write_and_free (struct page *page, struct frame *frame, 
                      const void *upage)
{
  bool dty = pagedir_is_dirty (page->pg_dir, upage);
  if (page->writable & CAN_WRITE_FILE && dty)
  {
    struct file *fil = page->file;
    off_t e_off = page->offset;
    acquire_lock_file ();
    file_write_at (fil, frame->kpage, SIZE (e_off), OFFS (e_off));
    release_lock_file ();
  }
  palloc_free_page (frame->kpage);
  free (frame);
}

/* Loads the frame by mapping it appropriately and getting a new frame if
   it is not there */
bool
frame_load (uint32_t *pd, const void *upage, bool write, bool keep_locked)
{
  struct page *page = pagedir_get_info (pd, upage);
  if (page == NULL || (write && page->writable == 0))
    return false;
  lock_acquire (&frame_lock);
  if (page->frame != NULL)
  {
    if (keep_locked)
      page->frame->perm_to_evict++;
    lock_release (&frame_lock);
    return true;
  }
  /* Check if the page is read only to update our hash mapping */
  struct frame *frame = NULL;
  bool success = false;
  if (page->writable == 0)
    if (page->type & TYPE_FILE)
    {
      struct frame fr;
      list_init (&fr.information);
      list_push_back (&fr.information, &page->elem);
      struct hash_elem *e = hash_find (&read_only_frames, &fr.hash_elem);
      if (e != NULL)
      {
        frame = hash_entry (e, struct frame, hash_elem);
        page->frame = frame;
        list_push_back (&frame->information, &page->elem);
        pagedir_set_page (page->pg_dir, upage, frame->kpage, page->writable!=0);
        pagedir_set_dirty (page->pg_dir, upage, false);
        pagedir_set_accessed (page->pg_dir, upage, true);
        success = true;
      }
    }
  bool t = false;
  if (frame == NULL)
  {
    void *kpage = palloc_get_page (PAL_USER | PAL_ZERO);
    if (kpage != NULL)
      frame = frame_alloc_helper (kpage);
    else
      frame = frame_evict_clean ();
    if (frame != NULL)
    {
      /* Map page to frame and read the data in. */
      page->frame = frame;
      list_push_back (&frame->information, &page->elem);
      pagedir_set_page (page->pg_dir, upage, frame->kpage, page->writable!=0);
      pagedir_set_dirty (page->pg_dir, upage, false);
      pagedir_set_accessed (page->pg_dir, upage, true);
      t = true;
      success = true;
    }
  }
  bool a = false;
  if (t && (page->swapped || page->type & TYPE_FILE))
  {
    a = true;
    if (!page->swapped)
    {
      if (page->writable == 0)
        /* When frame has no write accesses, we add it to our hash map */
        hash_insert (&read_only_frames, &frame->hash_elem);
      struct file *fil = page->file;
      off_t e_off = page->offset;
      lock_release (&frame_lock);
      acquire_lock_file ();
      file_read_at (fil, frame->kpage, SIZE (e_off), OFFS (e_off));
      release_lock_file ();
    }
    else
    {
      lock_release (&frame_lock);
      swap_read (page->swp_loc, frame->kpage);
      page->swapped = false;
    }
  }
  else if (t && (page->type & TYPE_KERNEL))
  {
    void *kpage = (void *) page->kpage;
    memcpy (frame->kpage, kpage, PGSIZE);
    palloc_free_page (kpage);
    page->kpage = NULL;
    page->type = TYPE_ZERO;
  }
  if (a)
  {
    lock_acquire (&frame_lock);
    frame->perm_to_evict--;
  }
  if (success && keep_locked)
    frame->perm_to_evict++;
  lock_release (&frame_lock);
  return success;
}

static void *
frame_alloc_helper (void *kpage)
{
  struct frame *frame = calloc (1, sizeof (struct frame));
  if (frame != NULL)
  {
    list_init (&frame->information);
    frame->kpage = kpage;
    /* Insert the new frame to the end of the eviction list */
    if (!list_empty (&frame_list))
      list_insert (clock_hand, &frame->list_elem);
    else
    {
      list_push_front (&frame_list, &frame->list_elem);
      clock_hand = list_begin (&frame_list);
    }
  }
  else
    PANIC ("calloc failed");
  return frame;
}

/* Evicts the right frame based on the clock algorithm and returns a
   free frame */
static void *
frame_evict_clean (void)
{
  block_sector_t swp_loc;
  bool dirty = false;
  struct frame *frame = frame_evict_help();
  struct list_elem *e = list_begin (&frame->information);
  struct page *page = list_entry (e, struct page, elem);
  while (e != list_end (&frame->information))
  {
    dirty = dirty || pagedir_is_dirty (page->pg_dir, page->upage);
    pagedir_clear_page (page->pg_dir, page->upage);
    e = list_next (e);
  }
  bool s = false;
  /* Whenever possible, we write the frame to swap to read easily */ 
  if (dirty || page->writable & CAN_WRITE_SWAP)
  {
    frame->perm_to_evict++;
    s = true;
  }
  else if (page->type & TYPE_FILE && page->writable == 0)
    hash_delete (&read_only_frames, &frame->hash_elem);
  if (s && page->writable & CAN_WRITE_FILE)
  {
    struct file *fil = page->file;
    off_t e_off = page->offset;
    lock_release (&frame_lock);
    acquire_lock_file ();
    file_write_at (fil, frame->kpage, SIZE (e_off), OFFS (e_off));
    release_lock_file ();
    lock_acquire (&frame_lock);
    frame->perm_to_evict--;
  }
  else if (s)
  {
    lock_release (&frame_lock);
    swp_loc = swap_write (frame->kpage);
    lock_acquire (&frame_lock);
    frame->perm_to_evict--;
  }
  e = list_begin (&frame->information);
  while (e != list_end (&frame->information))
  {
    page = list_entry (list_front (&frame->information),
                            struct page, elem);
    page->frame = NULL;
    if (page->writable & CAN_WRITE_SWAP)
    {
      page->swapped = true;
      page->swp_loc = swp_loc;
    }
    e = list_remove (e);
  }
  memset (frame->kpage, 0, PGSIZE);
  return frame;
}

/* Gets the right frame to evict based on the clock algorithm from the list 
   of frames available to evict. We check whether the current one the head points
   to is not locked and evict if it is not and update the clock hand. */
static void *
frame_evict_help (void)
{
  ASSERT (!list_empty (&frame_list));
  struct frame *found = list_entry (clock_hand, struct frame, list_elem);
  frame_adjust_clock_h ();
  return found;
}
/* Adjusts the clock hand and goes to the next entry */
static void
frame_adjust_clock_h (void)
{
  clock_hand = list_next (clock_hand);
  if (clock_hand == list_end (&frame_list))
    clock_hand = list_begin (&frame_list);
  return;
}
/* Gets the frame's has info data */
static unsigned
frame_hash (const struct hash_elem *e, void *aux UNUSED)
{
  struct page *page = list_entry (list_front (&hash_entry (e, 
      struct frame, hash_elem)->information), struct page, elem);
  return hash_bytes (&page->file, 
      sizeof (page->file)) ^ hash_bytes 
      (&page->offset, 
      sizeof (page->offset));
}
/* Checks if frame a's file is stored before b in memory */
static bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
            void *aux UNUSED)
{
  struct page *page_info_a = list_entry (list_front (&hash_entry (a_, 
      struct frame, hash_elem)->information), struct page, elem);
  struct page *page_info_b = list_entry (list_front (&hash_entry (b_, 
      struct frame, hash_elem)->information), struct page, elem);
  if (page_info_a->file < page_info_b->file)
    return true;
  else if (page_info_a->file > page_info_b->file)
    return false;
  if (page_info_a->offset
      < page_info_b->offset)
    return true;
  else
    return false;
}
