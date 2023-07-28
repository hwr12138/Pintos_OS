#include <stdio.h>
#include <list.h>
#include <limits.h>
#include "devices/block.h"
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "filesys/cache.h"
#include "threads/thread.h"

struct lock cache_lock;
struct cache caches[MAX_CACHE];
struct list cache;

void write_behind (void *aux);

/* init the buffer cache system */
void
cache_init (void)
{
  lock_init(&cache_lock);
  for(int i = 0; i < MAX_CACHE; i++)
  {
    caches->dirty = false;
    caches->free = true;
  }
  list_init (&cache);
}

/* acquire a cache block if the block hasn't been cached, if it is cached, use
   that data */
struct cache *
cache_acquire (block_sector_t sector)
{
  struct cache *c = NULL;
  lock_acquire (&cache_lock);
  for (struct list_elem *e = list_begin (&cache); e != list_end (&cache); e = list_next (e))
  {
    c = list_entry (e, struct cache, elem);
    if (c->disk_sector == sector)
      break;
  }
  lock_release (&cache_lock);
  return c;
}

/* release a cache block and mark it as dirty if input dirty is true, block 
   becomes available afterwards. */
void
cache_release (struct cache *c, bool dirty)
{
  lock_acquire (&cache_lock);
  if (dirty)
    c->dirty = true;
  else
  {
    list_push_back (&cache, &c->elem);
  }
  lock_release (&cache_lock);
}

/* write all drity blocks to disk */
void 
write_behind (void *aux UNUSED)
{
  while (true)
  {
    lock_acquire (&cache_lock);
    // look for dirty blocks in cache
    struct cache *c;
    for (struct list_elem *e = list_begin (&cache); e != list_end (&cache); e = list_next (e))
    {
      c = list_entry (e, struct cache, elem);
      if (c->dirty == true)
        break;
    }
    while (c != NULL)
      {
        while (c->free == false)
          cond_wait (&c->avail, &cache_lock);
        lock_release (&cache_lock);
        block_write (fs_device, c->disk_sector, c->block);
        lock_acquire (&cache_lock);
        for (struct list_elem *e = list_begin (&cache); e != list_end (&cache); e = list_next (e))
        {
          struct cache *cache = list_entry (e, struct cache, elem);
          if (cache->dirty == true)
            break;
        }
      }
    lock_release (&cache_lock);
    timer_sleep (TIMER_FREQ * 4);
  }
}
