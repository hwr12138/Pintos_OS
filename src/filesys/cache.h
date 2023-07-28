#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <list.h>
#include "threads/synch.h"
#include "devices/block.h"

#define MAX_CACHE 64

struct cache 
{
    uint8_t block[BLOCK_SECTOR_SIZE];
    block_sector_t disk_sector;

    bool free;
    bool dirty;
    struct condition avail;
    struct list_elem elem;
};

void cache_init (void);
struct cache *cache_acquire (block_sector_t sector);
void cache_release (struct cache *c, bool dirty);

#endif /* filesys/cache.h */