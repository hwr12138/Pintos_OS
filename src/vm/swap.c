#include <stdbool.h>
#include <debug.h>
#include <bitmap.h>
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/swap.h"
  
struct block *block_devices;
/* Bitmap reserved for swaps */
static struct bitmap *swap_bitmap;  

/* Initialize swap map and device block */
void
swap_init(void)
{
  block_devices = block_get_role (BLOCK_SWAP);
  swap_bitmap = bitmap_create (block_size (block_devices) / BLOCK_SEC_P_PG);
}

/* Write the page from kpage to swap device and allocate space for it
   in swap map */
block_sector_t
swap_write (void *kpage)
{
  int i = 0;
  block_sector_t sector;
  /* Find the first available chunk of space in swap map and reserve it */
  block_sector_t sector_ = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
  if (sector_ != BITMAP_ERROR)
    sector = sector_ * BLOCK_SEC_P_PG;
  
  while (i < BLOCK_SEC_P_PG)
  {
    block_write (block_devices, sector, kpage);
    i++;
    sector++;
    kpage += BLOCK_SECTOR_SIZE; 
  }
  sector = sector - BLOCK_SEC_P_PG;
  return sector;
}

/* Reads a page from the swap device block into kpage */
void
swap_read (block_sector_t sector, void *kpage)
{
  int i = 0;
  while (i < BLOCK_SEC_P_PG)
  {
    block_read (block_devices, sector, kpage);
    i++;
    sector++;
    kpage += BLOCK_SECTOR_SIZE;
  }
  /* Reserve space in the swap map for sectors */
  block_sector_t start = (sector - BLOCK_SEC_P_PG) / BLOCK_SEC_P_PG;
  bitmap_set_multiple (swap_bitmap, start, 1, false);
} 
