#include "devices/block.h"

void swap_init(void);
block_sector_t swap_write (void *kpage);
void swap_read (block_sector_t sector, void *kpage);
