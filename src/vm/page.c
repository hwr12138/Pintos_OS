#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"

/* Returns true if it successfully updates info with the wanted information
   for that page directory and false otherwise */
bool
pagedir_set_info (uint32_t *pd, const void *upage, struct page *info)
{
  uint32_t *pte = lookup_page (pd, upage, true);
  if (pte == NULL)
    return false;
  struct page **pie = ((struct page **) (((uintptr_t) 
                pte + (1 << 12)) & ~(((1ul << 12) - 1) << 0))) + pt_no (upage);
  *pie = info;
  return true;
}

/* Looks for the wanted information for a page directory 
   regarding the user virtual address upage stored in pd.  
   Returns a pointer to the page information
   or null otherwise. */
struct page *
pagedir_get_info (uint32_t *pd, const void *upage)
{
  uint32_t *pte = lookup_page (pd, upage, false);
  struct page *pie = NULL;
  if (pte == NULL)
    return NULL;
  pie = *(((struct page **) (((uintptr_t) pte + 
                    (1 << 12)) & ~(((1ul << 12) - 1) << 0))) + pt_no (upage));
  return pie;
}
