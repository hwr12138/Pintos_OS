#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <threads/malloc.h>
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (char *name, char *p_arguments, void (**eip) (void),
                  void **esp);
static void allow_write (void);
static off_t read_file_helper (int fd, void *buffer_, off_t size);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name_) 
{
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  char *file_name = palloc_get_page (0);
  if (file_name == NULL)
    return TID_ERROR;
  strlcpy (file_name, file_name_, PGSIZE);

  struct aux_info args;
  args.name = strtok_r (file_name, " ", &args.p_arguments);
  struct thread *cur = thread_current ();
  args.ptid = cur->tid;

  /* Create a new thread to execute FILE_NAME. */
  sema_init (&args.wait_sema, 0);
  tid = thread_create (args.name, PRI_DEFAULT, start_process, &args);
  if (tid == TID_ERROR)
  {
    return TID_ERROR;
  }
  
  /* Wait for the thread to start running so it can be added to the child
      list. */
  sema_down (&args.wait_sema);
  if (args.th_chd != NULL)  
    list_push_back (&cur->children, &args.th_chd->child_elem);
  else
    tid = TID_ERROR;
  palloc_free_page (file_name);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  struct aux_info *aux = args_;
  struct intr_frame if_;
  bool success = false;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  success = load (aux->name, aux->p_arguments, &if_.eip, &if_.esp);
  if (success == false) {
    aux->th_chd = NULL;
  }
  aux->th_chd = thread_current ();
  thread_current ()->ptid = aux->ptid;
  sema_up (&aux->wait_sema);

  /* If load failed, quit. */
  if (success == false)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e = list_begin (&cur->children);;
  struct thread *child = list_entry (e, struct thread, child_elem);
  while (e != list_end (&cur->children))
  {
    if (child->tid == child_tid)
    {
      list_remove (e);
      break;
    }
    e = list_next (e);
  }
  if (child == NULL)
    return -1;
  
  /* We acquire the lock to see if the child is done exiting */
  lock_acquire (&child->exit_lock);
  while (child->status != THREAD_EXITING)
    cond_wait (&child->exiting, &child->exit_lock);
  int exit_status = child->exit;
  lock_release (&child->exit_lock);
  /* Free the child */
  palloc_free_page (child);
  return exit_status;
}

/* Destroy the current page directory. */
static void
pgdir_destr(void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd = cur->pagedir;
  cur->pagedir = NULL;
  pagedir_activate (NULL);
  pagedir_destroy (pd);
  printf ("%s: exit(%d)\n", cur->name, cur->exit);
}

/* Enables write access for the files used by current thread. */
static void
allow_write (void)
{
  struct thread *cur = thread_current ();
  for (int fd = 2; fd < 128; fd++)
  {
    struct file *f = cur->open_f[fd];
    if (f == NULL)
      continue;
    acquire_lock_file ();
    file_allow_write (f);
    file_close (f);
    release_lock_file ();
    cur->open_f[fd] = NULL;
  }
  free (cur->open_f);
}

/* Makes the current process exit, frees its resources, including
   any child processes it may have. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  if (cur->mem_mapd_f != NULL)
  {
    for (int md = 0; md < 128; md++)
      munmap (md);
    free (cur->mem_mapd_f);
  }
  /* Destory its page directory */
  if (cur->pagedir != NULL) 
    pgdir_destr ();
  if (cur->open_f != NULL)
    allow_write ();

  lock_acquire (&cur->exit_lock);
  struct list_elem *e = list_begin (&cur->children);
  while (e != list_end (&cur->children))
  {
    struct thread *child = list_entry (e, struct thread, child_elem);
    
    if (child->status == THREAD_EXITING)
    {
      lock_acquire (&child->exit_lock);
    /* Make the child parentless to avoid signaling when it exits */
    child->ptid = (tid_t) 0;
      /* Free the child */ 
      palloc_free_page (child);
      lock_release (&child->exit_lock);
    }
    
    e = list_remove (e);
  }
  enum thread_status status = THREAD_DYING;
  if (cur->ptid != (tid_t) 0)
  {
    /* The current process has a waiting parent, so we signal it and
       let the parent take care of freeing up resources like the stack. */
    status = THREAD_EXITING;
    cond_signal (&cur->exiting, &cur->exit_lock);
  }
  
  intr_disable();
  lock_release (&cur->exit_lock);
  cur->status = status;
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}


/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (const char *name, char *args, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, int fd);
static bool load_segment (int fd, off_t ofs, uint8_t *upage, 
            uint32_t read_bytes, uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (char *name, char *p_arguments, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Make sure the file is unmodifiable so we deny write accesses */ 
  acquire_lock_file ();
  struct file *file = filesys_open (name);
  if (file != NULL)
    file_deny_write (file);
  release_lock_file ();

  t->open_f = calloc (128, sizeof *t->open_f);
  t->mem_mapd_f = calloc (128, sizeof *t->mem_mapd_f);

  int fd = -1;
  if (file != NULL)
  {
    struct thread *cur = thread_current ();
    for (fd = 2; fd < 128; fd++)
      if (cur->open_f[fd] == NULL)
        break;
    cur->open_f[fd] = file;
    if (fd == -1)
    {
      acquire_lock_file ();
      file_close (file);
      release_lock_file ();
    }
  }
  if (fd == -1)
  {
    printf ("load: %s: open failed\n", name);
    goto done;       
  }

  /* Read and verify executable header. */
  if (read_file_helper (fd, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;
      
      struct file *f;
      off_t file_size = 0;
      f = thread_current ()->open_f[fd];
      if (f != NULL)
        {
          acquire_lock_file ();
          file_size = file_length (f);
          release_lock_file ();
        }
      if (file_ofs < 0 || file_ofs > file_size)
        goto done;

      if (f != NULL)
        {
          acquire_lock_file ();
          file_seek (f, file_ofs);
          release_lock_file ();
        }
      if (read_file_helper (fd, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, fd)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (fd, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  
  /* Set up stack. */
  if (!setup_stack (name, p_arguments, esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, int fd) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  struct file *f;
  off_t file_size = 0;
  f = thread_current ()->open_f[fd];
  if (f != NULL)
    {
      acquire_lock_file ();
      file_size = file_length (f);
      release_lock_file ();
    }
  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_size) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

   - READ_BYTES bytes at UPAGE must be read from FILE
   starting at offset OFS.

   - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error occurs.
*/
static bool
load_segment (int fd, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  struct thread *cur = thread_current ();
  struct file *file = cur->open_f[fd];
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      struct page *page = (struct page *)calloc (1, sizeof *page);
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      page->upage = upage;
      page->pg_dir = cur->pagedir;
      if (writable)
        page->writable = 0x02;
      if (page_read_bytes > 0)
        {
          ofs += page_read_bytes;
          page->type = 0x04;
          page->file = file;
          page->offset = ofs;
        }
      else
        page->type = 0x01;
      
      pagedir_set_info (cur->pagedir, upage, page);
      
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory and adding the program name and arguments. */
static bool
setup_stack (const char *name, char *args, void **esp)
{
  bool success = false;

  uint8_t *kpage = palloc_get_page (PAL_ZERO);
  struct page *page = (struct page *)calloc (1, sizeof *page);
  if (kpage == NULL || page == NULL)
  {
    return false;
  }
  void *upage = (void *) (PHYS_BASE - PGSIZE);
  success = install_page (upage, kpage, true);
  if (success == false)
  {
    free (page);
    palloc_free_page (kpage);
    return false;
  }
  uint8_t *bottom = PHYS_BASE;
  uint8_t *top = PHYS_BASE - 512;
  uint8_t *base = top;
  int argc = 0;
  for (const char *arg = name; arg != NULL;)
  {
    size_t len = strlen (arg) + 1;
    void *temp = (void *)(((uintptr_t) 
                           (bottom - len)) & ~(((1ul << 2) - 1) << 0));
    if ((void *) (top + 2 * sizeof (char *)) >= temp)
      /* Run out of space for more args */
      break;
    bottom -= len;
    memcpy (bottom, arg, len * sizeof (char));
    *((uint8_t **) top) = bottom;
    top += sizeof (char *);
    if (args == NULL)
      arg = NULL;
    else
      arg = strtok_r (NULL, " ", &args);
    argc++;
  }
  bottom = (void *) ((uintptr_t) bottom & ~(((1ul << 2) - 1) << 0));
  bottom -= sizeof (char *);
  /* The arg pointers need to be word aligned under the last NULL arg
     pointer */
  memmove (base + (bottom - top), base, argc * sizeof (char *));
  uint8_t *t = (base + (bottom - top)) - sizeof (char**);
  *((uint8_t **) t) = base + (bottom - top);
  base = base + (bottom - top);
  base = base - sizeof (char **);
  base = base - sizeof (argc);
  *((int *) base) = argc;
  base = base - sizeof (void *);
  *base = 0;
  *esp = base;

  /* Setup the page info for page faults and other operations*/
  page->upage = upage;
  page->writable = 0x02;
  page->kpage = kpage;
  page->type = 0x02;
  page->pg_dir = thread_current ()->pagedir;
  pagedir_set_info (thread_current ()->pagedir, upage, page);
  pagedir_clear_page (thread_current ()->pagedir, upage);
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

static off_t
read_file_helper (int fd, void *buffer_, off_t size)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  if (fd == 0)
    {
      /* Treat stdin as a special file descriptor that reads lines from the 
         keyboard. */
      while (bytes_read < size)
        {
          uint8_t c = input_getc ();
          if (c == '\n')
            break;
          buffer[bytes_read++] = c;
        }
    }
  else
    {
      struct file *file = thread_current ()->open_f[fd];
      if (file != NULL)
        {
          acquire_lock_file ();
          bytes_read = file_read (file, buffer, size);
          release_lock_file ();
        }
    }
  return bytes_read;
}