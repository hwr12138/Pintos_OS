#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "filesys/directory.h"

static void syscall_handler (struct intr_frame *);
static int syscall_halt(struct intr_frame* f);
static int syscall_exit(struct intr_frame* f);
static int syscall_exec(struct intr_frame* f);
static int syscall_wait(struct intr_frame* f);
static int syscall_create(struct intr_frame* f);
static int syscall_remove(struct intr_frame* f);
static int syscall_open(struct intr_frame* f);
static int syscall_filesize(struct intr_frame* f);
static int syscall_read(struct intr_frame* f);
static int syscall_write(struct intr_frame* f);
static int syscall_seek(struct intr_frame* f);
static int syscall_tell(struct intr_frame* f);
static int syscall_close(struct intr_frame* f);
static int syscall_mmap(struct intr_frame* f);
static int syscall_munmap(struct intr_frame* f);

static int syscall_chdir(struct intr_frame* f);
static int syscall_mkdir(struct intr_frame* f);
static int syscall_readdir(struct intr_frame* f);
static int syscall_isdir(struct intr_frame* f);
static int syscall_inumber(struct intr_frame* f);

static int get_user (const uint8_t *uaddr);
void validate_vaddr (uint32_t vaddr);
void validate_user (const char *ptr);
static bool get_arg_at_pos (const uint8_t *uaddr, int pos, int *arg);
static bool lock_buffer (const void *buffer, off_t size, bool write);
static bool unlock_buffer (const void *buffer, off_t size);
static size_t calc_pg_n (const void *buffer, off_t size);
void grow_stack_if_sa (uint32_t *pd, const void *vaddr);

static int (*sc[20])(struct intr_frame* f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  /* register all requirements of syscalls */
  sc[SYS_HALT] = &syscall_halt;
  sc[SYS_EXIT] = &syscall_exit;
  sc[SYS_EXEC] = &syscall_exec;
  sc[SYS_WAIT] = &syscall_wait;
  sc[SYS_CREATE] = &syscall_create;
  sc[SYS_REMOVE] = &syscall_remove;
  sc[SYS_OPEN] = &syscall_open;
  sc[SYS_FILESIZE] = &syscall_filesize;
  sc[SYS_READ] = &syscall_read;
  sc[SYS_WRITE] = &syscall_write;
  sc[SYS_SEEK] = &syscall_seek;
  sc[SYS_TELL] = &syscall_tell;
  sc[SYS_CLOSE] = &syscall_close;
  sc[SYS_MMAP] = &syscall_mmap;
  sc[SYS_MUNMAP] = &syscall_munmap;
  sc[SYS_CHDIR] = &syscall_chdir;
  sc[SYS_MKDIR] = &syscall_mkdir;
  sc[SYS_READDIR] = &syscall_readdir;
  sc[SYS_ISDIR] = &syscall_isdir;
  sc[SYS_INUMBER] = &syscall_inumber;
}

/* handler to call specific syscall*/
static void
syscall_handler (struct intr_frame *f) 
{
  int type = *(int *)f->esp;
  if (type >= 20 || type <= 0 || sc[type] == NULL)
  {
    f->eax = -1;
    thread_current()->exit = -1;
    thread_exit ();
  }
  f->eax = sc[type] (f);
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Validate if the virtual addr is legit */
void 
validate_vaddr (uint32_t vaddr)
{ 
  // validate if the vaddr is a valid user virtual addr
  if (is_user_vaddr(vaddr) == false)
  {
    thread_current()->exit = -1;
    thread_exit ();
  }
  // check if we can read a byte from the next 4 vaddr
  for (uint8_t i = 0; i <= 3; i++) 
  {
    if (get_user(((uint8_t *) vaddr) + i) == -1)
    {
      thread_current()->exit = -1;
      thread_exit ();
    }
  }
  // validate if the vaddr can be mapped to a legit kernel virtual addr
  void *ptr = pagedir_get_page (thread_current()->pagedir, vaddr);
  if (!ptr)
  {
    thread_current()->exit = -1;
    thread_exit ();
  }
  return ptr;
}

/* Check if name is null */
void
validate_user (const char *ptr)
{
  if (ptr == NULL)
  {
    thread_current()->exit = -1;
    thread_exit ();
  }
}

/* get argument from a specific user space address and store to arg. */
static bool
get_arg_at_pos (const uint8_t *uaddr, int pos, int *arg)
{
  const uint8_t *spec_pos = uaddr + sizeof (int) * pos;
  validate_vaddr (spec_pos);
  *arg = (uint8_t) get_user(spec_pos) | 
        (uint8_t) get_user(spec_pos + 1) << 8 | 
        (uint8_t) get_user(spec_pos + 2) << 16 |
        (uint8_t) get_user(spec_pos + 3) << 24;
  
  return true;
}

/* Locks the buffer to prevent paging the buffer when a file system 
   operation is occurring */
static bool
lock_buffer (const void *buffer, off_t size, bool write)
{
  bool success = false;
  struct thread *cur = thread_current ();
  size_t num_pages = calc_pg_n (buffer, size);
  void *upage = pg_round_down (buffer);
  size_t i = 0;
  /* We may need to grow the stack to include the buffer if it is
     outside the current stack region */
  grow_stack_if_sa (cur->pagedir, buffer);
  while (i < num_pages)
  {
    grow_stack_if_sa (cur->pagedir, upage);
    if (!frame_load (cur->pagedir, upage, write, true))
      break;
    i++;
    upage += PGSIZE;
  }
  if (i >= num_pages)
    return true;
  num_pages = i;
  upage = pg_round_down (buffer);
  i = 0;
  /* Unlock the pages when an error happens */
  while (i < num_pages)
  {
    struct page *page = pagedir_get_info (cur->pagedir, upage);
    if (page == NULL || page->frame == NULL)
      return;
    else
      frame_unlock (page);
    i++;
    upage += PGSIZE;
  }
  return success;
}
/* Unlocks the buffer from its previously locked state */
static bool
unlock_buffer (const void *buffer, off_t size)
{
  void *upage = pg_round_down (buffer);
  size_t num_pages = calc_pg_n (buffer, size);
  size_t i = 0;
  while (i < num_pages)
  {
    struct page *page = pagedir_get_info (thread_current ()->pagedir, upage);
    if (page == NULL || page->frame == NULL)
      return;
    else
      frame_unlock (page);
    i++;
    upage += PGSIZE;
  }
  return true;
}

/* Helper function to calculate the number of pages. */
static size_t
calc_pg_n (const void *buffer, off_t size)
{
  return (pg_round_down (buffer + size) - pg_round_down (buffer)) / PGSIZE + 1;
}

/* Halt the system */
static int
syscall_halt (struct intr_frame* f)
{
  (void) f;
  shutdown_power_off ();  
  return 0;
}

/* Terminates the current user program and returns status to the kernel*/
static int
syscall_exit (struct intr_frame* f)
{
  uint32_t *ptr = f->esp;
  //check if the address is valid
  validate_vaddr (ptr + 1);
  *ptr++;
  // record the the exit status
  thread_current()->exit = *ptr;
  thread_exit ();
  return 0;
}

/* Run executable commands */
static int
syscall_exec (struct intr_frame* f)
{
  uint32_t *ptr = f->esp;
  // check if ptr+1 address is valid
  validate_vaddr (ptr + 1);
  // check if the address of ptr+1 points to is valid
  validate_vaddr (*(ptr + 1));
  *ptr++;
  return process_execute((char *) *ptr);
}

/* Wait for the child process */
static int
syscall_wait (struct intr_frame* f)
{
  uint32_t *ptr = f->esp;
  // check if the address is valid
  validate_vaddr (ptr + 1);
  *ptr++;
  // call the function process_wait to wait for the child thread 
  return process_wait(*ptr);
}

/* Create a new file */
static int
syscall_create (struct intr_frame* f)
{
  uint32_t *ptr = f->esp;
  // check if the ptr+1 address is valid 
  validate_vaddr (ptr + 1);
  // check if the ptr+2 address is valid
  validate_vaddr (ptr + 2);
  // check if the address ptr+1 points to is valid 
  validate_vaddr (*(ptr + 1));
  // check if the name ptr+1 points to is null
  validate_user ((const char *)*(ptr + 1));
  *ptr++;
  
  acquire_lock_file ();
  bool success = filesys_create ((const char *)*ptr, *(ptr+1));
  release_lock_file ();
  return success;
}

/* Remove a certain file */
static int
syscall_remove (struct intr_frame* f)
{
  // validate
  uint32_t *ptr = f->esp;
  // check if the ptr+1 address is valid 
  validate_vaddr (ptr + 1);
  // check if the address ptr+1 points to is valid 
  validate_vaddr (*(ptr + 1));
  // check if the name ptr+1 points to is null
  validate_user ((const char *)*(ptr + 1));
  *ptr++;
  
  acquire_lock_file ();
  // call the function filesys_remove to perform the actual of removing file
  bool suc = filesys_remove ((const char *)*ptr);
  release_lock_file ();
  return suc;
}

/* Open a certain file */
static int
syscall_open (struct intr_frame* f)
{
  uint32_t *ptr = f->esp;
  // check if the ptr+1 address is valid 
  validate_vaddr (ptr + 1);
  // check if the address ptr+1 points to is valid 
  validate_vaddr (*(ptr + 1));
  // check if the name ptr+1 points to is null
  validate_user ((const char *)*(ptr + 1));
  *ptr++;
  
  struct file *file;
  acquire_lock_file ();
  file = filesys_open ((const char *)*ptr);
  release_lock_file ();

  int fd = -1;
  if (file != NULL)
    {
      struct thread *cur = thread_current ();
      for (fd = 2; fd < 128; fd++)
        if (cur->open_f[fd] == NULL)
          break;
      if (fd < 128)
        cur->open_f[fd] = file;
      if (fd == -1)
        {
          acquire_lock_file ();
          file_close (file);
          release_lock_file ();
        }
    }

  return fd;
}

/* Get the size of the file */
static int
syscall_filesize (struct intr_frame* fr)
{
  uint8_t *arg_base = (uint8_t *) fr->esp + sizeof (int);
  int fd;
  if (!get_arg_at_pos (arg_base, 0, &fd))
    thread_exit ();
  
  struct file *f;
  off_t size = 0;
  f = thread_current ()->open_f[fd];
  if (f != NULL) 
    {
      acquire_lock_file ();
      size = file_length (f);
      release_lock_file ();
    }
  return size;
}

/* Read bytes from the files to the buffer */
static int
syscall_read (struct intr_frame* f)
{
  uint8_t *arg_base = (uint8_t *) f->esp + sizeof (int);
  int fd;
  void *buffer;
  off_t size;
  off_t bytes_read = 0;

  get_arg_at_pos (arg_base, 0, &fd);
  get_arg_at_pos (arg_base, 1, (int *) &buffer);
  get_arg_at_pos (arg_base, 2, (int *) &size);
  is_user_vaddr (buffer);
  is_user_vaddr (buffer + size);
  if (buffer > buffer + size)
    thread_exit ();
  bool is_file = thread_current ()->open_f[fd] != NULL;
  if (is_file)
  {
    if (!lock_buffer (buffer, size, true))
      thread_exit ();
  }
  uint8_t chars;
  struct file *file;
  uint8_t *buffer_c = buffer;
  if (fd == 0)
  {
    while (bytes_read < size)
    {
      chars = input_getc ();
      if (chars == '\n')
        break;
      buffer_c[bytes_read++] = chars;
    }
  }
  else
  {
    file = thread_current ()->open_f[fd];
    if (file != NULL)
    {
      acquire_lock_file ();
      bytes_read = file_read (file, buffer_c, size);
      release_lock_file ();
    }
  }
  if (is_file)
  {
    unlock_buffer (buffer, size);
  }
  return bytes_read;
}

/* Write bytes from the buffer to the opened file */
static int
syscall_write (struct intr_frame* f)
{
  uint8_t *arg_base = (uint8_t *) f->esp + sizeof (int);
  int fd;
  const void *buffer;
  off_t size;
  off_t bytes_written = 0;
  
  get_arg_at_pos (arg_base, 0, &fd);
  get_arg_at_pos (arg_base, 1, (int *) &buffer);
  get_arg_at_pos (arg_base, 2, (int *) &size);
  is_user_vaddr (buffer);
  is_user_vaddr (buffer + size);
  if (buffer > buffer + size)
    thread_exit ();
  bool is_file = thread_current ()->open_f[fd] != NULL;
  if (is_file)
  {
    if (!lock_buffer (buffer, size, false))
      thread_exit ();

  }
  struct file *file;
  if (fd==1)
  {
    putbuf (buffer, size);
    bytes_written = size;
  }
  else
  {
    file = thread_current ()->open_f[fd];
    if (file != NULL)
    {
      acquire_lock_file ();
      bytes_written = file_write (file, buffer, size);
      release_lock_file ();
    }
  }
  if (is_file)
    unlock_buffer (buffer, size);  
  return bytes_written;
}

/* Change the next bute to be read or written in the file fd to a new
   position */
static int
syscall_seek (struct intr_frame* fr)
{
  uint8_t *arg_base = (uint8_t *) fr->esp + sizeof (int);
  int fd;
  int new_pos;
  get_arg_at_pos (arg_base, 0, &fd);
  get_arg_at_pos (arg_base, 1, (int *) &new_pos);
  
  struct file *f = thread_current ()->open_f[fd];
  if (f != NULL)
  {
    acquire_lock_file ();
    file_seek (f, (off_t) new_pos);
    release_lock_file ();
  }
  return 0;
}

/* Find the position where the next byte to be read or written in the opened
   file */
static int
syscall_tell (struct intr_frame* fr)
{
  int fd;
  get_arg_at_pos ((uint8_t *) fr->esp + sizeof (int), 0, &fd);
  
  struct file *f = thread_current ()->open_f[fd];
  off_t position = 0;
  if (f != NULL)
  {
    acquire_lock_file ();
    position = file_tell (f);
    release_lock_file ();
  }
  return position;
}

/* Closes the file and set its entry in the current thread to NULL */
static int
syscall_close (struct intr_frame* fr)
{
  int fd;
  get_arg_at_pos ((uint8_t *) fr->esp + sizeof (int), 0, &fd);
  
  struct thread *cur = thread_current ();
  struct file *f = cur->open_f[fd];
  if (f != NULL)
  {
    acquire_lock_file ();
    file_allow_write (f);
    file_close (f);
    release_lock_file ();
    cur->open_f[fd] = NULL;
  }
  return 0;
}

/* Maps the file located in esp of f to the user address space */
static int
syscall_mmap (struct intr_frame* f)
{
  int fd;
  void *vaddr;
  get_arg_at_pos ((uint8_t *) f->esp + sizeof (int), 0, &fd);
  get_arg_at_pos ((uint8_t *) f->esp + sizeof (int), 1, (int *) &vaddr);
  if (fd == 0 || fd == 1)
    return -1;
  
  /* Maps a file into the user address space starting at virtual address VADDR. */
  struct thread *cur = thread_current ();
  struct file *file = cur->open_f[fd];
  if (vaddr == 0 || pg_ofs (vaddr) != 0 || file == NULL)
    return -1;
  
  off_t len, ofs = 0;
  size_t n, i;
  len = file_length (file);
  // if ()
  //   return -1;
  n = ((size_t) pg_round_up ((const void *) len)) / PGSIZE;
  
  void *esp = cur->stck_ptr;
  void *upage;
  for (upage = vaddr, i = 0; i < n; i++, upage += PGSIZE)
  { 
    /* Check if we are accessing the stack */
    bool is_stack_acc = (upage >= MAX_STACK_SIZE && 
                  ((esp - upage) == 8 || (esp - upage) == 32 || upage >= esp));
    if (pagedir_get_info (cur->pagedir, upage) != NULL || is_stack_acc)
      return -1;
  }

  file = file_reopen (file);
  /* Get a map descriptor that stores info about the mapping */
  int md = 0;
  for (md = 0; md < 128; md++)
  {
    if (cur->mem_mapd_f[md].file == NULL)
      break;
  }
  if (md != 128)
  {
    cur->mem_mapd_f[md].upage = vaddr;
    cur->mem_mapd_f[md].file = file;
    cur->mem_mapd_f[md].mpd_pgs = n;
  }
  /* Set the page info with the right information */
  for (upage = vaddr, i = 0; i < n; i++, upage += PGSIZE)
  {
    struct page *page = (struct page *)calloc (1, sizeof *page);
    if (len <= PGSIZE)
      ofs += len;
    else
    {
      ofs += PGSIZE;
      len -= PGSIZE;
    }
    page->pg_dir = cur->pagedir;
    page->upage = upage;
    page->type = 0x04;
    page->writable = 0x01;
    page->file = file;
    page->offset = ofs;
    pagedir_set_info (cur->pagedir, upage, page);
  }
  if (i >= n)
    return md;
  n = i;
  i = 0;
  for (upage = vaddr; i < n; upage += PGSIZE)
  {
    frame_unload (cur->pagedir, upage);
    i++;
  }
  file_close (file);
  return -1;
}

/* Unmaps the file in esp of f from its address space */
static int
syscall_munmap (struct intr_frame* f)
{
  int md;
  get_arg_at_pos ((uint8_t *) f->esp + sizeof (int), 0, &md);
  return munmap (md);
}

/* Unmaps the memory mapping of the file located in md */
int 
munmap (int md)
{
  struct thread *cur = thread_current ();
  
  if (md < 0 || md > 128)
    return 0;
  struct mem_map *mmap = &cur->mem_mapd_f[md];
  if (mmap->file == NULL)
    return 0;
  void *upage = mmap->upage;
  size_t i = 0;
  while (i < mmap->mpd_pgs)
  {
    frame_unload (cur->pagedir, upage);
    i++;
    upage += PGSIZE;
  }
  file_close (mmap->file);
  mmap->file = NULL;
  return 0;
}

/* Check if a page faults occur from a stack access to grow the stack size */
void
grow_stack_if_sa (uint32_t *pd, const void *vaddr)
{
  struct page *page;
  void *upage = pg_round_down (vaddr);
  void *esp = thread_current ()->stck_ptr;
  /* if stack accesses happen right now */
  if (!(((esp - vaddr) == 8) || ((esp - vaddr) == 32) || (vaddr >= esp)))
    return;
  if (pagedir_get_info (pd, upage) == NULL && vaddr >= MAX_STACK_SIZE)
  {
    page = (struct page *)calloc (1, sizeof *page);
    if (page != NULL)
    {
      page->upage = pg_round_down (vaddr);
      page->pg_dir = pd;
      page->type = 0x01;
      page->writable = 0x02;
      pagedir_set_info (pd, upage, page);
    }
  }
}

/* Change the current working directory of the process based on the path */
static int 
syscall_chdir(struct intr_frame* f)
{
  char *path;
  get_arg_at_pos ((uint8_t *) f->esp + sizeof (int), 0, &path);
  return filesys_chdir (path);
}

/* Create the directory named dir */
static int 
syscall_mkdir(struct intr_frame* f) 
{
  char *dir;
  get_arg_at_pos ((uint8_t *) f->esp + sizeof (int), 0, &dir);
  return filesys_mkdir (dir, 0);
}

/* Reads a directory entry from fd */
static int
syscall_readdir(struct intr_frame* f)
{
  int fd;
  void *name;
  get_arg_at_pos ((uint8_t *) f->esp + sizeof (int), 0, &fd);
  get_arg_at_pos ((uint8_t *) f->esp + sizeof (int), 1, &name);
  if(!is_user_vaddr (name) || !is_user_vaddr (name + NAME_MAX + 1) || 
     name > name + NAME_MAX + 1)
     thread_exit ();
  return fd_readdir (fd, name);
}

/* Check if fd presents a directory */
static int
syscall_isdir(struct intr_frame* f)
{
  int fd;
  get_arg_at_pos ((uint8_t *) f->esp + sizeof (int), 0, &fd);
  return fd_isdir (fd);
}

/* Get the inode number of inode associated with fd */
static int
syscall_inumber(struct intr_frame* f)
{
  int fd;
  get_arg_at_pos ((uint8_t *) f->esp + sizeof (int), 0, &fd);
  return fd_inumber (fd);
}