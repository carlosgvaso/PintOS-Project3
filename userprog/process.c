#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
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
#include "threads/synch.h"
#include "threads/malloc.h"

#define LOGGING_LEVEL 6

#include <log.h>

typedef struct cmd_ {
  char *cmd_str;
  char **argv;
  int argc;
} cmd_t;

// FIXME: These semaphores should be per thread semaphores, and they belong in the thread struct.
struct semaphore launched;
struct semaphore exiting;

static thread_func start_process NO_RETURN;
static bool load (cmd_t *cmd, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   COMMAND. The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *command)
{
  char *cmd_copy, *save_ptr, *token;
  char cmd_name[16];  // Same lenght as thread name in struct thread
  cmd_t cmd;
  tid_t tid;

  // NOTE:
  // To see this print, make sure LOGGING_LEVEL in this file is <= L_TRACE (6)
  // AND LOGGING_ENABLE = 1 in lib/log.h
  // Also, probably won't pass with logging enabled.
  log(L_TRACE, "Started process execute: %s", command);

  /* Make a copy of COMMAND.
     Otherwise there's a race between the caller and load(). */
  cmd_copy = palloc_get_page (0);
  if (cmd_copy == NULL)
    return TID_ERROR;
  strlcpy (cmd_copy, command, PGSIZE);

  /* Parse the command
   * Use `strtok_r()` to find all the white-space separated tokens (words), and
   * save pointers to those tokens in an array. The array is dynamically
   * allocated, so DO NOT forget to free it after your are done usign it.
   */ 
  cmd.cmd_str = cmd_copy;
  cmd.argv = (char **) malloc(sizeof(char *));
  cmd.argc = 0;

  for (token = strtok_r (cmd.cmd_str, " ", &save_ptr); token != NULL;
      token = strtok_r (NULL, " ", &save_ptr)) {
    // Don't grow argv in the first iteration
    if (cmd.argc > 0) {
      // Grow argv to fit the new token
      cmd.argv = (char **) realloc(cmd.argv, (cmd.argc + 1) * sizeof(char *));
    }
    cmd.argv[cmd.argc] = token; // Save token pointer in argv
    ++(cmd.argc);               // Increment argc
  }

  // Copy first argument to a buffer to use as thread name
  strlcpy(cmd_name, cmd.argv[0], (strlen(cmd.argv[0]) + 1));

  sema_init(&launched, 0); // FIXME: should be t->launched when the semaphore is added to the threads struct
  sema_init(&exiting, 0);  // FIXME: should be t->exiting when the semaphore is added to the threads struct

  /* Create a new thread to execute COMMAND. */
  tid = thread_create (cmd_name, PRI_DEFAULT, start_process, &cmd);
  if (tid == TID_ERROR)
    palloc_free_page (cmd_copy);

  sema_down(&launched); // FIXME: should be t->launched when the semaphore is added to the threads struct

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *command_)
{
  /* Make a copy of the command as this thread's local variable to ensure it
   * doesn't get overwritten if process_execute get's called again. We are
   * responsible for freeing any dynamically allocated stuff in COMMAND_ from
   * here on.
   */
  cmd_t cmd = *(cmd_t *)command_;
  struct intr_frame if_;
  bool success;
  struct thread *th = thread_current();

  log(L_TRACE, "start_process()");

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (&cmd, &if_.eip, &if_.esp);

  // Set up the process' File Descriptor Table
  th->fd_tab[0] = NULL;  // Add stdin
  th->fd_tab[1] = NULL;  // Add stdout
  th->fd_tab[2] = NULL;  // Add stderr
  th->fd_tab_next = 3;

  /* If load failed, quit. */
  palloc_free_page (cmd.cmd_str); // Free page
  free(cmd.argv);  // Free dynamically allocated array
  if (!success)
    thread_exit ();

  sema_up(&launched); // FIXME: should be t->launched when the semaphore is added to the threads struct

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
   been successfully called for the given TID, returns -
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED)
{
  // Wait for child process to exit, and reap its exit status
  sema_down(&exiting); // FIXME: should be t->exiting when the semaphore is added to the threads struct

  // Here the child has exited. Get the childs exit status from its thread and return it

  // FIXME: Return the child exit status
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  sema_up(&exiting); // FIXME: should be t->launched when the semaphore is added to the threads struct
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

static bool setup_stack (cmd_t *cmd, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (cmd_t *cmd, void (**eip) (void), void **esp)
{
  log(L_TRACE, "load()");
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* The file to be opened and loaded is the first token of the cmd_str.
   * Since cmd_str was tokenized in process_execute(), the command should be
   * in the first argument (`cmd->argv[0]`).
   */
  const char *file_name = cmd->argv[0];

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
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
          if (validate_segment (&phdr, file))
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
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (cmd, esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
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

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  log(L_TRACE, "load_segment()");

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory.
  
   Must populate the stack with arguments: Ret_addr(0):argc:argv:argv[0]:
   argv[1]... */
static bool
setup_stack (cmd_t *cmd, void **esp)
{
  uint8_t *kpage;
  bool success = false;

  log(L_TRACE, "setup_stack()");

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
        *esp = PHYS_BASE;

        char *argv_stack[cmd->argc];  // Track location of arguments in stack
        char *espchar;                // char address in stack
        uint32_t *espword;            // word address in stack
        int len_tok = 0;  // Token length including trailing `\0`
        int len_stk = 0;  // Total cmd length in stack including all `\0` chars

        // Add arguments to stack
        for (int i=cmd->argc-1; i>=0; --i) {
          len_tok = strlen(cmd->argv[i]) + 1; // Find length of argument + `\0`
          *esp -= len_tok;    // Move esp ponter to fit argument in stack
          len_stk += len_tok; // Sum to total length of string
          strlcpy(*esp, cmd->argv[i], len_tok); // Copy argument to stack
          argv_stack[i] = (char *) (*esp);  // Save argument's stack address
        }

        /* Add padding if needed
           The formula used to find the bytes required to align the start of
           the string is: (aling - (offset mod aling)) mod aling */
        espchar = (char *) (*esp);  // Point token to the current top of stack
        for (int i=0; i<((4 - (len_stk % 4)) % 4); ++i) {
          *esp -= 1;    // Move top of stack to fit byte
          espchar--;    // Move pointer to fit byte
          *espchar = 0; // Add padding byte
        }
        
        // Add argv[] to stack
        *esp -= 4;  // Move top of stack to fit NULL last argv entry
        espword = (uint32_t *) (*esp);  // Move pointer to top of stack
        *espword = 0;                   // Add NULL last argv entry
        
        for (int i=cmd->argc-1; i>=0; --i) {  // Add pointers to all arguments
          *esp -= 4;  // Move top of stack to fit a word
          espword--;  // Move pointer to fit a word
          *espword = (uint32_t) argv_stack[i];  // Add pointer to argv[i] addr in stack
        }
        
        char *argvptr = (char *) espword; // Save argv[0] address
        *esp -= 4;                        // Move top of stack to fit a word
        espword--;                        // Move pointer to fit a word
        *espword = (uint32_t) argvptr;    // Add argv pointer to argv[0]
        
        // Add argc to stack
        *esp -= 4;            // Move top of stack to fit a word
        espword--;            // Move pointer to fit a word
        *espword = cmd->argc; // Add argc to stack
        
        // Add return address to stack
        *esp -= 4;    // Move top of stack to fit a word
        espword--;    // Move pointer to fit a word
        *espword = 0; // TODO: Add return address to stack
      }
      else {
        palloc_free_page (kpage);
      }
      // hex_dump( *(int*)esp, *esp, 128, true ); // NOTE: uncomment this to check arg passing
    }
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
