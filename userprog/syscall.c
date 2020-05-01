#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h" // shutdown_power_off()
#include "devices/input.h"    // input_getc()
#include "userprog/process.h" // process_*()
#include "lib/user/syscall.h" // pid_t
#include "filesys/off_t.h"    // off_t
#include "filesys/filesys.h"  // filesys_*()
#include "filesys/file.h"     // file_*()

#define SYSCALL_ARGC_MAX 3  // Max number of arguments that a syscall takes

/* Table to map a system call with the number of arguments it takes
 *
 * Read the entry of this array corresponding to the system call number to find
 * the number of arguments that system call takes.
 */
static const uint8_t syscall_argc[20] = {
  0,  // SYS_HALT
  1,  // SYS_EXIT
  1,  // SYS_EXEC
  1,  // SYS_WAIT
  2,  // SYS_CREATE
  1,  // SYS_REMOVE
  1,  // SYS_OPEN
  1,  // SYS_FILESIZE
  3,  // SYS_READ
  3,  // SYS_WRITE
  2,  // SYS_SEEK
  1,  // SYS_TELL
  1,  // SYS_CLOSE
  0,  // SYS_MMAP
  0,  // SYS_MUNMAP
  0,  // SYS_CHDIR
  0,  // SYS_MKDIR
  0,  // SYS_READDIR
  0,  // SYS_ISDIR
  0   // SYS_INUMBER
};

static void syscall_handler (struct intr_frame *);
void sys_halt (void);
void sys_exit (int status);
pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, void *buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);

void
syscall_init (void)
{
  // Initialize filesystem lock
  lock_init(&fs_lock);

  // Register a handler for TRAP (interrupt 0x30)
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* System call handler
 *
 * Read the necessary arguments from the stack, and call the routine related to
 * the system call called.
 */
static void
syscall_handler (struct intr_frame *f UNUSED)
{
  uint32_t callNo;
  uint32_t *user_esp = f->esp;
  uint32_t argv[SYSCALL_ARGC_MAX];

  // Get the system call number
  callNo = (uint32_t)(*user_esp);

  /* Get the syscall arguments from the stack
   *
   * In first iteration, we move the user_esp pointer down one word to skip the
   * system call number. Then, we get the first argument. In the next
   * iterations, we repeat those steps until we have fetched all the arguments.
   * The total number of arguments is fetched from the syscal_argc table.
   */
  for (int i=0; i<syscall_argc[callNo]; ++i) {
    // Move pointer down 1 word
    user_esp++;

    // Check we don't access kernel memory
    if ((void *)user_esp >= PHYS_BASE) {
      // We went over the PHYS_BASE, so kill the user process
      sys_exit(-1);
    }

    // Save argument value to argv
    argv[i] = (uint32_t)(*user_esp);
  }

  // Act according to the syscall
  switch(callNo) {
    case SYS_HALT:    // Shutdown machine
      sys_halt();
      break;
    case SYS_EXIT:
      sys_exit((int)argv[0]);
      break;
    case SYS_EXEC:
      f->eax = sys_exec((const char *)argv[0]);
      break;
    case SYS_WAIT:
      f->eax = sys_wait((pid_t)argv[0]);
      break;
    case SYS_CREATE:
      f->eax = sys_create((const char *)argv[0], (unsigned)argv[1]);
      break;
    case SYS_REMOVE:
      f->eax = sys_remove((const char *)argv[0]);
      break;
    case SYS_OPEN:
      f->eax =  sys_open((const char *)argv[0]);
      break;
    case SYS_FILESIZE:
      f->eax = sys_filesize((int)argv[0]);
      break;
    case SYS_READ:
      f->eax = sys_read((int)argv[0], (void *)argv[1], (unsigned)argv[2]);
      break;
    case SYS_WRITE:   // Called to output to either a file or stdout
      f->eax = sys_write((int)argv[0], (void *)argv[1], (unsigned)argv[2]);
      break;
    case SYS_SEEK:
      sys_seek((int)argv[0], (unsigned)argv[1]);
      break;
    case SYS_TELL:
      f->eax = sys_tell((int)argv[0]);
      break;
    case SYS_CLOSE:
      sys_close((int)argv[0]);
      break;
  }
}

/* Reads a byte at user virtual address UADDR.
 * 
 * UADDR must be below PHYS_BASE.
 * 
 * Returns the byte value if successful, -1 if a segfault occurred.
 */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
 * 
 * UDST must be below PHYS_BASE.
 * 
 * Returns true if successful, false if a segfault occurred.
 */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Checks if buffer is valid for reading
 *
 * Checks if a buffer pointer is below the PHYS_BASE, and if we can read from
 * the first and last bytes in the buffer.
 *
 * \param pointer Pointer to buffer to check
 * \param size    Size of buffer in bytes
 * \return  True if buffer is valid for reading, false otherwise
 */
static bool is_valid_read_pt(void *buffer, int size) {
  uint8_t *pt = (uint8_t *)buffer;

  // Check for NULL pointer
  if (buffer == NULL) {
    return false;
  }

  // Check if pointer is below PHYS_BASE
  if (buffer >= PHYS_BASE || buffer+size >= PHYS_BASE) {
    return false;
  }
  
  // Check if we can read from the first byte in buffer
  if (get_user((const uint8_t *)pt) == -1) {
    return false;
  }
  
  if (size > 1) {
    for (int i=0; i<size-1; ++i) {  // Move pointer to last byte in buffer
      ++pt;
    }

    // Check if we can read from the last byte in buffer
    if (get_user((const uint8_t *)pt) == -1) {
      return false;
    }
  }

  return true;
}

/* Checks if the buffer is valid for writing
 *
 * Checks if a buffer pointer is below the PHYS_BASE, and if we can write to
 * the first and last bytes in the buffer.
 *
 * \param pointer Pointer to buffer to check
 * \param size    Size of buffer in bytes
 * \return  True if buffer is valid for writing, false otherwise
 */
static bool is_valid_write_pt(void *buffer, int size) {
  uint8_t *pt = (uint8_t *)buffer;

  // Check for NULL pointer
  if (buffer == NULL) {
    return false;
  }

  // Check if pointer is below PHYS_BASE
  if (buffer >= PHYS_BASE || buffer+size >= PHYS_BASE) {
    return false;
  }
  
  // Check if we can write to the first byte in buffer
  if (!put_user(pt, 0)) {
    return false;
  }
  
  if (size > 1) {
    for (int i=0; i<size-1; ++i) {  // Move pointer to last byte in buffer
      ++pt;
    }

    // Check if we can read the last location in buffer
    if (!put_user(pt, 0)) {
      return false;
    }
  }

  return true;
}

/* System Call: void halt (void)
 * 
 * Terminates Pintos by calling shutdown_power_off() (declared in
 * threads/init.h). This should be seldom used, because you lose some
 * information about possible deadlock situations, etc.
 */
void sys_halt(void) {
  shutdown_power_off();
}

/* System Call: void exit (int status)
 *
 * Terminates the current user program, returning status to the kernel. If the
 * process's parent waits for it (see below), this is the status that will be
 * returned. Conventionally, a status of 0 indicates success and nonzero values
 * indicate errors.
 */
void sys_exit (int status) {
  struct thread *current_thread = thread_current();

  current_thread->exit_status = status;
  printf("%s: exit(%d)\n", current_thread->name, status);

  // Cleanup and de-allocation and waiting for parent to reap exit status
  thread_exit();
}

/* System Call: pid_t exec (const char *cmd_line)
 *
 * Runs the executable whose name is given in cmd_line, passing any given
 * arguments, and returns the new process's program id (pid). Must return pid
 * -1, which otherwise should not be a valid pid, if the program cannot load or
 * run for any reason. Thus, the parent process cannot return from the exec 
 * until it knows whether the child process successfully loaded its executable.
 * You must use appropriate synchronization to ensure this.
 */
pid_t sys_exec (const char *cmd_line) {
  pid_t pid = -1;
  uint8_t buf_size;

  // Check for bad FILE pointer
  if (cmd_line != NULL) {
    buf_size = (uint8_t)(strlen(cmd_line) + 1);
  } else {
    sys_exit(SYSCALL_EXIT_ERR);
    return (pid);
  }
  if (!is_valid_read_pt((void *)cmd_line, buf_size)) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (pid);
  }

  // The `process_execute()` function does all we need
  return (pid_t)process_execute(cmd_line);
}

/* System Call: int wait (pid_t pid)
 *
 * Waits for a child process pid and retrieves the child's exit status.
 *
 * If pid is still alive, waits until it terminates. Then, returns the status
 * that pid passed to exit. If pid did not call exit(), but was terminated by
 * the kernel (e.g. killed due to an exception), wait(pid) must return -1. It
 * is perfectly legal for a parent process to wait for child processes that
 * have already terminated by the time the parent calls wait, but the kernel
 * must still allow the parent to retrieve its child's exit status, or learn
 * that the child was terminated by the kernel.
 *
 * wait must fail and return -1 immediately if any of the following conditions
 * is true:
 *
 * - `pid` does not refer to a direct child of the calling process. `pid` is a
 *   direct child of the calling process if and only if the calling process
 *   received pid as a return value from a successful call to exec.
 *
 *   Note that children are not inherited: if A spawns child B and B spawns
 *   child process C, then A cannot wait for C, even if B is dead. A call to
 *   wait(C) by process A must fail. Similarly, orphaned processes are not
 *   assigned to a new parent if their parent process exits before they do.
 *
 * - The process that calls wait has already called wait on pid. That is, a
 *   process may wait for any given child at most once.
 *
 * Processes may spawn any number of children, wait for them in any order, and
 * may even exit without having waited for some or all of their children. Your
 * design should consider all the ways in which waits can occur. All of a
 * process's resources, including its struct thread, must be freed whether its
 * parent ever waits for it or not, and regardless of whether the child exits
 * before or after its parent.
 *
 * You must ensure that Pintos does not terminate until the initial process
 * exits. The supplied Pintos code tries to do this by calling process_wait()
 * (in userprog/process.c) from main() (in threads/init.c). We suggest that you
 * implement process_wait() according to the comment at the top of the function
 * and then implement the wait system call in terms of process_wait().
 *
 * Implementing this system call requires considerably more work than any of
 * the rest.
 */
int sys_wait (pid_t pid) {
  // The process_wait() function does all we need
  return process_wait((tid_t)pid);
}

/* System Call: bool create (const char *file, unsigned initial_size)
 *
 * Creates a new file called file initially initial_size bytes in size. Returns
 * true if successful, false otherwise. Creating a new file does not open it:
 * opening the new file is a separate operation which would require a open
 * system call.
 */
bool sys_create (const char *file, unsigned initial_size) {
  bool created = false;
  uint8_t buf_size;

  // Check for bad FILE pointer
  if (file != NULL) {
    buf_size = (uint8_t)(strlen(file) + 1);
  } else {
    sys_exit(SYSCALL_EXIT_ERR);
    return (created);
  }
  if (!is_valid_read_pt((void *)file, buf_size)) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (created);
  }

  // Use filesys interface to create a new file in the filesystem
  lock_acquire(&fs_lock);
  created = filesys_create(file, (off_t)initial_size);
  lock_release(&fs_lock);
  
  return (created);
}

/* System Call: bool remove (const char *file)
 *
 * Deletes the file called file. Returns true if successful, false otherwise.
 * A file may be removed regardless of whether it is open or closed, and
 * removing an open file does not close it. See Removing an Open File, for
 * details.
 */
bool sys_remove (const char *file) {
  bool removed = false;
  uint8_t buf_size;

  // Check for bad FILE pointer
  if (file != NULL) {
    buf_size = (uint8_t)(strlen(file) + 1);
  } else {
    sys_exit(SYSCALL_EXIT_ERR);
    return (removed);
  }
  if (!is_valid_read_pt((void *)file, buf_size)) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (removed);
  }

  // Use filesys interface to remove a file from the filesystem
  lock_acquire(&fs_lock);
  removed = filesys_remove(file);
  lock_release(&fs_lock);

  return (removed);
}

/* System Call: int open (const char *file)
 *
 * Opens the file called file. Returns a nonnegative integer handle called a
 * "file descriptor" (fd), or -1 if the file could not be opened.
 *
 * File descriptors numbered 0 and 1 are reserved for the console: fd 0
 * (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output.
 * The open system call will never return either of these file descriptors,
 * which are valid as system call arguments only as explicitly described below.
 *
 * Each process has an independent set of file descriptors. File descriptors
 * are not inherited by child processes.
 *
 * When a single file is opened more than once, whether by a single process or
 * different processes, each open returns a new file descriptor. Different file
 * descriptors for a single file are closed independently in separate calls to
 * close and they do not share a file position.
 */
int sys_open (const char *file) {
  int fd = -1;
  struct file *file_pt;
  uint8_t buf_size;

  // Check for bad FILE pointer
  if (file != NULL) {
    buf_size = (uint8_t)(strlen(file) + 1);
  } else {
    sys_exit(SYSCALL_EXIT_ERR);
    return (fd);
  }
  if (!is_valid_read_pt((void *)file, buf_size)) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (fd);
  }

  // Use filesys interface to remove a file from the filesystem
  lock_acquire(&fs_lock);
  file_pt = filesys_open(file);
  if (file_pt != NULL) {
    fd = thread_fd_add(thread_current(), file_pt);
  }
  lock_release(&fs_lock);

  return (fd);
}

/* System Call: int filesize (int fd)
 *
 * Returns the size, in bytes, of the file open as fd.
 */
int sys_filesize (int fd) {
  int size = -1;
  struct thread *th = thread_current();
  
  // Check the file descriptor exists in the FDT
  if (fd < 0 || fd >= th->fd_tab_next || th->fd_tab[fd] == NULL) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (size);
  }

  lock_acquire(&fs_lock);
  size = (int) file_length(th->fd_tab[fd]);
  lock_release(&fs_lock);

  return (size);
}

/* System Call: int read (int fd, void *buffer, unsigned size)
 *
 * Reads size bytes from the file open as fd into buffer. Returns the number of
 * bytes actually read (0 at end of file), or -1 if the file could not be read
 * (due to a condition other than end of file). Fd 0 reads from the keyboard
 * using input_getc().
 */
int sys_read (int fd, void *buffer, unsigned size) {
  int rb = 0;
  uint8_t buf_size;
  struct thread *th = thread_current();

  // If size is 0 there us nothing to read
  if (size == 0) {
    return (rb);
  }

  // Check for bad FILE pointer
  buf_size =  (uint8_t)size;
  if (!is_valid_write_pt(buffer, buf_size)) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (rb);
  }
  
  // Special cases to handle stdin and stdout
  if (fd == 0) { // Stdin
    char in_char = '\0';  // Initialize to any value to pass first while check
    char *buf = (char *)buffer;

    /* The `input_getc()` function reads 1 char at the time from the stdin.
     * Use it on a loop until we detect the user pressing the [Enter] key. This
     * will produce a `\n` char in Unix or `\r\n` in Windows systems.
     */
    while (in_char != '\n') {
      in_char = input_getc(); // Get input char from stdin
      buf[rb] = in_char;      // Write char to buffer
      ++rb;                   // Increase read byte count
    }
    
    return (rb);
  } else if (fd == 1) { // Stdout
    return (rb);
  }

  // Check the file descriptor exists in the FDT
  if (fd < 0 || fd >= th->fd_tab_next || th->fd_tab[fd] == NULL) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (rb);
  }
  
  // Write data to other fds
  lock_acquire(&fs_lock);
  rb = (int) file_read(th->fd_tab[fd], buffer, (off_t)size);
  lock_release(&fs_lock);

  return (rb);
}

/* System Call: int write (int fd, const void *buffer, unsigned size)
 *
 * Writes size bytes from buffer to the open file fd. Returns the number of
 * bytes actually written, which may be less than size if some bytes could not
 * be written. Writing past end-of-file would normally extend the file, but
 * file growth is not implemented by the basic file system. The expected
 * behavior is to write as many bytes as possible up to end-of-file and return
 * the actual number written, or 0 if no bytes could be written at all.
 *
 * Fd 1 writes to the console. Your code to write to the console should write
 * all of buffer in one call to putbuf(), at least as long as size is not
 * bigger than a few hundred bytes. (It is reasonable to break up larger
 * buffers.) Otherwise, lines of text output by different processes may end up
 * interleaved on the console, confusing both human readers and our grading
 * scripts.
 */
int sys_write(int fd, void *buffer, unsigned size) {
  int wb = 0;
  uint8_t buf_size;
  struct thread *th = thread_current();

  // If size is 0 there us nothing to write
  if (size == 0) {
    return (wb);
  }

  // Check for bad FILE pointer
  buf_size = (uint8_t)size;
  if (!is_valid_read_pt(buffer, buf_size)) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (wb);
  }
  
  // Special cases to handle stdin and stdout
  if (fd == 0) {  // Stdin
    return (wb);
  } else if (fd == 1) { // Stdout
    putbuf(buffer, size);
    wb = (int)size;
    return (wb);
  }

  // Check the file descriptor exists in the FDT
  if (fd < 0 || fd >= th->fd_tab_next || th->fd_tab[fd] == NULL) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (wb);
  }
  
  // Write data to other fds
  lock_acquire(&fs_lock);
  wb = (int) file_write(th->fd_tab[fd], buffer, (off_t)size);
  lock_release(&fs_lock);

  return (wb);
}

/* System Call: void seek (int fd, unsigned position)
 * 
 * Changes the next byte to be read or written in open file fd to position,
 * expressed in bytes from the beginning of the file. (Thus, a position of 0 is
 * the file's start.)
 *
 * A seek past the current end of a file is not an error. A later read obtains
 * 0 bytes, indicating end of file. A later write extends the file, filling any
 * unwritten gap with zeros. (However, in Pintos files have a fixed length
 * until project 4 is complete, so writes past end of file will return an
 * error.) These semantics are implemented in the file system and do not
 * require any special effort in system call implementation.
 */
void sys_seek (int fd, unsigned position) {
  struct thread *th = thread_current();
  
  // Check the file descriptor exists in the FDT
  if (fd < 0 || fd >= th->fd_tab_next || th->fd_tab[fd] == NULL) {
    sys_exit(SYSCALL_EXIT_ERR);
  }

  lock_acquire(&fs_lock);
  file_seek(th->fd_tab[fd], (off_t)position);
  lock_release(&fs_lock);
}

/* System Call: unsigned tell (int fd)
 *
 * Returns the position of the next byte to be read or written in open file fd,
 * expressed in bytes from the beginning of the file.
 */
unsigned sys_tell (int fd) {
  unsigned result = 0;
  struct thread *th = thread_current();
  
  // Check the file descriptor exists in the FDT
  if (fd < 0 || fd >= th->fd_tab_next || th->fd_tab[fd] == NULL) {
    sys_exit(SYSCALL_EXIT_ERR);
    return (result);
  }

  lock_acquire(&fs_lock);
  result = (unsigned) file_tell(th->fd_tab[fd]);
  lock_release(&fs_lock);

  return (result);
}

/* System Call: void close (int fd)
 *
 * Closes file descriptor fd. Exiting or terminating a process implicitly
 * closes all its open file descriptors, as if by calling this function for
 * each one.
 */
void sys_close (int fd) {
  struct thread *th = thread_current();
  
  // Check the file descriptor exists in the FDT
  if (fd < 0 || fd >= th->fd_tab_next || th->fd_tab[fd] == NULL) {
    sys_exit(SYSCALL_EXIT_ERR);
  }

  lock_acquire(&fs_lock);
  file_close(th->fd_tab[fd]);
  thread_fd_remove(th, fd);
  lock_release(&fs_lock);
}

