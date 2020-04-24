#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define SYSCALL_EXIT_ERR -1 // System call error exit code

void syscall_init (void);
void sys_exit (int status);

#endif /* userprog/syscall.h */
