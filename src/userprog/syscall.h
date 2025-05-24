#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init(void);

int exit(int status);
int practice(int num);
void halt();
int exec(const char* file);
int wait(int pid);
// int fork(const char* file, const struct intr_frame* f);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);
void close(int fd);
// void seek(int fd, unsigned position);
// unsigned tell(int fd);

#endif /* userprog/syscall.h */
