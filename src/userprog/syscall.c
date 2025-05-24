#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler(struct intr_frame*);

static bool validate_user_ptr(const void *);

static bool validate_range(const void *start, size_t size);

static bool validate_string(const char *str);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  if (!validate_range(f->esp, 4)) {
    exit(-1);
    NOT_REACHED();
  }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    if (!validate_range(f->esp + 4, 4)) {
      exit(-1);
      NOT_REACHED();
    }
    exit(args[1]);
    NOT_REACHED();
  } else if (args[0] == SYS_PRACTICE) {
    f->eax = practice(args[1]);
  } else if (args[0] == SYS_HALT) {
    halt();
    NOT_REACHED();
  } else if (args[0] == SYS_EXEC) {
    if (!validate_range(f->esp + 4, 4)) {
      exit(-1);
      NOT_REACHED();
    }
    f->eax = exec((char*) args[1]);
  } else if (args[0] == SYS_WAIT) {
    f->eax = wait(args[1]);
  } else if (args[0] == SYS_FORK) {
    f->eax = process_fork((char*) args[1], f);
  } else if (args[0] == SYS_CREATE) {
    if (!validate_range(f->esp + 4, 8) || !validate_string((char*) args[1])) {
      exit(-1);
      NOT_REACHED();
    }
    f->eax = create((char*) args[1], args[2]);
  } else if (args[0] == SYS_REMOVE) {
    if (!validate_range(f->esp + 4, 4) || !validate_string((char*) args[1])) {
      exit(-1);
      NOT_REACHED();
    }
    f->eax = remove((char*) args[1]);
  } else if (args[0] == SYS_OPEN) {
    if (!validate_range(f->esp + 4, 4) || !validate_string((char*) args[1])) {
      exit(-1);
      NOT_REACHED();
    }
    f->eax = open((char*) args[1]);
  } else if (args[0] == SYS_FILESIZE) {
    if (!validate_range(f->esp + 4, 4)) {
      exit(-1);
      NOT_REACHED();
    }
    f->eax = filesize(args[1]);
  } else if (args[0] == SYS_READ) {
    if (!validate_range(f->esp + 4, 12)) {
      exit(-1);
      NOT_REACHED();
    }
    int fd = (int) args[1];
    void* buffer = (void *) args[2];
    unsigned size = (unsigned) args[3];

    if (!validate_range(buffer, size)) {
      exit(-1);
      NOT_REACHED();
    }
    f->eax = read(fd, buffer, size);
  } else if (args[0] == SYS_WRITE) {
    if (!validate_range(f->esp + 4, 12)) {
      exit(-1);
      NOT_REACHED();
    }
    int fd = (int) args[1];
    void* buffer = (void *) args[2];
    unsigned size = (unsigned) args[3];

    if (!validate_range(buffer, size)) {
      exit(-1);
      NOT_REACHED();
    }
    f->eax = write(fd, buffer, size);
  } else if (args[0] == SYS_SEEK) {
    if (!validate_range(f->esp + 4, 8)) {
      exit(-1);
      NOT_REACHED();
    }
    seek(args[1], args[2]);
  } else if (args[0] == SYS_TELL) {
    if (!validate_range(f->esp + 4, 4)) {
      exit(-1);
      NOT_REACHED();
    }
    f->eax = tell(args[1]);
  } else if (args[0] == SYS_CLOSE) {
    if (!validate_range(f->esp + 4, 4)) {
      exit(-1);
      NOT_REACHED();
    }
    close(args[1]);
  } else {
    exit(-1);
    NOT_REACHED();
  }
}

/* Syscall wrappers that includes validating user pointers */

int exit(int status) {
  struct thread *cur = thread_current();
  cur->pcb->exit_status = status;  // Set status from syscall
  printf("%s: exit(%d)\n", cur->pcb->process_name, status);
  process_exit();  // process_exit() calls thread_exit() internally
  NOT_REACHED();   // Prevent compiler warnings
}

int practice(int num) {
  return num + 1;
}

void halt() {
  shutdown_power_off();
}

int exec(const char* file) {
  if (!validate_string(file)) {
    exit(-1);
    NOT_REACHED();
  }
  return process_execute(file);
}

int wait(int pid) {
  return process_wait(pid);
}

// int fork(const char* file, const struct intr_frame* f) {
//   return 0;
// }

bool create(const char* file, unsigned initial_size) {
  return filesys_create(file, initial_size);
}

bool remove(const char* file) {
  return filesys_remove(file);
}

int open(const char* file) {
  struct file* f = filesys_open(file);
  if (f == NULL) return -1; // Failed to open

  struct process* cur_process = thread_current()->pcb;
  int fd = STDERR_FILENO + 1;
  while (fd < FDT_SIZE && cur_process->fd_table[fd] != NULL) ++fd;
  if (fd >= FDT_SIZE) {
    file_close(f);
    return -1;
  }
  cur_process->fd_table[fd] = f;
  return fd;
}

int filesize(int fd) {
  if (fd >= FDT_SIZE || fd < 0) return -1;
  struct file *f = thread_current()->pcb->fd_table[fd];
  return f != NULL ? file_length(f) : -1;
}

int read(int fd, void* buffer, unsigned size) {
  if (fd >= FDT_SIZE || fd < 0) return -1;
  if (fd == STDIN_FILENO) {
    uint8_t* buf = buffer;
    for (size_t i=0; i<size; i++) {
      buf[i] = input_getc();
    }
    return size;
  }
    
  struct file* file = thread_current()->pcb->fd_table[fd];
  if (file == NULL) {
    return -1;
  }
  if (size > filesize(fd)) return -1;
  return file_read(file, buffer, size);
}

int write(int fd, const void* buffer, unsigned size) {
  if (fd >= FDT_SIZE || fd < 0) return -1;
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }

  struct file* file = thread_current()->pcb->fd_table[fd];
  if (file == NULL) {
    return -1;
  }
  
  return file_write(file, buffer, size);
}

int tell(int fd) {
  if (fd < 0 || fd >= FDT_SIZE) return -1;
  struct file* f = thread_current()->pcb->fd_table[fd];
  if (f == NULL) return -1;
  return file_tell(f);
}

void seek(int fd, unsigned position) {
  if (fd < 0 || fd >= FDT_SIZE) return;
  struct file* f = thread_current()->pcb->fd_table[fd];
  if (f == NULL) return;
  file_seek(f, position);
}

void close(int fd) {
  if (fd < 0 || fd >= FDT_SIZE) return;
  struct process* pcb = thread_current()->pcb;
  struct file* f = pcb->fd_table[fd];
  if (f != NULL) {
    file_close(f);
    pcb->fd_table[fd] = NULL;
  }
}

/* Helper functions for validating user given pointers */

static bool validate_user_ptr(const void *usr_ptr) {
  // If its not null or an address in user space
  if (usr_ptr == NULL || !is_user_vaddr(usr_ptr)) 
    return false;

  struct thread *cur = thread_current();
  void* page_base = pg_round_down(usr_ptr);

  // If ptr to page is NULL, means it does not reside in memory
  // Currently no demand paging implemented.
  // TODO implement demand paging
  if (pagedir_get_page(cur->pcb->pagedir, page_base) != NULL)
        return true;
  
  return false;
}

static bool validate_range(const void *start, size_t size) {
  const uint8_t *ptr = start;
  const uint8_t *end = ptr + size;

  while (ptr < end) {
      // Check if the current page is valid
      if (!validate_user_ptr(ptr)) {
          return false;
      }
      // Move to the next page
      ptr = pg_round_down(ptr) + PGSIZE;
  }
  return true;
}

static bool validate_string(const char *str) {
  if (str == NULL) {
      return false;
  }
  for (size_t i = 0; i < 4096; i++) {
      if (!validate_user_ptr(str + i)) {
          return false;
      }
      if (str[i] == '\0') {
          return true;
      }
  }
  return false; // Exceeds max length or no null terminator
}