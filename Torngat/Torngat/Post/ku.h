//
//  fun_utils.h
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef fun_utils_h
#define fun_utils_h

#include <stdio.h>
#include <mach-o/loader.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <mach/mach.h>
#include <sys/stat.h>

// Needed definitions
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

// "General" purpose
uint8_t *get_sha256(uint8_t* code_dir);
uint8_t *get_code_directory(const char* name);
int cp(const char *from, const char *to);

// Kernel utility stuff
void init_kernel_utils(mach_port_t tfp0);
uint64_t kalloc(vm_size_t size);
uint32_t kread32(uint64_t where);
uint64_t kread64(uint64_t where);
void kwrite32(uint64_t where, uint32_t what);
void kwrite64(uint64_t where, uint64_t what);
uint64_t proc_for_pid(pid_t pid);
uint64_t proc_for_name(char *nm);
unsigned int pid_for_name(char *nm);
uint64_t find_port_address(mach_port_name_t port);
uint64_t task_self_addr(void);
uint64_t kmem_alloc_wired(uint64_t size);
uint64_t find_kernproc(void);
#define kfree(addr, size) mach_vm_deallocate(tfp0, addr, size)
uint64_t zm_fix_addr(uint64_t addr);
#endif /* fun_utils_h */
