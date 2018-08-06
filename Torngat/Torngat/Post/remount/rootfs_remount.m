//
//  rootfs_remount.cpp
//  electra1131
//
//  Created by CoolStar on 6/7/18.
//  Copyright © 2018 CoolStar. All rights reserved.
//

#include <stdio.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <Foundation/Foundation.h>
#include "rootfs_remount.h"
#include "kmem.h"
#include "ku.h"
#include "patchfinder64.h"
#include "kexecute.h"
#include "offsetof.h"
#include "apfs_util.h"
#define file_exists(fname) (access(fname, 0) == 0)
#define cp(to, from) copyfile(from, to, 0, COPYFILE_ALL)

struct hfs_mount_args {
    char    *fspec;            /* block special device to mount */
    uid_t    hfs_uid;        /* uid that owns hfs files (standard HFS only) */
    gid_t    hfs_gid;        /* gid that owns hfs files (standard HFS only) */
    mode_t    hfs_mask;        /* mask to be applied for hfs perms  (standard HFS only) */
    u_int32_t hfs_encoding;    /* encoding for this volume (standard HFS only) */
    struct    timezone hfs_timezone;    /* user time zone info (standard HFS only) */
    int        flags;            /* mounting flags, see below */
    int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
    int        journal_flags;          /* flags to pass to journal_open/create */
    int        journal_disable;        /* don't use journaling (potentially dangerous) */
};

uint64_t offset_vfs_context_current;
uint64_t offset_vnode_lookup;
uint64_t offset_vnode_put;

#define ROOTFSTESTFILE "/.bit_of_fun"
#define ROOTFSMNT "/var/rootfsmnt"

uint64_t get_vfs_context() {
    // vfs_context_t vfs_context_current(void)
    uint64_t vfs_context = kexecute(offset_vfs_context_current, 1, 0, 0, 0, 0, 0, 0);
    vfs_context = zm_fix_addr(vfs_context);
    return vfs_context;
}

int vnode_lookup(const char *path, int flags, uint64_t *vpp, uint64_t vfs_context){
    size_t len = strlen(path) + 1;
    
    uint64_t vnode = kalloc(sizeof(uint64_t));
    
    uint64_t ks = kalloc(len);
    kwrite(ks, path, len);
    
    int ret = (int)kexecute(offset_vnode_lookup, ks, 0, vnode, vfs_context, 0, 0, 0);
    if (ret != 0) {
        return -1;
    }
    
    *vpp = rk64(vnode);
    kfree(ks, len);
    kfree(vnode, sizeof(uint64_t));
    return 0;
}

int vnode_put(uint64_t vnode){
    return (int)kexecute(offset_vnode_put, vnode, 0, 0, 0, 0, 0, 0);
}

uint64_t getVnodeAtPath(uint64_t vfs_context, char *path){
    uint64_t *vpp = (uint64_t *)malloc(sizeof(uint64_t));
    int ret = vnode_lookup(path, O_RDONLY, vpp, vfs_context);
    if (ret != 0){
        printf("unable to get vnode from path for %s\n", path);
        return -1;
    }
    uint64_t vnode = *vpp;
    free(vpp);
    
    return vnode;
}

void dumpContentsOfDir(char *path);

int mountDevAsRWAtPath(char *dev, char *path) {
    struct hfs_mount_args mntargs;
    bzero(&mntargs, sizeof(struct hfs_mount_args));
    mntargs.fspec = dev;
    mntargs.hfs_mask = 1;
    gettimeofday(NULL, &mntargs.hfs_timezone);

    int rvtmp = mount("apfs", path, 0, (void *)&mntargs);
    printf("mounting: %d\n", rvtmp);
    return rvtmp;
}

int remountRootAsRW_old() {
    uint64_t _rootvnode = find_rootvnode();
    uint64_t rootfs_vnode = rk64(_rootvnode);
    uint64_t v_mount = rk64(rootfs_vnode + offsetof_v_mount);
    uint32_t v_flag = rk32(v_mount + offsetof_mnt_flag);
    
    v_flag = v_flag & ~MNT_NOSUID;
    v_flag = v_flag & ~MNT_RDONLY;
    wk32(v_mount + offsetof_mnt_flag, v_flag & ~MNT_ROOTFS);
    
    char *dev_path = strdup("/dev/disk0s1s1");
    int rv = mount("apfs", "/", MNT_UPDATE, (void *)&dev_path);
    printf("remount2: %d\n", rv);
    
    v_mount = rk64(rootfs_vnode + offsetof_v_mount);
    wk32(v_mount + offsetof_mnt_flag, v_flag);
    
    if (file_exists(ROOTFSTESTFILE)){
        printf("Found previous test.. unlinking.\n");
        unlink(ROOTFSTESTFILE);
    }
    
    int fd = open(ROOTFSTESTFILE, O_RDONLY);
    if (fd == -1) {
        fd = creat(ROOTFSTESTFILE, 0644);
    } else {
        printf("File already exists!\n");
    }
    close(fd);
    
    printf("Did we mount / as read+write? %s\n", file_exists(ROOTFSTESTFILE) ? "yes" : "no");
    return 0;
}

int remountRootAsRW(uint64_t slide, uint64_t kern_proc, uint64_t our_proc, int snapshot_success){
    if (kCFCoreFoundationVersionNumber <= 1451.51 || snapshot_success == 0){
        return remountRootAsRW_old();
    }
    
    if (!getOffsets(slide)){
        return -1;
    }
    
    uint64_t kernucred = rk64(kern_proc+offsetof_p_ucred);
    uint64_t ourucred = rk64(our_proc+offsetof_p_ucred);
     
    uint64_t vfs_context = get_vfs_context();
    
    char *dev_path = "/dev/disk0s1s1";
    uint64_t devVnode = getVnodeAtPath(vfs_context, dev_path);
    uint64_t specInfo = rk64(devVnode + offsetof_v_specinfo);
    
    wk32(specInfo + offsetof_si_flags, 0); //clear dev vnode's v_specflags
    
    if (file_exists(ROOTFSMNT))
        rmdir(ROOTFSMNT);
    
    mkdir(ROOTFSMNT, 0755);
    chown(ROOTFSMNT, 0, 0);
    
    printf("Temporarily setting kern ucred\n");
    
    wk64(our_proc+offsetof_p_ucred, kernucred);
    
    int rv = -1;
    
    if (mountDevAsRWAtPath(dev_path, ROOTFSMNT) != ERR_SUCCESS) {
        printf("Error mounting root at %s\n", ROOTFSMNT);
        
        goto out;
    }
    
    /* APFS snapshot mitigation bypass bug by CoolStar, exploitation by Pwn20wnd */
    /* Disables the new APFS snapshot mitigations introduced in iOS 11.3 */
    
    printf("Disabling the APFS snapshot mitigations\n");
    
    const char *systemSnapshot = find_system_snapshot(ROOTFSMNT);
    const char *newSystemSnapshot = "orig-fs";
    
    if (!systemSnapshot) {
        goto out;
    }
    
    int rvrename = do_rename(ROOTFSMNT, systemSnapshot, newSystemSnapshot);
    
    if (rvrename) {
        goto out;
    }
    
    rv = 0;
    
    unmount(ROOTFSMNT, 0);
    rmdir(ROOTFSMNT);
    
out:
    printf("Restoring our ucred\n");
    
    wk64(our_proc+offsetof_p_ucred, ourucred);
    
    //cleanup
    vnode_put(devVnode);
    
    if (!rv) {
        printf("Disabled the APFS snapshot mitigations\n");
        
        printf("Restarting\n");
        sleep(2);
        reboot(0x400);
    } else {
        printf("Failed to disable the APFS snapshot mitigations\n");
    }
    
    return -1;
}
