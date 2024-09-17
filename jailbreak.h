#pragma once
#ifndef _JAILBREAK_HH
#define _JAILBREAK_HH

#include <stdint.h>
#include "defs.h"

// Structure representing jailbreak credentials.
// This structure is used to hold credential information for a process in the 
// jailbreak context. It contains user and group identifiers, as well as pointers
// to key filesystem and security structures.
struct jbc_cred {
    uid_t uid;            // Effective user ID of the process.
    uid_t ruid;           // Real user ID of the process.
    uid_t svuid;          // Saved user ID, used for privilege management.
    gid_t rgid;           // Real group ID of the process.
    gid_t svgid;          // Saved group ID, used for group privilege management.
    uintptr_t prison;     // Pointer to the prison structure, representing the process's jail or container.
    uintptr_t cdir;       // Pointer to the current working directory vnode.
    uintptr_t rdir;       // Pointer to the root directory vnode, typically "/" or a jail's root.
    uintptr_t jdir;       // Pointer to the jail directory vnode, representing the jail's root.
    uint64_t sceProcType; // The type of the process, used to identify system processes.
    uint64_t sonyCred;    // Sony-specific credential value, related to process security levels.
    uint64_t sceProcCap;  // Capability flags for the process, controlling access to certain system functions.
};


uintptr_t jbc_get_prison0(void);
uintptr_t jbc_get_rootvnode(void);
int jbc_get_cred(struct jbc_cred*);
int jbc_jailbreak_cred(struct jbc_cred*);
int jbc_set_cred(const struct jbc_cred*);

#endif
