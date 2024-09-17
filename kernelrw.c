#include <stdarg.h>
#include <stdbool.h>
#include "kernelrw.h"

/**
 * k_kcall - Kernel helper function to perform a call with up to 6 arguments.
 * 
 * @td: Thread data (unused).
 * @uap: User arguments, where the first element is the function pointer and the rest are its arguments.
 * 
 * This function is used internally by the `kexec` assembly function to call a specified
 * function in the kernel with up to six arguments. The result of the call is stored back
 * in the first argument.
 * 
 * Returns:
 *  Always returns 0.
 */
static int k_kcall(void *td, uint64_t **uap) {
    uint64_t *args = uap[1];
    // Call the function with the arguments provided and store the result in args[0].
    args[0] = ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))args[0])
        (args[1], args[2], args[3], args[4], args[5], args[6]);
    return 0;
}

// Assembly code for making a system call into the kernel.
// This uses syscall number 11 and the address in rcx.
asm("kexec:\nmov $11, %rax\nmov %rcx, %r10\nsyscall\nret");
void kexec(void *, void *);

/**
 * jbc_krw_kcall - Perform a kernel call with variable arguments.
 * 
 * @fn: The function pointer to call in the kernel.
 * @...: Up to 6 additional arguments to pass to the function.
 * 
 * This function allows calling a kernel function with up to six arguments by using `kexec`.
 * 
 * Returns:
 *  The return value of the kernel function called.
 */
uint64_t jbc_krw_kcall(uint64_t fn, ...) {
    va_list v;
    va_start(v, fn);
    uint64_t uap[7] = { fn }; // Array to hold the function pointer and arguments.
    
    // Extract up to 6 arguments from the variable arguments list.
    for (int i = 1; i <= 6; i++)
        uap[i] = va_arg(v, uint64_t);
    
    // Execute the kernel function call using `kexec`.
    kexec(k_kcall, uap);
    va_end(v);
    return uap[0];
}

// Assembly code to get the current thread descriptor from the %gs segment register.
asm("k_get_td:\nmov %gs:0, %rax\nret");
extern char k_get_td[];

/**
 * jbc_krw_get_td - Retrieve the current thread descriptor (TD).
 * 
 * This function calls a kernel function to get the current thread descriptor,
 * which is a structure that holds thread-specific information in FreeBSD.
 * 
 * Returns:
 *  The current thread descriptor pointer.
 */
uintptr_t jbc_krw_get_td(void) {
    return jbc_krw_kcall((uintptr_t)k_get_td);
}

// State variables for detecting the presence of Mira.
static int have_mira = -1;
static int mira_socket[2];

/**
 * do_check_mira - Check if Mira (a homebrew enabler) is present.
 * 
 * This function checks if the Mira homebrew enabler is present by attempting
 * to create a socket pair and perform a read/write operation on it.
 * 
 * Returns:
 *  1 if Mira is present,
 *  0 otherwise.
 */
static int do_check_mira(void) {
    // Create a socket pair for inter-process communication.
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, mira_socket))
        return 0;
    
    // Write a byte to the socket using the current thread descriptor as data.
    if (write(mira_socket[1], (void *)jbc_krw_get_td(), 1) == 1) {
        char c;
        // Read a byte from the socket, indicating Mira's presence.
        read(mira_socket[0], &c, 1);
        return 1;
    }
    return 0;
}

/**
 * check_mira - Check if Mira is available.
 * 
 * This is an inline function to cache the result of `do_check_mira`.
 * 
 * Returns:
 *  True if Mira is available,
 *  False otherwise.
 */
static inline bool check_mira(void) {
    if (have_mira < 0)
        have_mira = do_check_mira();
    return (bool)have_mira;
}

/**
 * check_ptr - Check if a pointer is within a valid memory region.
 * 
 * @p: The pointer to check.
 * @kind: The type of memory region to check against.
 * 
 * This function checks if a given pointer falls within the expected range for
 * user space, kernel heap, or kernel text regions.
 * 
 * Returns:
 *  True if the pointer is within the specified region,
 *  False otherwise.
 */
static inline bool check_ptr(uintptr_t p, KmemKind kind) {
    if (kind == USERSPACE)
        return p < 0x800000000000; // User space pointers are below this address.
    else if (kind == KERNEL_HEAP)
        return p >= 0xffff800000000000 && p < 0xffffffff00000000;
    else if (kind == KERNEL_TEXT)
        return p >= 0xffffffff00000000 && p < 0xfffffffffffff000;
    else
        return false;
}

/**
 * kcpy_mira - Copy memory using Mira.
 * 
 * @dst: Destination address.
 * @src: Source address.
 * @sz: Size of the memory to copy.
 * 
 * This function uses the Mira socket to copy memory between the kernel and user space.
 * It transfers data in chunks of up to 64 bytes.
 * 
 * Returns:
 *  0 on success,
 * -1 on failure.
 */
static int kcpy_mira(uintptr_t dst, uintptr_t src, size_t sz) {
    while (sz > 0) {
        size_t chk = (sz > 64 ? 64 : sz);
        // Write the source data to Mira.
        if (write(mira_socket[1], (void *)src, chk) != chk)
            return -1;
        // Read the copied data from Mira into the destination.
        if (read(mira_socket[0], (void *)dst, chk) != chk)
            return -1;
        dst += chk;
        src += chk;
        sz -= chk;
    }
    return 0;
}

// Assembly function for copying memory.
asm("k_kcpy:\nmov %rdx, %rcx\nrep movsb\nret");
extern char k_kcpy[];

/**
 * jbc_krw_memcpy - Copy memory between kernel and user space.
 * 
 * @dst: Destination address.
 * @src: Source address.
 * @sz: Size of the memory to copy.
 * @kind: The type of memory region.
 * 
 * This function copies memory between kernel and user space, using different
 * methods depending on whether Mira is present and the type of memory.
 * 
 * Returns:
 *  0 on success,
 * -1 on failure.
 */
int jbc_krw_memcpy(uintptr_t dst, uintptr_t src, size_t sz, KmemKind kind) {
    if (sz == 0)
        return 0;

    // Check if the destination and source pointers are within the correct regions.
    bool u1 = check_ptr(dst, USERSPACE) && check_ptr(dst + sz - 1, USERSPACE);
    bool ok1 = check_ptr(dst, kind) && check_ptr(dst + sz - 1, kind);
    bool u2 = check_ptr(src, USERSPACE) && check_ptr(src + sz - 1, USERSPACE);
    bool ok2 = check_ptr(src, kind) && check_ptr(src + sz - 1, kind);

    // Ensure that the pointers are either both in user space or both in the specified kind.
    if (!((u1 || ok1) && (u2 || ok2)))
        return -1;

    // If both pointers are in user space, this operation is not allowed.
    if (u1 && u2)
        return -1;

    // Use Mira for copying if available.
    if (check_mira())
        return kcpy_mira(dst, src, sz);

    // Otherwise, perform the memory copy in kernel space.
    jbc_krw_kcall((uintptr_t)k_kcpy, dst, src, sz);
    return 0;
}

/**
 * jbc_krw_read64 - Read a 64-bit value from memory.
 * 
 * @p: The pointer to read from.
 * @kind: The type of memory region.
 * 
 * This function reads a 64-bit value from the specified memory region.
 * 
 * Returns:
 *  The value read on success,
 * -1 on failure.
 */
uint64_t jbc_krw_read64(uintptr_t p, KmemKind kind) {
    uint64_t ans;
    // Use jbc_krw_memcpy to read the 64-bit value from the specified memory region.
    if (jbc_krw_memcpy((uintptr_t)&ans, p, sizeof(ans), kind))
        return -1;
    return ans;
}

/**
 * jbc_krw_write64 - Write a 64-bit value to memory.
 * 
 * @p: The pointer to write to.
 * @kind: The type of memory region.
 * @val: The value to write.
 * 
 * This function writes a 64-bit value to the specified memory region.
 * 
 * Returns:
 *  0 on success,
 * -1 on failure.
 */
int jbc_krw_write64(uintptr_t p, KmemKind kind, uintptr_t val) {
    // Use jbc_krw_memcpy to write the 64-bit value to the specified memory region.
    return jbc_krw_memcpy(p, (uintptr_t)&val, sizeof(val), kind);
}
