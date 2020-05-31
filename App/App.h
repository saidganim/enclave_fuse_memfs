/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

void edger8r_array_attributes(void);
void edger8r_type_attributes(void);
void edger8r_pointer_attributes(void);
void edger8r_function_attributes(void);

void ecall_libc_functions(void);
void ecall_libcxx_functions(void);
void ecall_thread_functions(void);


// fuse fs ecalls
static int ecall_createentry(const char *path, mode_t mode, struct node **node);
static int ecall_memfs_getattr(const char *path, struct stat *stbuf);
static int ecall_memfs_readlink(const char *path, char *buf, size_t size);
static int ecall_memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
static int ecall_memfs_mknod(const char *path, mode_t mode, dev_t rdev);
static int ecall_memfs_mkdir(const char *path, mode_t mode);
static int ecall_memfs_unlink(const char *path);
static int ecall_memfs_rmdir(const char *path);
static int ecall_memfs_symlink(const char *from, const char *to);
static int ecall_memfs_rename(const char *from, const char *to);
static int ecall_memfs_link(const char *from, const char *to);
static int ecall_memfs_chmod(const char *path, mode_t mode);
static int ecall_memfs_chown(const char *path, uid_t uid, gid_t gid);
static int ecall_memfs_utimens(const char *path, const struct timespec ts[2]);
static int ecall_memfs_truncate(const char *path, off_t size);
static int ecall_memfs_open(const char *path, struct fuse_file_info *fi);
static int ecall_memfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int ecall_memfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int ecall_memfs_release(const char *path, struct fuse_file_info *fi);


#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
