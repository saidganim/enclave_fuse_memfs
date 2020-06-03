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


#define FUSE_USE_VERSION 26
#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <fuse.h>


#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <libgen.h>

#include "node.h"
#include "dir.h"

#define BLOCKSIZE 4096

#define O_WRITE(flags) ((flags) & (O_RDWR | O_WRONLY))
#define O_READ(flags)  (((flags) & (O_RDWR | O_RDONLY)) | !O_WRITE(flags))

#define U_ATIME (1 << 0)
#define U_CTIME (1 << 1)
#define U_MTIME (1 << 2)

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

//
// Utility functions
//

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;



/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    FILE* fd = fopen("/home/said/fuse_enclave_logs", "a");
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];
    if(fd <= 0)
      return;
    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                fprintf(fd,"Info: %s\n", sgx_errlist[idx].sug);
            fprintf(fd,"Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}




/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}



extern "C"{

    struct filesystem {
    struct node *root;
    };

    struct filehandle {
    struct node *node;
    int o_flags;
    };

    struct filesystem the_fs;


char * safe_dirname(const char *msg) {
  char *buf = strdup(msg);
  char *dir = dirname(buf);
  char *res = strdup(dir);
  free(buf);
  return res;
}

char * safe_basename(const char *msg) {
  char *buf = strdup(msg);
  char *nam = basename(buf);
  char *res = strdup(nam);
  free(buf);
  return res;
}

int getnodebypath(const char *path, struct filesystem *fs, struct node **node) {
  return getnoderelativeto(path, fs->root, node);
}

static void update_times(struct node *node, int which) {
  time_t now = time(0);
  if(which & U_ATIME) node->vstat.st_atime = now;
  if(which & U_CTIME) node->vstat.st_ctime = now;
  if(which & U_MTIME) node->vstat.st_mtime = now;
}

static int initstat(struct node *node, mode_t mode) {
  struct stat *stbuf = &node->vstat;
  memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_mode  = mode;
  stbuf->st_nlink = 0;
  update_times(node, U_ATIME | U_MTIME | U_CTIME);
  return 1;
}

static int createentry(const char *path, mode_t mode, struct node **node) {
  char *dirpath = safe_dirname(path);

  // Find parent node
  struct node *dir;
  int ret = getnodebypath(dirpath, &the_fs, &dir);
  free(dirpath);
  if(!ret) {
    return -errno;
  }

  // Create new node
  *node = (struct node*)malloc(sizeof(struct node));
  if(!*node) {
    return -ENOMEM;
  }

  (*node)->fd_count = 0;
  (*node)->delete_on_close = 0;

  // Initialize stats
  if(!initstat(*node, mode)) {
    free(*node);
    return -errno;
  }

  struct fuse_context *ctx = fuse_get_context();
  (*node)->vstat.st_uid = ctx->uid;
  (*node)->vstat.st_gid = ctx->gid;

  // Add to parent directory
  if(!dir_add_alloc(dir, safe_basename(path), *node, 0)) {
    free(*node);
    return -errno;
  }

  return 0;
}


static int memfs_getattr(const char *path, struct stat *stbuf) {
  struct node *node;
  if(!getnodebypath(path, &the_fs, &node)) {
    return -errno;
  }

  stbuf->st_mode   = node->vstat.st_mode;
  stbuf->st_nlink  = node->vstat.st_nlink;
  stbuf->st_size   = node->vstat.st_size;
  stbuf->st_blocks = node->vstat.st_blocks;
  stbuf->st_uid    = node->vstat.st_uid;
  stbuf->st_gid    = node->vstat.st_gid;
  stbuf->st_mtime  = node->vstat.st_mtime;
  stbuf->st_atime  = node->vstat.st_atime;
  stbuf->st_ctime  = node->vstat.st_ctime;

  // Directories contain the implicit hardlink '.'
  if(S_ISDIR(node->vstat.st_mode)) {
    stbuf->st_nlink++;
  }

  return 0;
}

static int memfs_readlink(const char *path, char *buf, size_t size) {
  struct node *node;
  if(!getnodebypath(path, &the_fs, &node)) {
    return -errno;
  }

  if(!S_ISLNK(node->vstat.st_mode)) {
    return -ENOLINK;
  }

  // Fuse breaks compatibility with other readlink() implementations as we cannot use the return
  // value to indicate how many bytes were written. Instead, we need to null-terminate the string,
  // unless the buffer is not large enough to hold the path. In that case, fuse will null-terminate
  // the string before passing it on.

  if(node->vstat.st_size > size) {
    memcpy(buf, node->data, size);
  } else {
    strcpy(buf, (char*)node->data);
  }

  return 0;
}

static int memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  struct node *dir;
  if(!getnodebypath(path, &the_fs, &dir)) {
    return -errno;
  }

  if(!S_ISDIR(dir->vstat.st_mode)) {
    return -ENOTDIR;
  }

  filler(buf, ".",  &dir->vstat, 0);
  if(dir == the_fs.root) {
    filler(buf, "..", NULL, 0);
  } else {
    char *parent_path = safe_dirname(path);
    struct node *parent;
    getnodebypath(parent_path, &the_fs, &parent);
    free(parent_path);
    filler(buf, "..", &parent->vstat, 0);
  }

  struct direntry *entry = (struct direntry*)dir->data;
  while(entry != NULL) {
    if(filler(buf, entry->name, &entry->node->vstat, 0))
      break;
    entry = entry->next;
  }

  return 0;
}

static int memfs_mknod(const char *path, mode_t mode, dev_t rdev) {
  struct node *node;
  int res = createentry(path, mode, &node);
  if(res) return res;

  if(S_ISREG(mode)) {
    node->data = NULL;
    node->vstat.st_blocks = 0;
  } else {
    return -ENOSYS;
  }

  return 0;
}

static int memfs_mkdir(const char *path, mode_t mode) {
  struct node *node;
  int res = createentry(path, S_IFDIR | mode, &node);
  if(res) return res;

  // No entries
  node->data = NULL;

  return 0;
}

static int memfs_unlink(const char *path) {
  char *dirpath, *name;
  struct node *dir, *node;

  // Find inode
  if(!getnodebypath(path, &the_fs, &node)) {
    return -errno;
  }

  if(S_ISDIR(node->vstat.st_mode)) {
    return -EISDIR;
  }

  dirpath = safe_dirname(path);

  // Find parent inode
  if(!getnodebypath(dirpath, &the_fs, &dir)) {
    free(dirpath);
    return -errno;
  }

  free(dirpath);

  name = safe_basename(path);

  // Find directory entry in parent
  if(!dir_remove(dir, name)) {
    free(name);
    return -errno;
  }

  free(name);

  // If the link count is zero, delete the associated data
  if(node->vstat.st_nlink == 0) {
    if(node->fd_count == 0) {
      // No open file descriptors, we can safely delete the node
      if(node->data) free(node->data);
      free(node);
    } else {
      // There are open file descriptors, schedule deletion
      node->delete_on_close = 1;
    }
  }

  return 0;
}

static int memfs_rmdir(const char *path) {
  char *dirpath, *name;
  struct node *dir, *node;

  // Find inode
  if(!getnodebypath(path, &the_fs, &node)) {
    return -errno;
  }

  if(!S_ISDIR(node->vstat.st_mode)) {
    return -ENOTDIR;
  }

  // Check if directory is empty
  if(node->data != NULL) {
    return -ENOTEMPTY;
  }

  dirpath = safe_dirname(path);

  // Find parent inode
  if(!getnodebypath(dirpath, &the_fs, &dir)) {
    free(dirpath);
    return -errno;
  }

  free(dirpath);

  name = safe_basename(path);

  // Find directory entry in parent
  if(!dir_remove(dir, name)) {
    free(name);
    return -errno;
  }

  free(name);

  free(node);

  return 0;
}

static int memfs_symlink(const char *from, const char *to) {
  struct node *node;
  int res = createentry(to, S_IFLNK | 0766, &node);
  if(res) return res;

  node->data = strdup(from);
  node->vstat.st_size = strlen(from);

  return 0;
}

// TODO: Adapt to description: https://linux.die.net/man/2/rename
static int memfs_rename(const char *from, const char *to) {
  char *fromdir, *fromnam, *todir, *tonam;
  struct node *node, *fromdirnode, *todirnode;

  if(!getnodebypath(from, &the_fs, &node)) {
    return -errno;
  }

  fromdir = safe_dirname(from);

  if(!getnodebypath(fromdir, &the_fs, &fromdirnode)) {
    free(fromdir);
    return -errno;
  }

  free(fromdir);

  todir = safe_dirname(to);

  if(!getnodebypath(todir, &the_fs, &todirnode)) {
    free(todir);
    return -errno;
  }

  free(todir);

  tonam = safe_basename(to);

  // TODO: When replacing, perform the same things as when unlinking
  if(!dir_add_alloc(todirnode, tonam, node, 1)) {
    free(tonam);
    return -errno;
  }

  free(tonam);

  fromnam = safe_basename(from);

  if(!dir_remove(fromdirnode, fromnam)) {
    free(fromnam);
    return -errno;
  }

  free(fromnam);

  return 0;
}

static int memfs_link(const char *from, const char *to) {
  char *todir, *tonam;
  struct node *node, *todirnode;

  if(!getnodebypath(from, &the_fs, &node)) {
    return -errno;
  }

  todir = safe_dirname(to);

  if(!getnodebypath(todir, &the_fs, &todirnode)) {
    free(todir);
    return -errno;
  }

  free(todir);

  tonam = safe_basename(to);

  if(!dir_add_alloc(todirnode, tonam, node, 0)) {
    free(tonam);
    return -errno;
  }

  free(tonam);

  return 0;
}

static int memfs_chmod(const char *path, mode_t mode) {
  struct node *node;
  if(!getnodebypath(path, &the_fs, &node)) {
    return -errno;
  }

  mode_t mask = S_ISUID | S_ISGID | S_ISVTX |
                S_IRUSR | S_IWUSR | S_IXUSR |
                S_IRGRP | S_IWGRP | S_IXGRP |
                S_IROTH | S_IWOTH | S_IXOTH;

  node->vstat.st_mode = (node->vstat.st_mode & ~mask) | (mode & mask);

  update_times(node, U_CTIME);

  return 0;
}

static int memfs_chown(const char *path, uid_t uid, gid_t gid) {
  struct node *node;
  if(!getnodebypath(path, &the_fs, &node)) {
    return -errno;
  }

  node->vstat.st_uid = uid;
  node->vstat.st_gid = gid;

  update_times(node, U_CTIME);

  return 0;
}

static int memfs_utimens(const char *path, const struct timespec ts[2]) {
  struct node *node;
  if(!getnodebypath(path, &the_fs, &node)) {
    return -errno;
  }

  node->vstat.st_atime = ts[0].tv_sec;
  node->vstat.st_mtime = ts[1].tv_sec;

  return 0;
}

static int memfs_truncate(const char *path, off_t size) {
  struct node *node;
  if(!getnodebypath(path, &the_fs, &node)) {
    return -errno;
  }
  int res;
  sgx_status_t sgxres = ecall_memfs_truncate(global_eid, &res, (long long)path, size);
  if(sgxres != SGX_SUCCESS){
    print_error_message(sgxres);
    return -EBADF;
  }
  update_times(node, U_CTIME | U_MTIME);
  return res;
}

static int memfs_open(const char *path, struct fuse_file_info *fi) {
  struct node *node;
  if(!getnodebypath(path, &the_fs, &node)) {
    return -errno;
  }

  if(!S_ISREG(node->vstat.st_mode)) {
    if(S_ISDIR(node->vstat.st_mode)) {
      return -EISDIR;
    }
  }

  // Update file timestamps
  update_times(node, U_ATIME);

  // The "file handle" is a pointer to a struct we use to keep track of the inode and the
  // flags passed to open().
  struct filehandle *fh = (struct filehandle*)malloc(sizeof(struct filehandle));
  fh->node    = node;
  fh->o_flags = fi->flags;

  fi->fh = (uint64_t) fh;
  int res;
  ecall_memfs_open(global_eid, &res, (long long)path, (long long)fi);
  node->fd_count++;

  return 0;
}

static int memfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  struct filehandle *fh = (struct filehandle *) fi->fh;
  int res = 0;
  struct node *node = fh->node;
  // Check whether the file was opened for reading
  
  if(!O_READ(fh->o_flags)) {
    return -EACCES;
  }
  sgx_status_t sgxres = ecall_memfs_read(global_eid, &res, (long long)path, (long long)buf, size, offset, (long long)fi);
  if(sgxres != SGX_SUCCESS){
     print_error_message(sgxres);
    return -EBADF;
  }
  if(res > 0) 
    update_times(node, U_ATIME);
  return res;
}

static int memfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  struct filehandle *fh = (struct filehandle *) fi->fh;
  int res = 0;
  struct node *node = fh->node;
  // Check whether the file was opened for writing
  if(!O_WRITE(fh->o_flags)) {
    return -EACCES;
  }
  
  int sgxres = ecall_memfs_write(global_eid, &res, (long long)path, (long long)buf, size, offset, (long long)fi);
  if(sgxres != SGX_SUCCESS)
    return -EBADF;
  if(res > 0) update_times(node, U_CTIME | U_MTIME);
  // Update file size if necessary
  off_t minsize = offset + size;
  if(minsize > node->vstat.st_size) {
    node->vstat.st_size = minsize;
  }
  return res;
}

static int memfs_release(const char *path, struct fuse_file_info *fi) {
  struct filehandle *fh = (struct filehandle *) fi->fh;

  // If the file was deleted but we could not free it due to open file descriptors,
  // free the node and its data after all file descriptors have been closed.
  if(--fh->node->fd_count == 0) {
    if(fh->node->delete_on_close) {
      if(fh->node->data) free(fh->node->data);
      free(fh->node);
    }
  }

  // Free "file handle"
  free(fh);

  return 0;
}

static void* init_enclave_fs(struct fuse_conn_info *conn){
    FILE* fd = fopen("/home/said/fuse_enclave_logs", "a");
    fprintf(fd, "ENCLAVE MOUNT TRYING\n");
    fclose(fd);
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return NULL; 
    }
    fd = fopen("/home/said/fuse_enclave_logs", "a");
    fprintf(fd, "ENCLAVE MOUNT SUCCESS\n");
    fflush(fd);

    return NULL;

}

void destroy_enclave_fs(void*){
  sgx_destroy_enclave(global_eid);
}

    static struct fuse_operations memfs_oper = {
    .getattr      = memfs_getattr,
    .readlink     = memfs_readlink,
    .getdir       = NULL,
    .mknod        = memfs_mknod,
    .mkdir        = memfs_mkdir,
    .unlink       = memfs_unlink,
    .rmdir        = memfs_rmdir,
    .symlink      = memfs_symlink,
    .rename       = memfs_rename,
    .link         = memfs_link,
    .chmod        = memfs_chmod,
    .chown        = memfs_chown,
    .truncate     = memfs_truncate,
    .open         = memfs_open,
    .read         = memfs_read,
    .write        = memfs_write,
    .statfs       = NULL,
    .flush        = NULL,
    .release      = memfs_release,
    .fsync        = NULL,
    .setxattr     = NULL,
    .getxattr     = NULL,
    .listxattr    = NULL,
    .removexattr  = NULL,
    .opendir      = NULL,
    .readdir      = memfs_readdir,
    .releasedir   = NULL,
    .fsyncdir     = NULL,
    .init         = init_enclave_fs,
    .destroy      = destroy_enclave_fs,
    .access       = NULL,
    .utimens      = memfs_utimens,
    };

};

//
// Filesystem entry points
//






/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
 
    struct node *root = (struct node*) malloc(sizeof(struct node));

    memset(root, 0, sizeof(struct node));
    initstat(root, S_IFDIR | 0755);
    root->vstat.st_uid = getuid();
    root->vstat.st_gid = getgid();

    // No entries
    root->data = NULL;

    // Set root directory of filesystem
    the_fs.root = root;

    umask(0);
    return fuse_main(argc, argv, &memfs_oper, NULL);
}

