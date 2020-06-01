
#include <string.h>
#include "sgx_cpuid.h"

#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"
#define BLOBSZ (512U)


//
// Filesystem entry points
//
template<int blobSize>
class BlobFile{
    

  private:
    struct chunks{
      struct chunks* next;
      char blob[blobSize];
    }
    unsigned long long size;
    struct chunks;
};

std::map<String, BlobFile<BLOBSZ>> filesStorage;



int ecall_memfs_getattr(long long enpathp, long long enstbufp) {
  return 0;
}

int ecall_memfs_readlink(long long enpathp, long long enbufp, size_t size) {
  
  return 0;
}

int ecall_memfs_readdir(long long enpathp, long long enbufp, long long enfillerp, long long offset, long long enfip) {
 
  return 0;
}

int ecall_memfs_mknod(long long enpathp , long long mode, long long rdev) {
  
  return 0;
}

int ecall_memfs_mkdir(long long enpathp , long long mode) {
  return 0;
}

int ecall_memfs_unlink(long long enpathp ) {

  return 0;
}

int ecall_memfs_rmdir(long long enpathp ) {
  
  return 0;
}

int ecall_memfs_symlink(long long enfromp, long long entop) {
 
  return 0;
}

int ecall_memfs_link(long long enfromp, long long entop) {
  
  return 0;
}

int ecall_memfs_chmod(long long enpathp , long long mode) {
  
  return 0;
}

int ecall_memfs_chown(long long enpathp , long long uid, long long gid) {
 
  return 0;
}

int ecall_memfs_utimens(long long enpathp , long long entsp) {
 
  return 0;
}

int ecall_memfs_truncate(long long enpathp , long long size) {
 
  return 0;
}

int ecall_memfs_open(long long enpathp , long long enfip) {
  const char* path = (const char*)enpathp;
  if(!filesStorage.contains(string(path)){
    filesStorage.
  }
  return 0;
}

int ecall_memfs_read(long long enpathp , long long enbufp, size_t size, long long offset, long long enfip) {
 
  return size;
}

int ecall_memfs_write(long long enpathp , long long enbufp, size_t size, long long offset, long long enfip) {
  
  return size;
}

int ecall_memfs_release(long long enpathp , long long enfip) {
 
  return 0;
}