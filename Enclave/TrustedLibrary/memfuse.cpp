
#include <string.h>
#include "sgx_cpuid.h"

#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"

// #define NDEBUG
#include <iostream>
#include <math.h>
#include <map>
#include <string>
#include <string.h>
#include <cassert>
#include <errno.h>

#define BLOBSZ (512U)
//
// Filesystem entry points
//
template<int blobSize>
class BlobFile{
    

  private:
    struct chunks{
      struct chunks* next = nullptr;
      char blob[blobSize] = {{0}};
    };
    unsigned long long size = blobSize;
    unsigned long long allocated_chnks = 1;
    struct chunks chnks;

  public:
    void extend(int new_size){
        new_size = (new_size + blobSize - 1) / blobSize*blobSize;
      if(size >= new_size)
        return;
      struct chunks* currchnk = &chnks;

      while(currchnk->next)
        currchnk = currchnk->next;
      while(size < new_size){
        currchnk->next = new chunks;
        currchnk = currchnk->next;
        size += blobSize;
        ++allocated_chnks;
      }
    };

    int read(void* buf, size_t length, size_t offset){
        struct chunks* currchnk = &chnks;
        size_t curroffset = 0;
        size_t len = length;
        if(offset >= size)
          return 0;
        if(len+offset >= size)
          length = len = size - offset;
        while((curroffset+blobSize <= offset) && currchnk){
          curroffset += blobSize;
          assert(currchnk->next != nullptr);
          currchnk = currchnk->next;
        }
        curroffset += offset % blobSize;

        while((len > 0) && currchnk){
          size_t shift = std::min(len, blobSize - (curroffset % blobSize));
          memcpy(buf, &currchnk->blob[curroffset % blobSize], shift);
          currchnk = currchnk->next;
          curroffset += shift;
          buf += shift;
          len -= shift;
        }
        return length;
    }

    void truncate(){
      struct chunks* currchnk = &chnks;
      while(currchnk != nullptr){
          memset(currchnk->blob, 0x0, blobSize);
          currchnk = currchnk->next;
      }
    }

    int modify(size_t offset, std::string content){
      if(size < offset + content.length())
        extend(offset+content.length());
      
      struct chunks* currchnk = &chnks;
      size_t curroff = 0;
      while(curroff+blobSize <= offset){
        curroff += blobSize;
        assert(currchnk->next != nullptr);
        currchnk = currchnk->next;
      }

      curroff += offset % blobSize;
      const char* str = content.c_str();
      size_t towrite = content.length();
      while(towrite > 0){
        assert(currchnk != nullptr);
        size_t shift = std::min(towrite, blobSize - (curroff % blobSize));
        memcpy(&(currchnk->blob[curroff % blobSize]), str, shift);
        str += shift;
        curroff += shift;
        towrite -= shift;
        currchnk = currchnk->next;
      }
    }  

    // void print_file(){
    //     struct chunks* currchnk = &chnks;
    //     while(currchnk != nullptr){
    //         char buff[blobSize + 1];
    //         memcpy(buff, currchnk->blob, blobSize);
    //         buff[blobSize] = 0;
    //         std::cout<<buff;
    //         currchnk = currchnk->next;
    //     }
    //     std::cout<<std::endl;
    // }
};

std::map<std::string , BlobFile<BLOBSZ>*> filesStorage;



//
// Filesystem entry points
//



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
  const char* path = (const char*)enpathp;
  if(filesStorage.count(std::string(path)) != 0){
    BlobFile<BLOBSZ>* oldFile = filesStorage[std::string(path)];
    filesStorage.erase(std::string(path));
    delete oldFile;
  }

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
  const char* path = (const char*)enpathp;
  if(filesStorage.count(std::string(path)) != 0){
    BlobFile<BLOBSZ>* file = filesStorage[std::string(path)];
    file->truncate();
  }

  return 0;
}

int ecall_memfs_open(long long enpathp , long long enfip) {
  const char* path = (const char*)enpathp;
  BlobFile<BLOBSZ>* newFile = new BlobFile<BLOBSZ>;
  if(filesStorage.count(std::string(path)) == 0){
    filesStorage.emplace(std::string(path), newFile);
  }
  return 0;
}

int ecall_memfs_read(long long enpathp , long long enbufp, size_t size, long long offset, long long enfip) {
  const char* path = (const char*)enpathp;
  if(filesStorage.count(std::string(path)) != 0){
    BlobFile<BLOBSZ>* file = filesStorage[std::string(path)];
    return file->read((void*)enbufp, size, offset);
  }
  return -EBADF;
}

int ecall_memfs_write(long long enpathp , long long enbufp, size_t size, long long offset, long long enfip) {
  const char* path = (const char*)enpathp;
  
  if(filesStorage.count(std::string(path)) == 0){
    BlobFile<BLOBSZ>* newFile = new BlobFile<BLOBSZ>;
    filesStorage.emplace(std::string(path), newFile);
  }
  
  BlobFile<BLOBSZ>* file = filesStorage[std::string(path)];
  file->modify(offset, std::string((char*)enbufp, size));

  return size;
}

int ecall_memfs_release(long long enpathp , long long enfip) {
 
  return 0;
}