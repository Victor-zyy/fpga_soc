#   Stage3
* file_private_cow.c: to see copy on write on file-backend mmap
* file_shared_visibility.c: to see MAP_SHARED and msync
* file_private_dontneed.c: cow after and then dontneed. finally read
* file_private_pfn.c: both mmap to file,if one writes COW without affecting another
* fork_anon_cow.c: parent and child to prove anonymous COW page
* rootfs_lifetime.c: mmap to file, even unlink and close fd dont release the inodethe contents still exist
