#   Stage2. demand pageing and fault

* demand_paging.c: test touched / read / write once to twice to see what happens, like minor fault RSS, zero_page -> anonymous page
* access_cost.c: test zero_path and direct write path cycles
* page_scale.c: test VMPTE grows between the size of pages we touched
* zero_pfn.c: to judge the mmap only read page is mapped to the same physical page
* populate_test.c: to test MAP_POPULATE attribute in mmap flags it will prefill the PTE rather than kernel fill after faults.
* dontneed_test.c: test madvise function call, it will drop the pages and reserve the page table
* mlock/munlock: mlock and mlock2(xxxMLOCK_ONFAULT)
* pgtlife_time.c: madvise/munmap/mmap stuff the VmPTE and RSS 
