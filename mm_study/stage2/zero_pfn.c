#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGEMAP_PRESENT   (1ULL << 63)
#define PAGEMAP_PFN_MASK  ((1ULL << 55) - 1)
#define KPF_ZERO_PAGE     24

static volatile uint64_t read_sink;

static int read_u64_at(int fd, off_t offset, uint64_t * value)
{
	ssize_t ret = pread(fd, value, sizeof(*value), offset);

	if (ret < 0) {
		perror("pread");
		return -1;
	}

	if (ret != (ssize_t) sizeof(*value)) {
		fprintf(stderr,
			"short pread: got %zd bytes, expected %zu\n",
			ret, sizeof(*value));
		return -1;
	}

	return 0;
}

static int is_selected_page(size_t page, size_t pages)
{
	return page == 0 ||
	    page == 1 ||
	    page == 511 || page == 512 || page == 1023 || page == pages - 1;
}

int main(void)
{
	const size_t length = 16UL * 1024UL * 1024UL;

	long page_size_long = sysconf(_SC_PAGESIZE);
	if (page_size_long <= 0) {
		perror("sysconf");
		return EXIT_FAILURE;
	}

	size_t page_size = (size_t)page_size_long;
	size_t pages = length / page_size;

	volatile unsigned char *memory = mmap(NULL,
					      length,
					      PROT_READ | PROT_WRITE,
					      MAP_PRIVATE | MAP_ANONYMOUS,
					      -1,
					      0);

	if (memory == MAP_FAILED) {
		perror("mmap");
		return EXIT_FAILURE;
	}

	/*
	 * 首次读取所有页面：
	 * 预期建立共享零页PTE。
	 */
	uint64_t sum = 0;

	for (size_t page = 0; page < pages; ++page)
		sum += memory[page * page_size];

	read_sink += sum;

	int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	if (pagemap_fd < 0) {
		perror("open pagemap");
		munmap((void *)memory, length);
		return EXIT_FAILURE;
	}

	int kpageflags_fd = open("/proc/kpageflags", O_RDONLY);
	if (kpageflags_fd < 0)
		perror("open kpageflags");

	uint64_t first_pfn = UINT64_MAX;
	size_t present_pages = 0;
	size_t same_pfn_pages = 0;
	size_t different_pfn_pages = 0;
	size_t zero_page_flag_pages = 0;

	printf("mapping             : %p\n", (const void *)memory);
	printf("page size           : %zu\n", page_size);
	printf("pages               : %zu\n", pages);

	for (size_t page = 0; page < pages; ++page) {
		uintptr_t virtual_address =
		    (uintptr_t) memory + page * page_size;

		off_t pagemap_offset =
		    (off_t) (virtual_address / page_size) *
		    (off_t) sizeof(uint64_t);

		uint64_t entry;

		if (read_u64_at(pagemap_fd, pagemap_offset, &entry) != 0) {
			close(pagemap_fd);

			if (kpageflags_fd >= 0)
				close(kpageflags_fd);

			munmap((void *)memory, length);
			return EXIT_FAILURE;
		}

		int present = (entry & PAGEMAP_PRESENT) != 0;
		uint64_t pfn = entry & PAGEMAP_PFN_MASK;

		if (!present) {
			if (is_selected_page(page, pages)) {
				printf("page=%4zu VA=%p not-present\n",
				       page, (void *)virtual_address);
			}

			continue;
		}

		++present_pages;

		if (first_pfn == UINT64_MAX)
			first_pfn = pfn;

		if (pfn == first_pfn)
			++same_pfn_pages;
		else
			++different_pfn_pages;

		int zero_page_flag = -1;

		if (kpageflags_fd >= 0) {
			uint64_t flags;

			if (read_u64_at(kpageflags_fd,
					(off_t) pfn * sizeof(uint64_t),
					&flags) == 0) {
				zero_page_flag =
				    (int)((flags >> KPF_ZERO_PAGE) & 1);

				if (zero_page_flag)
					++zero_page_flag_pages;
			}
		}

		if (is_selected_page(page, pages)) {
			uint64_t physical_address =
			    pfn * page_size + virtual_address % page_size;

			printf("page=%4zu VA=%p PFN=0x%" PRIx64
			       " PA=0x%" PRIx64
			       " ZERO_PAGE=%d\n",
			       page,
			       (void *)virtual_address,
			       pfn, physical_address, zero_page_flag);
		}
	}

	printf("\nfirst PFN           : 0x%" PRIx64 "\n", first_pfn);
	printf("present pages       : %zu\n", present_pages);
	printf("same PFN pages      : %zu\n", same_pfn_pages);
	printf("different PFN pages : %zu\n", different_pfn_pages);
	printf("ZERO_PAGE pages     : %zu\n", zero_page_flag_pages);
	printf("read_sink           : %" PRIu64 "\n", read_sink);

	close(pagemap_fd);

	if (kpageflags_fd >= 0)
		close(kpageflags_fd);

	munmap((void *)memory, length);
	return EXIT_SUCCESS;
}
