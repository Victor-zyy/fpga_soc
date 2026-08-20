#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define PM_PFN_MASK       ((1ULL << 55) - 1ULL)
#define PM_SOFT_DIRTY     (1ULL << 55)
#define PM_EXCLUSIVE      (1ULL << 56)
#define PM_UFFD_WP        (1ULL << 57)
#define PM_FILE_OR_SHANON (1ULL << 61)
#define PM_SWAPPED        (1ULL << 62)
#define PM_PRESENT        (1ULL << 63)

enum {
	KPF_LOCKED = 0,
	KPF_ERROR = 1,
	KPF_REFERENCED = 2,
	KPF_UPTODATE = 3,
	KPF_DIRTY = 4,
	KPF_LRU = 5,
	KPF_ACTIVE = 6,
	KPF_SLAB = 7,
	KPF_WRITEBACK = 8,
	KPF_RECLAIM = 9,
	KPF_BUDDY = 10,
	KPF_MMAP = 11,
	KPF_ANON = 12,
	KPF_SWAPCACHE = 13,
	KPF_SWAPBACKED = 14,
	KPF_COMPOUND_HEAD = 15,
	KPF_COMPOUND_TAIL = 16,
	KPF_HUGE = 17,
	KPF_UNEVICTABLE = 18,
	KPF_HWPOISON = 19,
	KPF_NOPAGE = 20,
	KPF_KSM = 21,
	KPF_THP = 22,
	KPF_OFFLINE = 23,
	KPF_ZERO_PAGE = 24,
	KPF_IDLE = 25,
	KPF_PGTABLE = 26
};

static const char *kpf_names[27] = {
	"LOCKED",
	"ERROR",
	"REFERENCED",
	"UPTODATE",
	"DIRTY",
	"LRU",
	"ACTIVE",
	"SLAB",
	"WRITEBACK",
	"RECLAIM",
	"BUDDY",
	"MMAP",
	"ANON",
	"SWAPCACHE",
	"SWAPBACKED",
	"COMPOUND_HEAD",
	"COMPOUND_TAIL",
	"HUGE",
	"UNEVICTABLE",
	"HWPOISON",
	"NOPAGE",
	"KSM",
	"THP",
	"OFFLINE",
	"ZERO_PAGE",
	"IDLE",
	"PGTABLE"
};

struct page_snapshot {
	uintptr_t address;

	uint64_t pagemap_raw;
	uint64_t pfn;

	int soft_dirty;
	int exclusive;
	int uffd_wp;
	int file_or_shared_anon;
	int swapped;
	int present;

	int maps_contains;

	int mincore_ok;
	int mincore_errno;
	int resident;

	int physical_info_valid;
	uint64_t kpagecount;
	uint64_t kpageflags;
};

static volatile uint64_t sink;

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static void write_u32(int fd, off_t offset, uint32_t value)
{
	ssize_t result = pwrite(fd, &value, sizeof(value), offset);

	if (result != (ssize_t) sizeof(value))
		die("pwrite");
}

static uint32_t read_u32(int fd, off_t offset)
{
	uint32_t value = 0;

	ssize_t result = pread(fd, &value, sizeof(value), offset);

	if (result != (ssize_t) sizeof(value))
		die("pread");

	return value;
}

static uint64_t read_indexed_u64(int fd, uint64_t index, const char *what)
{
	uint64_t value = 0;

	off_t offset = (off_t) (index * sizeof(value));

	ssize_t result = pread(fd,
			       &value,
			       sizeof(value),
			       offset);

	if (result != (ssize_t) sizeof(value)) {
		if (result < 0)
			perror(what);
		else
			fprintf(stderr, "%s: short read %zd\n", what, result);

		exit(EXIT_FAILURE);
	}

	return value;
}

static int address_in_maps(const void *address)
{
	uintptr_t target = (uintptr_t) address;

	FILE *fp = fopen("/proc/self/maps", "r");

	if (fp == NULL)
		die("fopen maps");

	char line[1024];

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long start;
		unsigned long end;

		if (sscanf(line, "%lx-%lx", &start, &end) != 2) {
			continue;
		}

		if (target >= (uintptr_t) start && target < (uintptr_t) end) {
			fclose(fp);
			return 1;
		}
	}

	fclose(fp);

	return 0;
}

static struct page_snapshot snapshot_page(const void *address,
					  size_t page_size,
					  int pagemap_fd,
					  int kpagecount_fd, int kpageflags_fd)
{
	struct page_snapshot result;

	memset(&result, 0, sizeof(result));

	result.address = (uintptr_t) address;

	uint64_t vpn = (uint64_t) (uintptr_t) address / (uint64_t) page_size;

	result.pagemap_raw = read_indexed_u64(pagemap_fd, vpn, "pagemap");

	result.pfn = result.pagemap_raw & PM_PFN_MASK;

	result.soft_dirty = !!(result.pagemap_raw & PM_SOFT_DIRTY);

	result.exclusive = !!(result.pagemap_raw & PM_EXCLUSIVE);

	result.uffd_wp = !!(result.pagemap_raw & PM_UFFD_WP);

	result.file_or_shared_anon = !!(result.pagemap_raw & PM_FILE_OR_SHANON);

	result.swapped = !!(result.pagemap_raw & PM_SWAPPED);

	result.present = !!(result.pagemap_raw & PM_PRESENT);

	result.maps_contains = address_in_maps(address);

	unsigned char vec = 0;

	errno = 0;

	if (mincore((void *)address, page_size, &vec) == 0) {
		result.mincore_ok = 1;
		result.resident = !!(vec & 1);
	} else {
		result.mincore_ok = 0;
		result.mincore_errno = errno;
	}

	/*
	 * PFN==0 can also mean that PFNs were hidden by
	 * the kernel for an unprivileged reader.
	 *
	 * On this board/root experiment we expect real
	 * nonzero PFNs for present pages.
	 */
	if (result.present && result.pfn != 0) {
		result.physical_info_valid = 1;

		result.kpagecount =
		    read_indexed_u64(kpagecount_fd, result.pfn, "kpagecount");

		result.kpageflags =
		    read_indexed_u64(kpageflags_fd, result.pfn, "kpageflags");
	}

	return result;
}

static int kpf_test(uint64_t flags, unsigned int bit)
{
	return !!(flags & (1ULL << bit));
}

static void print_kpageflags(uint64_t flags)
{
	printf("kpageflags raw       : 0x%016" PRIx64 "\n", flags);

	printf("kpageflags set       :");

	int any = 0;

	for (unsigned int bit = 0; bit < 27; ++bit) {
		if (kpf_test(flags, bit)) {
			printf(" %s", kpf_names[bit]);
			any = 1;
		}
	}

	if (!any)
		printf(" none");

	printf("\n");
}

static void print_snapshot(const char *name, const struct page_snapshot *s)
{
	printf("\n========== %s ==========\n", name);

	printf("VA                   : %p\n", (void *)s->address);

	printf("maps contains VA     : %s\n", s->maps_contains ? "yes" : "no");

	printf("pagemap raw          : 0x%016" PRIx64 "\n", s->pagemap_raw);

	printf("present              : %d\n", s->present);

	printf("swapped              : %d\n", s->swapped);

	printf("soft-dirty           : %d\n", s->soft_dirty);

	printf("exclusive            : %d\n", s->exclusive);

	printf("uffd-wp              : %d\n", s->uffd_wp);

	printf("file/shared-anon     : %d\n", s->file_or_shared_anon);

	printf("PFN                  : 0x%011" PRIx64 "\n", s->pfn);

	if (s->mincore_ok) {
		printf("mincore              : success\n");
		printf("resident             : %d\n", s->resident);
	} else {
		printf("mincore              : failed "
		       "errno=%d (%s)\n",
		       s->mincore_errno, strerror(s->mincore_errno));
	}

	if (s->physical_info_valid) {
		printf("kpagecount           : %" PRIu64 "\n", s->kpagecount);

		print_kpageflags(s->kpageflags);
	} else {
		printf("kpagecount           : N/A\n");

		printf("kpageflags           : N/A\n");
	}
}

static void compare_identity(const char *name,
			     const struct page_snapshot *before,
			     const struct page_snapshot *after)
{
	printf("\n========== %s ==========\n", name);

	printf("before PFN           : 0x%011" PRIx64 "\n", before->pfn);

	printf("after PFN            : 0x%011" PRIx64 "\n", after->pfn);

	printf("PFN unchanged        : %s\n",
	       before->present &&
	       after->present && before->pfn == after->pfn ? "yes" : "no");

	printf("before kpagecount    : %" PRIu64 "\n",
	       before->physical_info_valid ? before->kpagecount : 0);

	printf("after kpagecount     : %" PRIu64 "\n",
	       after->physical_info_valid ? after->kpagecount : 0);

	if (before->physical_info_valid && after->physical_info_valid) {
		printf("kpageflags same     : %s\n",
		       before->kpageflags == after->kpageflags ? "yes" : "no");
	}
}

int main(void)
{
	const char *path = "stage6_1_backing.bin";

	setvbuf(stdout, NULL, _IONBF, 0);

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0)
		die("sysconf");

	size_t page_size = (size_t)page_size_long;

	printf("PID                  : %ld\n", (long)getpid());

	printf("page size            : %zu bytes\n", page_size);

	/*
	 * ----------------------------------------------------------
	 * Open observation interfaces.
	 * ----------------------------------------------------------
	 */
	int pagemap_fd = open("/proc/self/pagemap",
			      O_RDONLY | O_CLOEXEC);

	if (pagemap_fd < 0)
		die("open pagemap");

	int kpagecount_fd = open("/proc/kpagecount",
				 O_RDONLY | O_CLOEXEC);

	if (kpagecount_fd < 0)
		die("open kpagecount");

	int kpageflags_fd = open("/proc/kpageflags",
				 O_RDONLY | O_CLOEXEC);

	if (kpageflags_fd < 0)
		die("open kpageflags");

	/*
	 * ----------------------------------------------------------
	 * Prepare a 3-page backing file.
	 * ----------------------------------------------------------
	 */
	unlink(path);

	int fd = open(path,
		      O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC,
		      0600);

	if (fd < 0)
		die("open backing file");

	if (ftruncate(fd, (off_t) (3 * page_size)) != 0) {
		die("ftruncate");
	}

	write_u32(fd, 0, 0x11111111U);

	write_u32(fd, (off_t) page_size, 0x22222222U);

	write_u32(fd, (off_t) (2 * page_size), 0x33333333U);

	/*
	 * ----------------------------------------------------------
	 * 1. Untouched private anonymous.
	 * ----------------------------------------------------------
	 */
	volatile unsigned char *untouched = mmap(NULL,
						 page_size,
						 PROT_READ | PROT_WRITE,
						 MAP_PRIVATE | MAP_ANONYMOUS,
						 -1,
						 0);

	if (untouched == MAP_FAILED)
		die("mmap untouched");

	/*
	 * ----------------------------------------------------------
	 * 2. Zero-page mapping.
	 * ----------------------------------------------------------
	 */
	volatile unsigned char *zero_page = mmap(NULL,
						 page_size,
						 PROT_READ | PROT_WRITE,
						 MAP_PRIVATE | MAP_ANONYMOUS,
						 -1,
						 0);

	if (zero_page == MAP_FAILED)
		die("mmap zero");

	sink += zero_page[0];

	/*
	 * ----------------------------------------------------------
	 * 3. Normal private anonymous.
	 * ----------------------------------------------------------
	 */
	volatile uint32_t *anon = mmap(NULL,
				       page_size,
				       PROT_READ | PROT_WRITE,
				       MAP_PRIVATE | MAP_ANONYMOUS,
				       -1,
				       0);

	if (anon == MAP_FAILED)
		die("mmap anon");

	*anon = 0xaaaaaaaaU;

	/*
	 * ----------------------------------------------------------
	 * 4. Private anonymous page that will become PROT_NONE.
	 * ----------------------------------------------------------
	 */
	volatile uint32_t *none_page = mmap(NULL,
					    page_size,
					    PROT_READ | PROT_WRITE,
					    MAP_PRIVATE | MAP_ANONYMOUS,
					    -1,
					    0);

	if (none_page == MAP_FAILED)
		die("mmap none");

	*none_page = 0xbbbbbbbbU;

	struct page_snapshot none_before =
	    snapshot_page((const void *)none_page,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	if (mprotect((void *)none_page, page_size, PROT_NONE) != 0) {
		die("mprotect PROT_NONE");
	}

	/*
	 * ----------------------------------------------------------
	 * 5. MAP_PRIVATE file page, read only.
	 * ----------------------------------------------------------
	 */
	volatile uint32_t *file_private = mmap(NULL,
					       page_size,
					       PROT_READ,
					       MAP_PRIVATE,
					       fd,
					       0);

	if (file_private == MAP_FAILED)
		die("mmap private file");

	sink += *file_private;

	/*
	 * ----------------------------------------------------------
	 * 6. MAP_PRIVATE file page, then COW.
	 * ----------------------------------------------------------
	 */
	volatile uint32_t *file_cow = mmap(NULL,
					   page_size,
					   PROT_READ | PROT_WRITE,
					   MAP_PRIVATE,
					   fd,
					   (off_t) page_size);

	if (file_cow == MAP_FAILED)
		die("mmap cow file");

	sink += *file_cow;

	struct page_snapshot cow_before = snapshot_page((const void *)file_cow,
							page_size,
							pagemap_fd,
							kpagecount_fd,
							kpageflags_fd);

	*file_cow = 0xc0c0c0c0U;

	/*
	 * ----------------------------------------------------------
	 * 7/8. Two MAP_SHARED mappings of exactly the same file page.
	 * ----------------------------------------------------------
	 */
	volatile uint32_t *shared_a = mmap(NULL,
					   page_size,
					   PROT_READ,
					   MAP_SHARED,
					   fd,
					   (off_t) (2 * page_size));

	if (shared_a == MAP_FAILED)
		die("mmap shared A");

	volatile uint32_t *shared_b = mmap(NULL,
					   page_size,
					   PROT_READ,
					   MAP_SHARED,
					   fd,
					   (off_t) (2 * page_size));

	if (shared_b == MAP_FAILED)
		die("mmap shared B");

	sink += *shared_a;
	sink += *shared_b;

	/*
	 * ----------------------------------------------------------
	 * 9. MAP_SHARED | MAP_ANONYMOUS.
	 * ----------------------------------------------------------
	 */
	volatile uint32_t *shared_anon = mmap(NULL,
					      page_size,
					      PROT_READ | PROT_WRITE,
					      MAP_SHARED | MAP_ANONYMOUS,
					      -1,
					      0);

	if (shared_anon == MAP_FAILED)
		die("mmap shared anon");

	*shared_anon = 0xddddddddU;

	/*
	 * ----------------------------------------------------------
	 * 10. Create a true unmapped hole protected on both sides.
	 *
	 * No later mmap() calls are performed after this point.
	 * ----------------------------------------------------------
	 */
	unsigned char *guards = mmap(NULL,
				     3 * page_size,
				     PROT_NONE,
				     MAP_PRIVATE | MAP_ANONYMOUS,
				     -1,
				     0);

	if (guards == MAP_FAILED)
		die("mmap guards");

	void *hole = guards + page_size;

	if (munmap(hole, page_size) != 0) {
		die("munmap hole");
	}

	/*
	 * ----------------------------------------------------------
	 * Capture final states.
	 * ----------------------------------------------------------
	 */
	struct page_snapshot hole_s = snapshot_page(hole,
						    page_size,
						    pagemap_fd,
						    kpagecount_fd,
						    kpageflags_fd);

	struct page_snapshot untouched_s =
	    snapshot_page((const void *)untouched,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot zero_s = snapshot_page((const void *)zero_page,
						    page_size,
						    pagemap_fd,
						    kpagecount_fd,
						    kpageflags_fd);

	struct page_snapshot anon_s = snapshot_page((const void *)anon,
						    page_size,
						    pagemap_fd,
						    kpagecount_fd,
						    kpageflags_fd);

	struct page_snapshot none_after = snapshot_page((const void *)none_page,
							page_size,
							pagemap_fd,
							kpagecount_fd,
							kpageflags_fd);

	struct page_snapshot file_private_s =
	    snapshot_page((const void *)file_private,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot cow_after = snapshot_page((const void *)file_cow,
						       page_size,
						       pagemap_fd,
						       kpagecount_fd,
						       kpageflags_fd);

	struct page_snapshot shared_a_s = snapshot_page((const void *)shared_a,
							page_size,
							pagemap_fd,
							kpagecount_fd,
							kpageflags_fd);

	struct page_snapshot shared_b_s = snapshot_page((const void *)shared_b,
							page_size,
							pagemap_fd,
							kpagecount_fd,
							kpageflags_fd);

	struct page_snapshot shared_anon_s =
	    snapshot_page((const void *)shared_anon,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("1. true unmapped hole", &hole_s);

	print_snapshot("2. untouched private anon", &untouched_s);

	print_snapshot("3. zero-page mapping", &zero_s);

	print_snapshot("4. private anonymous", &anon_s);

	print_snapshot("5. private anon under PROT_NONE", &none_after);

	compare_identity("5. PROT_NONE identity comparison",
			 &none_before, &none_after);

	print_snapshot("6. private file page before COW", &file_private_s);

	print_snapshot("7. private file page after COW", &cow_after);

	compare_identity("7. file COW identity comparison",
			 &cow_before, &cow_after);

	printf("\nCOW backing value    : 0x%08x\n",
	       read_u32(fd, (off_t) page_size));

	printf("COW mapping value    : 0x%08x\n", *file_cow);

	print_snapshot("8. shared file mapping A", &shared_a_s);

	print_snapshot("9. shared file mapping B", &shared_b_s);

	printf("\n========== 8/9. shared alias comparison ==========\n");

	printf("same PFN             : %s\n",
	       shared_a_s.present &&
	       shared_b_s.present &&
	       shared_a_s.pfn == shared_b_s.pfn ? "yes" : "NO");

	printf("A kpagecount         : %" PRIu64 "\n", shared_a_s.kpagecount);

	printf("B kpagecount         : %" PRIu64 "\n", shared_b_s.kpagecount);

	printf("A exclusive          : %d\n", shared_a_s.exclusive);

	printf("B exclusive          : %d\n", shared_b_s.exclusive);

	print_snapshot("10. MAP_SHARED anonymous", &shared_anon_s);

	printf("\n========== final checks ==========\n");

	printf("hole has no VMA      : %s\n",
	       !hole_s.maps_contains ? "yes" : "NO");

	printf("untouched has VMA    : %s\n",
	       untouched_s.maps_contains ? "yes" : "NO");

	printf("hole present=0       : %s\n", !hole_s.present ? "yes" : "NO");

	printf("untouched present=0  : %s\n",
	       !untouched_s.present ? "yes" : "NO");

	printf("zero page present    : %s\n", zero_s.present ? "yes" : "NO");

	printf("zero KPF_ZERO_PAGE   : %s\n",
	       zero_s.physical_info_valid &&
	       kpf_test(zero_s.kpageflags, KPF_ZERO_PAGE) ? "yes" : "NO");

	printf("anon KPF_ANON        : %s\n",
	       anon_s.physical_info_valid &&
	       kpf_test(anon_s.kpageflags, KPF_ANON) ? "yes" : "NO");

	printf("PROT_NONE same PFN   : %s\n",
	       none_before.present &&
	       none_after.present &&
	       none_before.pfn == none_after.pfn ? "yes" : "NO");

	printf("COW changed PFN      : %s\n",
	       cow_before.present &&
	       cow_after.present &&
	       cow_before.pfn != cow_after.pfn ? "yes" : "NO");

	printf("COW file-bit 1->0    : %s\n",
	       cow_before.file_or_shared_anon &&
	       !cow_after.file_or_shared_anon ? "yes" : "NO");

	printf("shared aliases PFN   : %s\n",
	       shared_a_s.present &&
	       shared_b_s.present &&
	       shared_a_s.pfn == shared_b_s.pfn ? "yes" : "NO");

	printf("\nsink                 : %" PRIu64 "\n", sink);

	/*
	 * Cleanup.
	 */
	munmap((void *)untouched, page_size);

	munmap((void *)zero_page, page_size);

	munmap((void *)anon, page_size);

	munmap((void *)none_page, page_size);

	munmap((void *)file_private, page_size);

	munmap((void *)file_cow, page_size);

	munmap((void *)shared_a, page_size);

	munmap((void *)shared_b, page_size);

	munmap((void *)shared_anon, page_size);

	/*
	 * Middle guard page was already unmapped.
	 */
	munmap(guards, page_size);

	munmap(guards + 2 * page_size, page_size);

	close(kpageflags_fd);
	close(kpagecount_fd);
	close(pagemap_fd);

	close(fd);

	unlink(path);

	return EXIT_SUCCESS;
}
