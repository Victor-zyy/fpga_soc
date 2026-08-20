#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#define PM_PFN_MASK       ((1ULL << 55) - 1ULL)
#define PM_EXCLUSIVE      (1ULL << 56)
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

struct usage_snapshot {
	long minflt;
	long majflt;
};

struct page_snapshot {
	uintptr_t address;

	uint64_t pagemap_raw;
	uint64_t pfn;

	int present;
	int swapped;
	int exclusive;
	int file_or_shared_anon;

	int resident;

	int physical_valid;
	uint64_t kpagecount;
	uint64_t kpageflags;
};

struct vma_info {
	char header[512];
	char vmflags[512];

	unsigned long rss_kb;
	unsigned long pss_kb;
	unsigned long shared_dirty_kb;
	unsigned long private_dirty_kb;
	unsigned long anonymous_kb;
};

static volatile uint32_t sink;

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static int flag_set(uint64_t flags, unsigned int bit)
{
	return !!(flags & (1ULL << bit));
}

static struct usage_snapshot usage_now(void)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage) != 0) {
		die("getrusage");
	}

	struct usage_snapshot result = {
		.minflt = usage.ru_minflt,
		.majflt = usage.ru_majflt
	};

	return result;
}

static uint64_t read_indexed_u64(int fd, uint64_t index, const char *what)
{
	uint64_t value = 0;

	ssize_t result = pread(fd,
			       &value,
			       sizeof(value),
			       (off_t) (index * sizeof(value)));

	if (result != (ssize_t) sizeof(value)) {
		if (result < 0)
			perror(what);
		else
			fprintf(stderr, "%s: short read %zd\n", what, result);

		exit(EXIT_FAILURE);
	}

	return value;
}

static struct page_snapshot snapshot_page(const void *address,
					  size_t page_size,
					  int pagemap_fd,
					  int kpagecount_fd, int kpageflags_fd)
{
	struct page_snapshot result;

	memset(&result, 0, sizeof(result));

	result.address = (uintptr_t) address;

	uint64_t vpn = result.address / page_size;

	result.pagemap_raw = read_indexed_u64(pagemap_fd, vpn, "pagemap");

	result.pfn = result.pagemap_raw & PM_PFN_MASK;

	result.present = !!(result.pagemap_raw & PM_PRESENT);

	result.swapped = !!(result.pagemap_raw & PM_SWAPPED);

	result.exclusive = !!(result.pagemap_raw & PM_EXCLUSIVE);

	result.file_or_shared_anon = !!(result.pagemap_raw & PM_FILE_OR_SHANON);

	unsigned char vec = 0;

	if (mincore((void *)address, page_size, &vec) == 0) {
		result.resident = !!(vec & 1);
	}

	if (result.present && result.pfn != 0) {

		result.physical_valid = 1;

		result.kpagecount =
		    read_indexed_u64(kpagecount_fd, result.pfn, "kpagecount");

		result.kpageflags =
		    read_indexed_u64(kpageflags_fd, result.pfn, "kpageflags");
	}

	return result;
}

static void print_flags(uint64_t flags)
{
	printf("kpageflags set       :");

	int any = 0;

	for (unsigned int bit = 0; bit < 27; ++bit) {

		if (flag_set(flags, bit)) {
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

	printf("pagemap raw          : 0x%016" PRIx64 "\n", s->pagemap_raw);

	printf("present              : %d\n", s->present);

	printf("swapped              : %d\n", s->swapped);

	printf("exclusive            : %d\n", s->exclusive);

	printf("file/shared-anon     : %d\n", s->file_or_shared_anon);

	printf("PFN                  : 0x%011" PRIx64 "\n", s->pfn);

	printf("resident             : %d\n", s->resident);

	if (!s->physical_valid) {
		printf("kpagecount           : N/A\n");
		printf("kpageflags           : N/A\n");
		return;
	}

	printf("kpagecount           : %" PRIu64 "\n", s->kpagecount);

	printf("kpageflags raw       : 0x%016" PRIx64 "\n", s->kpageflags);

	print_flags(s->kpageflags);

	printf("\nselected flags:\n");

	printf("  REFERENCED         : %d\n",
	       flag_set(s->kpageflags, KPF_REFERENCED));

	printf("  UPTODATE           : %d\n",
	       flag_set(s->kpageflags, KPF_UPTODATE));

	printf("  DIRTY              : %d\n",
	       flag_set(s->kpageflags, KPF_DIRTY));

	printf("  LRU                : %d\n", flag_set(s->kpageflags, KPF_LRU));

	printf("  ACTIVE             : %d\n",
	       flag_set(s->kpageflags, KPF_ACTIVE));

	printf("  MMAP               : %d\n",
	       flag_set(s->kpageflags, KPF_MMAP));

	printf("  ANON               : %d\n",
	       flag_set(s->kpageflags, KPF_ANON));

	printf("  SWAPBACKED         : %d\n",
	       flag_set(s->kpageflags, KPF_SWAPBACKED));

	printf("  UNEVICTABLE        : %d\n",
	       flag_set(s->kpageflags, KPF_UNEVICTABLE));
}

static void read_vma_info(const void *address, struct vma_info *info)
{
	memset(info, 0, sizeof(*info));

	uintptr_t target = (uintptr_t) address;

	FILE *fp = fopen("/proc/self/smaps",
			 "r");

	if (fp == NULL)
		die("fopen smaps");

	char line[1024];
	int active = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {

		unsigned long start;
		unsigned long end;
		char perms[8];

		if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {

			active =
			    target >= (uintptr_t) start &&
			    target < (uintptr_t) end;

			if (active) {
				snprintf(info->header,
					 sizeof(info->header), "%s", line);

				info->header[strcspn(info->header,
						     "\n")] = '\0';
			}

			continue;
		}

		if (!active)
			continue;

		unsigned long value;

		if (sscanf(line, "Rss: %lu kB", &value) == 1) {

			info->rss_kb = value;

		} else if (sscanf(line, "Pss: %lu kB", &value) == 1) {

			info->pss_kb = value;

		} else if (sscanf(line, "Shared_Dirty: %lu kB", &value) == 1) {

			info->shared_dirty_kb = value;

		} else if (sscanf(line, "Private_Dirty: %lu kB", &value) == 1) {

			info->private_dirty_kb = value;

		} else if (sscanf(line, "Anonymous: %lu kB", &value) == 1) {

			info->anonymous_kb = value;

		} else if (strncmp(line, "VmFlags:", 8) == 0) {

			snprintf(info->vmflags,
				 sizeof(info->vmflags), "%s", line + 8);

			info->vmflags[strcspn(info->vmflags, "\n")] = '\0';

			break;
		}
	}

	fclose(fp);
}

static void print_vma(const char *name, const void *address)
{
	struct vma_info info;

	read_vma_info(address, &info);

	printf("\n========== %s ==========\n", name);

	printf("mapping              : %s\n", info.header);

	printf("Rss                  : %lu kB\n", info.rss_kb);

	printf("Pss                  : %lu kB\n", info.pss_kb);

	printf("Shared_Dirty         : %lu kB\n", info.shared_dirty_kb);

	printf("Private_Dirty        : %lu kB\n", info.private_dirty_kb);

	printf("Anonymous            : %lu kB\n", info.anonymous_kb);

	printf("VmFlags              :%s\n", info.vmflags);
}

static void write_u32(int fd, off_t offset, uint32_t value)
{
	ssize_t result = pwrite(fd,
				&value,
				sizeof(value),
				offset);

	if (result != (ssize_t) sizeof(value))
		die("pwrite");
}

static uint32_t read_u32(int fd, off_t offset)
{
	uint32_t value = 0;

	ssize_t result = pread(fd,
			       &value,
			       sizeof(value),
			       offset);

	if (result != (ssize_t) sizeof(value))
		die("pread");

	return value;
}

/*
 * On this single-hart machine this provides the same kind of
 * local LRU/mlock batch-drain trigger verified in 6.4.1b.
 *
 * We do NOT use the target mappings themselves, so their lock
 * policy is not modified.
 */
static void force_local_drain(volatile uint32_t * control, size_t page_size)
{
	if (mlock((const void *)control, page_size) != 0) {
		die("mlock control");
	}

	if (munlock((const void *)control, page_size) != 0) {
		die("munlock control");
	}
}

static void compare_pages(const char *name,
			  const struct page_snapshot *before,
			  const struct page_snapshot *after)
{
	printf("\n========== %s ==========\n", name);

	printf("before PFN           : 0x%011" PRIx64 "\n", before->pfn);

	printf("after PFN            : 0x%011" PRIx64 "\n", after->pfn);

	printf("PFN unchanged        : %s\n",
	       before->present &&
	       after->present && before->pfn == after->pfn ? "yes" : "no");

	printf("PFN changed          : %s\n",
	       before->present &&
	       after->present && before->pfn != after->pfn ? "yes" : "no");

	printf("before bit61         : %d\n", before->file_or_shared_anon);

	printf("after bit61          : %d\n", after->file_or_shared_anon);

	if (before->physical_valid && after->physical_valid) {

		printf("before count         : %" PRIu64 "\n",
		       before->kpagecount);

		printf("after count          : %" PRIu64 "\n",
		       after->kpagecount);

		printf("before ANON          : %d\n",
		       flag_set(before->kpageflags, KPF_ANON));

		printf("after ANON           : %d\n",
		       flag_set(after->kpageflags, KPF_ANON));

		printf("before LRU           : %d\n",
		       flag_set(before->kpageflags, KPF_LRU));

		printf("after LRU            : %d\n",
		       flag_set(after->kpageflags, KPF_LRU));

		printf("before DIRTY         : %d\n",
		       flag_set(before->kpageflags, KPF_DIRTY));

		printf("after DIRTY          : %d\n",
		       flag_set(after->kpageflags, KPF_DIRTY));

		printf("before REFERENCED    : %d\n",
		       flag_set(before->kpageflags, KPF_REFERENCED));

		printf("after REFERENCED     : %d\n",
		       flag_set(after->kpageflags, KPF_REFERENCED));
	}
}

int main(void)
{
	const char *path = "stage6_4_2_backing.bin";

	const uint32_t original = 0x11111111U;

	const uint32_t cow_value1 = 0xc0c0c0c0U;

	const uint32_t cow_value2 = 0xd0d0d0d0U;

	setvbuf(stdout, NULL, _IONBF, 0);

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0)
		die("sysconf");

	size_t page_size = (size_t)page_size_long;

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

	unlink(path);

	int fd = open(path,
		      O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC,
		      0600);

	if (fd < 0)
		die("open backing");

	if (ftruncate(fd, (off_t) page_size) != 0) {
		die("ftruncate");
	}

	/*
	 * This also makes the tmpfs page-cache page resident.
	 */
	write_u32(fd, 0, original);

	/*
	 * Separate anonymous control page.  It is used only to force
	 * the same local drain behavior that we verified in 6.4.1b.
	 */
	volatile uint32_t *control = mmap(NULL,
					  page_size,
					  PROT_READ | PROT_WRITE,
					  MAP_PRIVATE | MAP_ANONYMOUS,
					  -1,
					  0);

	if (control == MAP_FAILED)
		die("mmap control");

	*control = 0xaaaaaaaaU;

	/*
	 * The actual COW mapping.
	 */
	volatile uint32_t *private_map = mmap(NULL,
					      page_size,
					      PROT_READ | PROT_WRITE,
					      MAP_PRIVATE,
					      fd,
					      0);

	if (private_map == MAP_FAILED)
		die("mmap private");

	/*
	 * Permanent observation alias of the old file page.
	 */
	volatile uint32_t *shared_alias = mmap(NULL,
					       page_size,
					       PROT_READ,
					       MAP_SHARED,
					       fd,
					       0);

	if (shared_alias == MAP_FAILED)
		die("mmap shared alias");

	printf("PID                  : %ld\n", (long)getpid());

	printf("page size            : %zu\n", page_size);

	printf("file                 : %s\n", path);

	printf("control              : %p\n", (const void *)control);

	printf("private map          : %p\n", (const void *)private_map);

	printf("shared alias         : %p\n", (const void *)shared_alias);

	printf("initial backing      : 0x%08x\n", read_u32(fd, 0));

	/*
	 * Populate both file PTEs.
	 */
	sink += *private_map;
	sink += *shared_alias;

	/*
	 * Stabilize pending local LRU work before the baseline.
	 */
	force_local_drain(control, page_size);

	/*
	 * ---------------------------------------------------------
	 * 0. Baseline: both VAs must point at the SAME file PFN.
	 * ---------------------------------------------------------
	 */
	struct page_snapshot private_before =
	    snapshot_page((const void *)private_map,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot alias_before =
	    snapshot_page((const void *)shared_alias,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("0A. private mapping before COW", &private_before);

	print_snapshot("0B. shared alias before COW", &alias_before);

	print_vma("0C. private VMA before COW", (const void *)private_map);

	printf("\n========== 0D. baseline identity ==========\n");

	printf("same PFN             : %s\n",
	       private_before.present &&
	       alias_before.present &&
	       private_before.pfn == alias_before.pfn ? "yes" : "NO");

	printf("private value        : 0x%08x\n", *private_map);

	printf("shared alias value   : 0x%08x\n", *shared_alias);

	printf("backing value        : 0x%08x\n", read_u32(fd, 0));

	/*
	 * ---------------------------------------------------------
	 * 1. First Store: true file -> anonymous COW.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 1. first Store / COW ==========\n");

	struct usage_snapshot usage_before = usage_now();

	*private_map = cow_value1;

	struct usage_snapshot usage_after = usage_now();

	long cow_minflt = usage_after.minflt - usage_before.minflt;

	long cow_majflt = usage_after.majflt - usage_before.majflt;

	printf("minor faults         : %ld\n", cow_minflt);

	printf("major faults         : %ld\n", cow_majflt);

	/*
	 * IMPORTANT:
	 * Capture immediately, BEFORE our explicit drain.
	 */
	struct page_snapshot private_immediate =
	    snapshot_page((const void *)private_map,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot alias_after_cow =
	    snapshot_page((const void *)shared_alias,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("1A. private COW page immediately after Store",
		       &private_immediate);

	print_snapshot("1B. original file page via shared alias after COW",
		       &alias_after_cow);

	print_vma("1C. private VMA immediately after COW",
		  (const void *)private_map);

	compare_pages("1D. private VA file->anon transition",
		      &private_before, &private_immediate);

	compare_pages("1E. original file PFN across COW",
		      &alias_before, &alias_after_cow);

	printf("\n========== 1F. content isolation ==========\n");

	printf("private value        : 0x%08x\n", *private_map);

	printf("shared alias value   : 0x%08x\n", *shared_alias);

	printf("backing value        : 0x%08x\n", read_u32(fd, 0));

	/*
	 * ---------------------------------------------------------
	 * 2. Explicitly drain local batches.
	 *
	 * This is specifically here because 6.4.1 demonstrated that
	 * newly-created folios can temporarily show KPF_LRU=0.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 2. force local batch drain ==========\n");

	force_local_drain(control, page_size);

	struct page_snapshot private_after_drain =
	    snapshot_page((const void *)private_map,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot alias_after_drain =
	    snapshot_page((const void *)shared_alias,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("2A. private COW page after drain",
		       &private_after_drain);

	print_snapshot("2B. original file page after drain",
		       &alias_after_drain);

	compare_pages("2C. COW page immediate -> drained",
		      &private_immediate, &private_after_drain);

	/*
	 * ---------------------------------------------------------
	 * 3. Second private Store should now be a hot write.
	 * ---------------------------------------------------------
	 */
	printf("\n========== 3. second private Store ==========\n");

	struct usage_snapshot usage2_before = usage_now();

	*private_map = cow_value2;

	struct usage_snapshot usage2_after = usage_now();

	long second_minflt = usage2_after.minflt - usage2_before.minflt;

	long second_majflt = usage2_after.majflt - usage2_before.majflt;

	printf("minor faults         : %ld\n", second_minflt);

	printf("major faults         : %ld\n", second_majflt);

	struct page_snapshot private_final =
	    snapshot_page((const void *)private_map,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_snapshot("3. private page after second Store", &private_final);

	printf("\n========== 4. final contents ==========\n");

	printf("private value        : 0x%08x "
	       "(expected 0x%08x)\n", *private_map, cow_value2);

	printf("shared alias value   : 0x%08x "
	       "(expected 0x%08x)\n", *shared_alias, original);

	printf("backing value        : 0x%08x "
	       "(expected 0x%08x)\n", read_u32(fd, 0), original);

	/*
	 * ---------------------------------------------------------
	 * Final semantic checks.
	 * ---------------------------------------------------------
	 */
	int baseline_same_file_pfn =
	    private_before.present &&
	    alias_before.present &&
	    private_before.pfn ==
	    alias_before.pfn &&
	    private_before.file_or_shared_anon &&
	    alias_before.file_or_shared_anon &&
	    !flag_set(private_before.kpageflags,
		      KPF_ANON);

	int cow_changed_pfn = private_before.pfn != private_immediate.pfn;

	int cow_bit61_1_to_0 =
	    private_before.file_or_shared_anon &&
	    !private_immediate.file_or_shared_anon;

	int cow_anon_0_to_1 = !flag_set(private_before.kpageflags,
					KPF_ANON) &&
	    flag_set(private_immediate.kpageflags,
		     KPF_ANON);

	int old_file_pfn_survives =
	    alias_before.pfn ==
	    alias_after_cow.pfn &&
	    alias_after_cow.file_or_shared_anon &&
	    !flag_set(alias_after_cow.kpageflags,
		      KPF_ANON);

	int old_count_2_to_1 =
	    private_before.pfn ==
	    alias_before.pfn &&
	    private_before.kpagecount == 2 && alias_after_cow.kpagecount == 1;

	int both_exclusive_after_cow =
	    private_immediate.exclusive &&
	    alias_after_cow.exclusive &&
	    private_immediate.kpagecount == 1 &&
	    alias_after_cow.kpagecount == 1;

	int backing_unchanged =
	    read_u32(fd, 0) == original && *shared_alias == original;

	int second_write_no_fault = second_minflt == 0;

	printf("\n========== final semantic summary ==========\n");

	printf("baseline same file PFN + bit61=1 + ANON=0 : %s\n",
	       baseline_same_file_pfn ? "yes" : "NO");

	printf("COW changed private PFN                   : %s\n",
	       cow_changed_pfn ? "yes" : "NO");

	printf("private bit61 1->0                       : %s\n",
	       cow_bit61_1_to_0 ? "yes" : "NO");

	printf("private KPF_ANON 0->1                    : %s\n",
	       cow_anon_0_to_1 ? "yes" : "NO");

	printf("original file PFN survives via alias     : %s\n",
	       old_file_pfn_survives ? "yes" : "NO");

	printf("old file kpagecount 2->1                 : %s\n",
	       old_count_2_to_1 ? "yes" : "NO");

	printf("after COW both PFNs count1/exclusive1    : %s\n",
	       both_exclusive_after_cow ? "yes" : "NO");

	printf("private COW leaves backing unchanged     : %s\n",
	       backing_unchanged ? "yes" : "NO");

	printf("first Store minor fault                  : %ld\n", cow_minflt);

	printf("second Store minor fault                 : %ld\n",
	       second_minflt);

	printf("second Store no fault                    : %s\n",
	       second_write_no_fault ? "yes" : "NO");

	/*
	 * Dynamic flags are reported, NOT used as semantic pass/fail.
	 */
	printf("\n========== dynamic flag observations ==========\n");

	printf("new COW LRU immediate->drain : %d -> %d\n",
	       flag_set(private_immediate.kpageflags,
			KPF_LRU),
	       flag_set(private_after_drain.kpageflags, KPF_LRU));

	printf("new COW DIRTY before->after  : %d -> %d\n",
	       flag_set(private_before.kpageflags,
			KPF_DIRTY),
	       flag_set(private_after_drain.kpageflags, KPF_DIRTY));

	printf("new COW REFERENCED before->after: %d -> %d\n",
	       flag_set(private_before.kpageflags,
			KPF_REFERENCED),
	       flag_set(private_after_drain.kpageflags, KPF_REFERENCED));

	printf("old file DIRTY after COW     : %d\n",
	       flag_set(alias_after_drain.kpageflags, KPF_DIRTY));

	printf("old file SWAPBACKED          : %d\n",
	       flag_set(alias_after_drain.kpageflags, KPF_SWAPBACKED));

	printf("new anon SWAPBACKED          : %d\n",
	       flag_set(private_after_drain.kpageflags, KPF_SWAPBACKED));

	printf("\nsink                 : %" PRIu32 "\n", sink);

	munmap((void *)shared_alias, page_size);

	munmap((void *)private_map, page_size);

	munmap((void *)control, page_size);

	close(fd);

	unlink(path);

	close(kpageflags_fd);
	close(kpagecount_fd);
	close(pagemap_fd);

	return EXIT_SUCCESS;
}
