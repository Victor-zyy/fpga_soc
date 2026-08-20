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
#define PM_PRESENT        (1ULL << 63)

enum {
	KPF_DIRTY = 4,
	KPF_LRU = 5,
	KPF_MMAP = 11,
	KPF_ANON = 12,
	KPF_SWAPBACKED = 14
};

struct usage_snapshot {
	long minflt;
	long majflt;
};

struct page_snapshot {
	uint64_t raw;
	uint64_t pfn;

	int present;
	int exclusive;
	int file_or_shared_anon;

	uint64_t count;
	uint64_t flags;

	int physical_valid;
};

struct smaps_info {
	char header[512];

	unsigned long rss_kb;
	unsigned long pss_kb;

	unsigned long shared_clean_kb;
	unsigned long shared_dirty_kb;

	unsigned long private_clean_kb;
	unsigned long private_dirty_kb;

	unsigned long anonymous_kb;
};

static volatile uint64_t sink;

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
	struct page_snapshot s;

	memset(&s, 0, sizeof(s));

	uint64_t vpn = (uint64_t) (uintptr_t) address / page_size;

	s.raw = read_indexed_u64(pagemap_fd, vpn, "pagemap");

	s.pfn = s.raw & PM_PFN_MASK;

	s.present = !!(s.raw & PM_PRESENT);

	s.exclusive = !!(s.raw & PM_EXCLUSIVE);

	s.file_or_shared_anon = !!(s.raw & PM_FILE_OR_SHANON);

	if (s.present && s.pfn != 0) {

		s.physical_valid = 1;

		s.count = read_indexed_u64(kpagecount_fd, s.pfn, "kpagecount");

		s.flags = read_indexed_u64(kpageflags_fd, s.pfn, "kpageflags");
	}

	return s;
}

static void print_page(const char *name, const struct page_snapshot *s)
{
	printf("\n========== %s ==========\n", name);

	printf("pagemap raw          : 0x%016" PRIx64 "\n", s->raw);

	printf("present              : %d\n", s->present);

	printf("exclusive            : %d\n", s->exclusive);

	printf("file/shared-anon     : %d\n", s->file_or_shared_anon);

	printf("PFN                  : 0x%011" PRIx64 "\n", s->pfn);

	if (!s->physical_valid) {
		printf("kpagecount           : N/A\n");
		printf("kpageflags           : N/A\n");
		return;
	}

	printf("kpagecount           : %" PRIu64 "\n", s->count);

	printf("kpageflags raw       : 0x%016" PRIx64 "\n", s->flags);

	printf("KPF_DIRTY            : %d\n", flag_set(s->flags, KPF_DIRTY));

	printf("KPF_LRU              : %d\n", flag_set(s->flags, KPF_LRU));

	printf("KPF_MMAP             : %d\n", flag_set(s->flags, KPF_MMAP));

	printf("KPF_ANON             : %d\n", flag_set(s->flags, KPF_ANON));

	printf("KPF_SWAPBACKED       : %d\n",
	       flag_set(s->flags, KPF_SWAPBACKED));
}

static void read_smaps(const void *address, struct smaps_info *info)
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

		} else if (sscanf(line, "Shared_Clean: %lu kB", &value) == 1) {

			info->shared_clean_kb = value;

		} else if (sscanf(line, "Shared_Dirty: %lu kB", &value) == 1) {

			info->shared_dirty_kb = value;

		} else if (sscanf(line, "Private_Clean: %lu kB", &value) == 1) {

			info->private_clean_kb = value;

		} else if (sscanf(line, "Private_Dirty: %lu kB", &value) == 1) {

			info->private_dirty_kb = value;

		} else if (sscanf(line, "Anonymous: %lu kB", &value) == 1) {

			info->anonymous_kb = value;

		} else if (strncmp(line, "VmFlags:", 8) == 0) {
			break;
		}
	}

	fclose(fp);
}

static void print_smaps(const char *name, const void *address)
{
	struct smaps_info s;

	read_smaps(address, &s);

	printf("\n========== %s ==========\n", name);

	printf("mapping              : %s\n", s.header);

	printf("Rss                  : %lu kB\n", s.rss_kb);

	printf("Pss                  : %lu kB\n", s.pss_kb);

	printf("Shared_Clean         : %lu kB\n", s.shared_clean_kb);

	printf("Shared_Dirty         : %lu kB\n", s.shared_dirty_kb);

	printf("Private_Clean        : %lu kB\n", s.private_clean_kb);

	printf("Private_Dirty        : %lu kB\n", s.private_dirty_kb);

	printf("Anonymous            : %lu kB\n", s.anonymous_kb);
}

/*
 * Use an isolated one-page anonymous VMA, surrounded by
 * PROT_NONE guards, so its smaps counters represent exactly
 * this single page.
 */
static volatile uint32_t *map_guarded_private_anon(size_t page_size,
						   void **reservation_out)
{
	unsigned char *reservation = mmap(NULL,
					  3 * page_size,
					  PROT_NONE,
					  MAP_PRIVATE | MAP_ANONYMOUS,
					  -1,
					  0);

	if (reservation == MAP_FAILED)
		die("mmap guard reservation");

	void *middle = reservation + page_size;

	void *mapped = mmap(middle,
			    page_size,
			    PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
			    -1,
			    0);

	if (mapped == MAP_FAILED)
		die("mmap guarded anon");

	*reservation_out = reservation;

	return (volatile uint32_t *)mapped;
}

static void force_local_drain(volatile uint32_t * control, size_t page_size)
{
	if (mlock((const void *)control, page_size) != 0) {
		die("mlock control");
	}

	if (munlock((const void *)control, page_size) != 0) {
		die("munlock control");
	}
}

static uint32_t pread_u32(int fd, off_t offset)
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

static void print_store_faults(const char *name,
			       struct usage_snapshot before,
			       struct usage_snapshot after)
{
	printf("\n========== %s ==========\n", name);

	printf("minor faults         : %ld\n", after.minflt - before.minflt);

	printf("major faults         : %ld\n", after.majflt - before.majflt);
}

int main(void)
{
	const char *path = "stage6_4_3_sparse.bin";

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

	/*
	 * Control page used only as the already-validated local
	 * LRU/mlock batch drain trigger.
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
	 * Sparse two-page tmpfs file.
	 *
	 * Deliberately DO NOT pwrite() it.  Both pages begin as holes.
	 */
	unlink(path);

	int fd = open(path,
		      O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC,
		      0600);

	if (fd < 0)
		die("open sparse file");

	if (ftruncate(fd, (off_t) (2 * page_size)) != 0) {
		die("ftruncate");
	}

	/*
	 * ---------------------------------------------------------
	 * A. isolated private anonymous page.
	 * ---------------------------------------------------------
	 */
	void *anon_reservation = NULL;

	volatile uint32_t *anon = map_guarded_private_anon(page_size,
							   &anon_reservation);

	/*
	 * ---------------------------------------------------------
	 * B. page0: two MAP_SHARED aliases of the SAME sparse
	 * tmpfs page.
	 * ---------------------------------------------------------
	 */
	volatile uint32_t *shared_a = mmap(NULL,
					   page_size,
					   PROT_READ | PROT_WRITE,
					   MAP_SHARED,
					   fd,
					   0);

	if (shared_a == MAP_FAILED)
		die("mmap shared A");

	volatile uint32_t *shared_b = mmap(NULL,
					   page_size,
					   PROT_READ | PROT_WRITE,
					   MAP_SHARED,
					   fd,
					   0);

	if (shared_b == MAP_FAILED)
		die("mmap shared B");

	/*
	 * ---------------------------------------------------------
	 * C. page1:
	 * one MAP_PRIVATE COW mapping
	 * plus one shared observer of the old file PFN.
	 * ---------------------------------------------------------
	 */
	volatile uint32_t *private_file = mmap(NULL,
					       page_size,
					       PROT_READ | PROT_WRITE,
					       MAP_PRIVATE,
					       fd,
					       (off_t) page_size);

	if (private_file == MAP_FAILED)
		die("mmap private file");

	volatile uint32_t *file_observer = mmap(NULL,
						page_size,
						PROT_READ,
						MAP_SHARED,
						fd,
						(off_t) page_size);

	if (file_observer == MAP_FAILED)
		die("mmap file observer");

	printf("PID                  : %ld\n", (long)getpid());

	printf("page size            : %zu\n", page_size);

	printf("file                 : %s\n", path);

	printf("anon                 : %p\n", (const void *)anon);

	printf("shared A             : %p\n", (const void *)shared_a);

	printf("shared B             : %p\n", (const void *)shared_b);

	printf("private file         : %p\n", (const void *)private_file);

	printf("file observer        : %p\n", (const void *)file_observer);

	/*
	 * =========================================================
	 * CASE A
	 * private anonymous Store
	 * =========================================================
	 */
	printf("\n##################################################\n"
	       "# CASE A: private anonymous\n"
	       "##################################################\n");

	struct usage_snapshot a_before = usage_now();

	*anon = 0xa1a1a1a1U;

	struct usage_snapshot a_after = usage_now();

	print_store_faults("A1. first anon Store", a_before, a_after);

	force_local_drain(control, page_size);

	struct page_snapshot anon_page = snapshot_page((const void *)anon,
						       page_size,
						       pagemap_fd,
						       kpagecount_fd,
						       kpageflags_fd);

	struct smaps_info anon_smaps;

	read_smaps((const void *)anon, &anon_smaps);

	print_page("A2. private anon physical state", &anon_page);

	print_smaps("A3. private anon smaps", (const void *)anon);

	/*
	 * =========================================================
	 * CASE B
	 * shared clean shmem page -> shared dirty page
	 * =========================================================
	 */
	printf("\n##################################################\n"
	       "# CASE B: shared tmpfs clean -> dirty\n"
	       "##################################################\n");

	/*
	 * Read both aliases only.  This materializes page0 and maps
	 * the same clean shmem folio into both VMAs.
	 */
	sink += *shared_a;
	sink += *shared_b;

	force_local_drain(control, page_size);

	struct page_snapshot sb_before_a = snapshot_page((const void *)shared_a,
							 page_size,
							 pagemap_fd,
							 kpagecount_fd,
							 kpageflags_fd);

	struct page_snapshot sb_before_b = snapshot_page((const void *)shared_b,
							 page_size,
							 pagemap_fd,
							 kpagecount_fd,
							 kpageflags_fd);

	struct smaps_info sb_smaps_before;

	read_smaps((const void *)shared_a, &sb_smaps_before);

	print_page("B1. shared A after read-only prefault", &sb_before_a);

	print_page("B2. shared B after read-only prefault", &sb_before_b);

	print_smaps("B3. shared A smaps before Store", (const void *)shared_a);

	printf("\nB baseline same PFN   : %s\n",
	       sb_before_a.pfn == sb_before_b.pfn ? "yes" : "NO");

	printf("B backing before     : 0x%08x\n", pread_u32(fd, 0));

	struct usage_snapshot b_before = usage_now();

	*shared_a = 0xb1b1b1b1U;

	struct usage_snapshot b_after = usage_now();

	print_store_faults("B4. first shared Store", b_before, b_after);

	force_local_drain(control, page_size);

	struct page_snapshot sb_after_a = snapshot_page((const void *)shared_a,
							page_size,
							pagemap_fd,
							kpagecount_fd,
							kpageflags_fd);

	struct page_snapshot sb_after_b = snapshot_page((const void *)shared_b,
							page_size,
							pagemap_fd,
							kpagecount_fd,
							kpageflags_fd);

	struct smaps_info sb_smaps_after;

	read_smaps((const void *)shared_a, &sb_smaps_after);

	print_page("B5. shared A after Store", &sb_after_a);

	print_page("B6. shared B after Store", &sb_after_b);

	print_smaps("B7. shared A smaps after Store", (const void *)shared_a);

	printf("\nB A value             : 0x%08x\n", *shared_a);

	printf("B B value             : 0x%08x\n", *shared_b);

	printf("B backing after      : 0x%08x\n", pread_u32(fd, 0));

	/*
	 * =========================================================
	 * CASE C
	 * clean file page -> private anonymous COW
	 * =========================================================
	 */
	printf("\n##################################################\n"
	       "# CASE C: private file -> COW anon\n"
	       "##################################################\n");

	sink += *private_file;
	sink += *file_observer;

	force_local_drain(control, page_size);

	struct page_snapshot c_private_before =
	    snapshot_page((const void *)private_file,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot c_observer_before =
	    snapshot_page((const void *)file_observer,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	print_page("C1. private file before COW", &c_private_before);

	print_page("C2. observer before COW", &c_observer_before);

	print_smaps("C3. private VMA before COW", (const void *)private_file);

	printf("\nC baseline same PFN   : %s\n",
	       c_private_before.pfn == c_observer_before.pfn ? "yes" : "NO");

	struct usage_snapshot c_before = usage_now();

	*private_file = 0xc1c1c1c1U;

	struct usage_snapshot c_after = usage_now();

	print_store_faults("C4. private file first Store / COW",
			   c_before, c_after);

	force_local_drain(control, page_size);

	struct page_snapshot c_private_after =
	    snapshot_page((const void *)private_file,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct page_snapshot c_observer_after =
	    snapshot_page((const void *)file_observer,
			  page_size,
			  pagemap_fd,
			  kpagecount_fd,
			  kpageflags_fd);

	struct smaps_info c_smaps_after;

	read_smaps((const void *)private_file, &c_smaps_after);

	print_page("C5. private COW anon after Store", &c_private_after);

	print_page("C6. old file PFN via observer", &c_observer_after);

	print_smaps("C7. private VMA after COW", (const void *)private_file);

	printf("\nC private value       : 0x%08x\n", *private_file);

	printf("C observer value      : 0x%08x\n", *file_observer);

	printf("C backing value       : 0x%08x\n",
	       pread_u32(fd, (off_t) page_size));

	/*
	 * =========================================================
	 * FINAL SEMANTIC CHECKS
	 * =========================================================
	 */

	int a_pgdirty_zero =
	    anon_page.physical_valid && !flag_set(anon_page.flags,
						  KPF_DIRTY);

	int a_smaps_dirty = anon_smaps.private_dirty_kb == page_size / 1024;

	int a_pte_dirty_inferred = a_pgdirty_zero && a_smaps_dirty;

	int b_clean_baseline =
	    sb_before_a.pfn ==
	    sb_before_b.pfn &&
	    sb_before_a.count == 2 && !flag_set(sb_before_a.flags,
						KPF_DIRTY);

	int b_pgdirty_0_to_1 = !flag_set(sb_before_a.flags,
					 KPF_DIRTY) &&
	    flag_set(sb_after_a.flags,
		     KPF_DIRTY);

	int b_same_pfn =
	    sb_before_a.pfn ==
	    sb_after_a.pfn && sb_after_a.pfn == sb_after_b.pfn;

	int b_shared_dirty = sb_smaps_after.shared_dirty_kb == page_size / 1024;

	int b_visibility =
	    *shared_b == 0xb1b1b1b1U && pread_u32(fd, 0) == 0xb1b1b1b1U;

	int c_true_cow =
	    c_private_before.pfn ==
	    c_observer_before.pfn &&
	    c_private_after.pfn !=
	    c_private_before.pfn &&
	    c_observer_after.pfn == c_private_before.pfn;

	int c_new_anon = flag_set(c_private_after.flags,
				  KPF_ANON) &&
	    !c_private_after.file_or_shared_anon;

	int c_pgdirty_zero = !flag_set(c_private_after.flags,
				       KPF_DIRTY);

	int c_smaps_dirty = c_smaps_after.private_dirty_kb == page_size / 1024;

	int c_pte_dirty_inferred = c_pgdirty_zero && c_smaps_dirty;

	int c_backing_unchanged = *file_observer == 0 && pread_u32(fd,
								   (off_t)
								   page_size) ==
	    0;

	printf("\n========== final semantic summary ==========\n");

	printf("A anon KPF_DIRTY remains 0             : %s\n",
	       a_pgdirty_zero ? "yes" : "NO");

	printf("A anon smaps Private_Dirty = 4K        : %s\n",
	       a_smaps_dirty ? "yes" : "NO");

	printf("A PTE dirty inferred while PG_dirty=0  : %s\n",
	       a_pte_dirty_inferred ? "yes" : "NO");

	printf("B shared baseline KPF_DIRTY=0/count=2  : %s\n",
	       b_clean_baseline ? "yes" : "NO");

	printf("B shared Store KPF_DIRTY 0->1          : %s\n",
	       b_pgdirty_0_to_1 ? "yes" : "NO");

	printf("B shared Store keeps same PFN          : %s\n",
	       b_same_pfn ? "yes" : "NO");

	printf("B smaps Shared_Dirty = 4K              : %s\n",
	       b_shared_dirty ? "yes" : "NO");

	printf("B Store visible via alias + pread      : %s\n",
	       b_visibility ? "yes" : "NO");

	printf("C private file performs true COW       : %s\n",
	       c_true_cow ? "yes" : "NO");

	printf("C new page is anonymous                : %s\n",
	       c_new_anon ? "yes" : "NO");

	printf("C new anon KPF_DIRTY remains 0         : %s\n",
	       c_pgdirty_zero ? "yes" : "NO");

	printf("C new anon smaps Private_Dirty = 4K    : %s\n",
	       c_smaps_dirty ? "yes" : "NO");

	printf("C PTE dirty inferred while PG_dirty=0  : %s\n",
	       c_pte_dirty_inferred ? "yes" : "NO");

	printf("C private COW leaves backing clean     : %s\n",
	       c_backing_unchanged ? "yes" : "NO");

	printf("\n========== dirty-layer interpretation ==========\n");

	printf("A: CPU Store -> smaps dirty=%s, KPF_DIRTY=%d\n",
	       a_smaps_dirty ? "yes" : "no",
	       flag_set(anon_page.flags, KPF_DIRTY));

	printf("B: shared Store -> smaps dirty=%s, KPF_DIRTY=%d\n",
	       b_shared_dirty ? "yes" : "no",
	       flag_set(sb_after_a.flags, KPF_DIRTY));

	printf("C: COW Store -> smaps dirty=%s, KPF_DIRTY=%d\n",
	       c_smaps_dirty ? "yes" : "no",
	       flag_set(c_private_after.flags, KPF_DIRTY));

	printf("\nsink                 : %" PRIu64 "\n", sink);

	/*
	 * Cleanup.
	 */
	munmap((void *)file_observer, page_size);

	munmap((void *)private_file, page_size);

	munmap((void *)shared_b, page_size);

	munmap((void *)shared_a, page_size);

	/*
	 * The complete 3-page reservation still exists;
	 * middle page merely has different protection/mapping.
	 */
	munmap(anon_reservation, 3 * page_size);

	munmap((void *)control, page_size);

	close(fd);
	unlink(path);

	close(kpageflags_fd);
	close(kpagecount_fd);
	close(pagemap_fd);

	return EXIT_SUCCESS;
}
