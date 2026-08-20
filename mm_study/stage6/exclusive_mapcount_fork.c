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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_PAGES 4

#define PM_PFN_MASK       ((1ULL << 55) - 1ULL)
#define PM_EXCLUSIVE      (1ULL << 56)
#define PM_FILE_OR_SHANON (1ULL << 61)
#define PM_SWAPPED        (1ULL << 62)
#define PM_PRESENT        (1ULL << 63)

struct usage_snapshot {
	long minflt;
	long majflt;
};

struct fault_delta {
	long minflt;
	long majflt;
};

struct page_observation {
	int valid;

	uint64_t raw;
	uint64_t pfn;

	int present;
	int swapped;
	int exclusive;
	int file_or_shared_anon;

	int count_valid;
	uint64_t kpagecount;
};

struct process_snapshot {
	pid_t pid;
	int available;

	struct page_observation page[TEST_PAGES];
};

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
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

static volatile uint32_t *page_ptr(volatile unsigned char *mapping,
				   size_t page_size, size_t page)
{
	return (volatile uint32_t *)
	    (mapping + page * page_size);
}

static uint64_t read_u64_at(int fd, uint64_t index, const char *what)
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

static uint64_t read_kpagecount(int fd, uint64_t pfn)
{
	return read_u64_at(fd, pfn, "kpagecount");
}

static void decode_pagemap(uint64_t raw, struct page_observation *obs)
{
	memset(obs, 0, sizeof(*obs));

	obs->valid = 1;
	obs->raw = raw;

	obs->pfn = raw & PM_PFN_MASK;

	obs->present = !!(raw & PM_PRESENT);

	obs->swapped = !!(raw & PM_SWAPPED);

	obs->exclusive = !!(raw & PM_EXCLUSIVE);

	obs->file_or_shared_anon = !!(raw & PM_FILE_OR_SHANON);
}

static int capture_process(pid_t pid,
			   volatile unsigned char *mapping,
			   size_t page_size,
			   int kpagecount_fd, struct process_snapshot *snapshot)
{
	memset(snapshot, 0, sizeof(*snapshot));

	snapshot->pid = pid;

	char path[128];

	snprintf(path, sizeof(path), "/proc/%ld/pagemap", (long)pid);

	int fd = open(path,
		      O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;

	snapshot->available = 1;

	for (size_t page = 0; page < TEST_PAGES; ++page) {

		uintptr_t address = (uintptr_t)
		    (mapping + page * page_size);

		uint64_t vpn = address / page_size;

		uint64_t raw = read_u64_at(fd,
					   vpn,
					   "pagemap");

		decode_pagemap(raw, &snapshot->page[page]);

		if (snapshot->page[page].present &&
		    snapshot->page[page].pfn != 0) {

			snapshot->page[page].count_valid = 1;

			snapshot->page[page].kpagecount =
			    read_kpagecount(kpagecount_fd,
					    snapshot->page[page].pfn);
		}
	}

	close(fd);

	return 0;
}

static void print_single_snapshot(const char *name,
				  const struct process_snapshot *snapshot)
{
	printf("\n========== %s ==========\n", name);

	printf("PID                  : %ld\n", (long)snapshot->pid);

	if (!snapshot->available) {
		printf("pagemap              : unavailable\n");
		return;
	}

	printf("page  PFN           present excl count " "file/shanon\n");

	for (size_t page = 0; page < TEST_PAGES; ++page) {

		const struct page_observation *p = &snapshot->page[page];

		printf("%-5zu "
		       "0x%011" PRIx64 " "
		       "%-7d " "%-4d ", page, p->pfn, p->present, p->exclusive);

		if (p->count_valid)
			printf("%-5" PRIu64 " ", p->kpagecount);
		else
			printf("%-5s ", "N/A");

		printf("%d\n", p->file_or_shared_anon);
	}
}

static void print_pair_snapshot(const char *name,
				const struct process_snapshot *parent,
				const struct process_snapshot *child)
{
	printf("\n========== %s ==========\n", name);

	printf("page | parent PFN   ex cnt | " "child PFN    ex cnt | same\n");

	for (size_t page = 0; page < TEST_PAGES; ++page) {

		const struct page_observation *p = &parent->page[page];

		const struct page_observation *c = &child->page[page];

		printf("%-4zu | "
		       "%011" PRIx64 "  %d  %-3" PRIu64
		       " | "
		       "%011" PRIx64 "  %d  %-3" PRIu64
		       " | %s\n",
		       page,
		       p->pfn,
		       p->exclusive,
		       p->count_valid ?
		       p->kpagecount : 0,
		       c->pfn,
		       c->exclusive,
		       c->count_valid ?
		       c->kpagecount : 0,
		       p->present &&
		       c->present && p->pfn == c->pfn ? "yes" : "no");
	}
}

static struct fault_delta measure_store(volatile uint32_t * address,
					uint32_t value)
{
	struct usage_snapshot before = usage_now();

	*address = value;

	struct usage_snapshot after = usage_now();

	struct fault_delta result = {
		.minflt = after.minflt - before.minflt,

		.majflt = after.majflt - before.majflt
	};

	return result;
}

static void print_store_result(const char *name,
			       const struct fault_delta *faults,
			       const struct page_observation *before,
			       const struct page_observation *after)
{
	printf("\n========== %s ==========\n", name);

	printf("minor faults         : %ld\n", faults->minflt);

	printf("major faults         : %ld\n", faults->majflt);

	printf("before PFN           : 0x%011" PRIx64 "\n", before->pfn);

	printf("after PFN            : 0x%011" PRIx64 "\n", after->pfn);

	printf("PFN unchanged        : %s\n",
	       before->present &&
	       after->present && before->pfn == after->pfn ? "yes" : "no");

	printf("PFN changed          : %s\n",
	       before->present &&
	       after->present && before->pfn != after->pfn ? "yes" : "no");

	printf("before exclusive     : %d\n", before->exclusive);

	printf("after exclusive      : %d\n", after->exclusive);

	printf("before kpagecount    : %" PRIu64 "\n",
	       before->count_valid ? before->kpagecount : 0);

	printf("after kpagecount     : %" PRIu64 "\n",
	       after->count_valid ? after->kpagecount : 0);
}

static void write_byte(int fd, char value)
{
	ssize_t result = write(fd, &value, 1);

	if (result != 1)
		die("write pipe");
}

static char read_byte(int fd)
{
	char value = 0;

	ssize_t result = read(fd, &value, 1);

	if (result != 1)
		die("read pipe");

	return value;
}

static char read_proc_state(pid_t pid)
{
	char path[128];

	snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);

	FILE *fp = fopen(path, "r");

	if (fp == NULL)
		return '\0';

	char line[512];
	char state = '\0';

	while (fgets(line, sizeof(line), fp) != NULL) {

		if (strncmp(line, "State:", 6) == 0) {

			if (sscanf(line, "State:\t%c", &state) == 1) {
				break;
			}
		}
	}

	fclose(fp);

	return state;
}

static int wait_for_zombie(pid_t pid)
{
	/*
	 * Do NOT waitpid() here:
	 * we explicitly want to inspect the process while it
	 * is a zombie but before it is reaped.
	 */
	for (int i = 0; i < 10000; ++i) {

		char state = read_proc_state(pid);

		if (state == 'Z')
			return 1;

		if (state == '\0')
			return 0;

		usleep(1000);
	}

	return 0;
}

static void probe_zombie_pagemap(pid_t pid,
				 const void *address, size_t page_size)
{
	printf("\n========== child pagemap while zombie ==========\n");

	char path[128];

	snprintf(path, sizeof(path), "/proc/%ld/pagemap", (long)pid);

	errno = 0;

	int fd = open(path,
		      O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		printf("open pagemap         : failed "
		       "errno=%d (%s)\n", errno, strerror(errno));
		return;
	}

	uint64_t raw = 0;

	uint64_t vpn = (uint64_t) (uintptr_t) address / page_size;

	errno = 0;

	ssize_t result = pread(fd,
			       &raw,
			       sizeof(raw),
			       (off_t) (vpn * sizeof(raw)));

	int saved_errno = errno;

	close(fd);

	printf("pread return         : %zd\n", result);

	if (result < 0) {
		printf("errno                : %d (%s)\n",
		       saved_errno, strerror(saved_errno));
	} else if (result == (ssize_t) sizeof(raw)) {
		printf("raw pagemap          : 0x%016" PRIx64 "\n", raw);

		printf("present              : %d\n", !!(raw & PM_PRESENT));
	}

	/*
	 * No semantic pass/fail check here.
	 * Zombie /proc behavior is only observational.
	 */
}

static int all_shared_after_fork(const struct process_snapshot *parent,
				 const struct process_snapshot *child)
{
	for (size_t i = 0; i < TEST_PAGES; ++i) {

		const struct page_observation *p = &parent->page[i];

		const struct page_observation *c = &child->page[i];

		if (!p->present ||
		    !c->present ||
		    p->pfn != c->pfn ||
		    p->exclusive ||
		    c->exclusive || p->kpagecount != 2 || c->kpagecount != 2) {
			return 0;
		}
	}

	return 1;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0)
		die("sysconf");

	size_t page_size = (size_t)page_size_long;

	size_t length = TEST_PAGES * page_size;

	int kpagecount_fd = open("/proc/kpagecount",
				 O_RDONLY | O_CLOEXEC);

	if (kpagecount_fd < 0)
		die("open kpagecount");

	volatile unsigned char *mapping = mmap(NULL,
					       length,
					       PROT_READ | PROT_WRITE,
					       MAP_PRIVATE | MAP_ANONYMOUS,
					       -1,
					       0);

	if (mapping == MAP_FAILED)
		die("mmap");

	/*
	 * Pre-populate all four pages.
	 */
	for (size_t page = 0; page < TEST_PAGES; ++page) {

		*page_ptr(mapping,
			  page_size, page) = 0x10000000U + (uint32_t) page;
	}

	printf("parent PID           : %ld\n", (long)getpid());

	printf("page size            : %zu\n", page_size);

	printf("mapping              : %p\n", (const void *)mapping);

	for (size_t page = 0; page < TEST_PAGES; ++page) {

		printf("page%zu VA             : %p\n", page, (const void *)
		       page_ptr(mapping, page_size, page));
	}

	/*
	 * ---------------------------------------------------------
	 * 0. Before fork.
	 * ---------------------------------------------------------
	 */
	struct process_snapshot pre_fork;

	if (capture_process(getpid(),
			    mapping,
			    page_size, kpagecount_fd, &pre_fork) != 0) {
		die("capture pre-fork");
	}

	print_single_snapshot("0. parent before fork", &pre_fork);

	int parent_to_child[2];
	int child_to_parent[2];

	if (pipe(parent_to_child) != 0)
		die("pipe");

	if (pipe(child_to_parent) != 0)
		die("pipe");

	pid_t child = fork();

	if (child < 0)
		die("fork");

	/*
	 * =========================================================
	 * CHILD
	 * =========================================================
	 */
	if (child == 0) {
		close(parent_to_child[1]);
		close(child_to_parent[0]);

		/*
		 * Tell parent that fork is complete and child is now
		 * blocked, so page mappings remain stable.
		 */
		write_byte(child_to_parent[1], 'R');

		for (;;) {
			char command = read_byte(parent_to_child[0]);

			if (command == 'C') {
				/*
				 * Child true-COWs page0.
				 */
				*page_ptr(mapping, page_size, 0) = 0xc0c0c0c0U;

				write_byte(child_to_parent[1], 'C');

			} else if (command == 'Q') {
				_exit(0);

			} else {
				_exit(100);
			}
		}
	}

	/*
	 * =========================================================
	 * PARENT
	 * =========================================================
	 */
	close(parent_to_child[0]);
	close(child_to_parent[1]);

	char ready = read_byte(child_to_parent[0]);

	if (ready != 'R') {
		fprintf(stderr, "bad child ready byte\n");
		exit(EXIT_FAILURE);
	}

	printf("child PID            : %ld\n", (long)child);

	/*
	 * ---------------------------------------------------------
	 * 1. Immediately after fork.
	 * ---------------------------------------------------------
	 */
	struct process_snapshot after_fork_parent;
	struct process_snapshot after_fork_child;

	capture_process(getpid(),
			mapping, page_size, kpagecount_fd, &after_fork_parent);

	capture_process(child,
			mapping, page_size, kpagecount_fd, &after_fork_child);

	print_pair_snapshot("1. after fork",
			    &after_fork_parent, &after_fork_child);

	/*
	 * ---------------------------------------------------------
	 * 2. Child COWs page0.
	 * ---------------------------------------------------------
	 */
	write_byte(parent_to_child[1], 'C');

	char cow_ack = read_byte(child_to_parent[0]);

	if (cow_ack != 'C') {
		fprintf(stderr, "bad child COW ack\n");
		exit(EXIT_FAILURE);
	}

	struct process_snapshot child_cow_parent;
	struct process_snapshot child_cow_child;

	capture_process(getpid(),
			mapping, page_size, kpagecount_fd, &child_cow_parent);

	capture_process(child,
			mapping, page_size, kpagecount_fd, &child_cow_child);

	print_pair_snapshot("2. after child COW page0",
			    &child_cow_parent, &child_cow_child);

	printf("\nparent page0 value   : 0x%08x "
	       "(expected 0x10000000)\n", *page_ptr(mapping, page_size, 0));

	/*
	 * ---------------------------------------------------------
	 * 3. Parent writes page0.
	 *
	 * At this point child already left the old PFN, therefore
	 * parent page0 should already have:
	 *
	 *   mapcount = 1
	 *   exclusive = 1
	 *
	 * but the inherited parent PTE can still be read-only.
	 * This is the key same-PFN reuse test.
	 * ---------------------------------------------------------
	 */
	struct page_observation p0_before = child_cow_parent.page[0];

	struct fault_delta p0_fault = measure_store(page_ptr(mapping,
							     page_size,
							     0),
						    0xa0a0a0a0U);

	struct process_snapshot p0_reuse_parent;
	struct process_snapshot p0_reuse_child;

	capture_process(getpid(),
			mapping, page_size, kpagecount_fd, &p0_reuse_parent);

	capture_process(child,
			mapping, page_size, kpagecount_fd, &p0_reuse_child);

	print_store_result("3. parent write page0 after child COW",
			   &p0_fault, &p0_before, &p0_reuse_parent.page[0]);

	print_pair_snapshot("3. state after parent page0 write",
			    &p0_reuse_parent, &p0_reuse_child);

	/*
	 * ---------------------------------------------------------
	 * 4. Parent writes page1 while child still maps old PFN.
	 * This should be true COW: count=2 before the Store.
	 * ---------------------------------------------------------
	 */
	struct page_observation p1_before = p0_reuse_parent.page[1];

	struct fault_delta p1_fault = measure_store(page_ptr(mapping,
							     page_size,
							     1),
						    0xb1b1b1b1U);

	struct process_snapshot parent_cow_parent;
	struct process_snapshot parent_cow_child;

	capture_process(getpid(),
			mapping, page_size, kpagecount_fd, &parent_cow_parent);

	capture_process(child,
			mapping, page_size, kpagecount_fd, &parent_cow_child);

	print_store_result("4. parent true COW page1",
			   &p1_fault, &p1_before, &parent_cow_parent.page[1]);

	print_pair_snapshot("4. state after parent COW page1",
			    &parent_cow_parent, &parent_cow_child);

	/*
	 * pages2/3 are still shared at this point.
	 */
	printf("\npage2 before child exit: "
	       "PFN=0x%011" PRIx64
	       " ex=%d count=%" PRIu64 "\n",
	       parent_cow_parent.page[2].pfn,
	       parent_cow_parent.page[2].exclusive,
	       parent_cow_parent.page[2].kpagecount);

	/*
	 * ---------------------------------------------------------
	 * 5. Child exits, but parent deliberately does NOT waitpid.
	 * ---------------------------------------------------------
	 */
	write_byte(parent_to_child[1], 'Q');

	int zombie = wait_for_zombie(child);

	printf("\n========== 5. child exit before waitpid ==========\n");

	printf("child zombie         : %s\n", zombie ? "yes" : "NO");

	printf("child state          : %c\n", read_proc_state(child));

	/*
	 * Observational only; we do not assume exactly how the
	 * zombie pagemap proc file behaves.
	 */
	probe_zombie_pagemap(child, (const void *)
			     page_ptr(mapping, page_size, 2), page_size);

	struct process_snapshot after_exit_parent;

	capture_process(getpid(),
			mapping, page_size, kpagecount_fd, &after_exit_parent);

	print_single_snapshot("5. parent while child is zombie",
			      &after_exit_parent);

	printf
	    ("\n========== 5. parent identity across child exit ==========\n");

	for (size_t page = 0; page < TEST_PAGES; ++page) {

		printf("page%zu PFN unchanged  : %s "
		       "(0x%011" PRIx64
		       " -> 0x%011" PRIx64 ")\n",
		       page,
		       parent_cow_parent.page[page].pfn ==
		       after_exit_parent.page[page].pfn ?
		       "yes" : "NO",
		       parent_cow_parent.page[page].pfn,
		       after_exit_parent.page[page].pfn);
	}

	printf("\npage2 after child exit : "
	       "PFN=0x%011" PRIx64
	       " ex=%d count=%" PRIu64 "\n",
	       after_exit_parent.page[2].pfn,
	       after_exit_parent.page[2].exclusive,
	       after_exit_parent.page[2].kpagecount);

	/*
	 * ---------------------------------------------------------
	 * 6. Parent writes page2 after child mm has disappeared.
	 *
	 * Expected:
	 *   before Store: exclusive=1, count=1
	 *   Store:        one minor fault
	 *   after Store:  same PFN
	 * ---------------------------------------------------------
	 */
	struct page_observation p2_before = after_exit_parent.page[2];

	struct fault_delta p2_fault = measure_store(page_ptr(mapping,
							     page_size,
							     2),
						    0xe2e2e2e2U);

	struct process_snapshot p2_after_parent;

	capture_process(getpid(),
			mapping, page_size, kpagecount_fd, &p2_after_parent);

	print_store_result("6. parent write page2 after child exit",
			   &p2_fault, &p2_before, &p2_after_parent.page[2]);

	/*
	 * Second Store should now be ordinary writable access.
	 */
	struct fault_delta p2_hot_fault = measure_store(page_ptr(mapping,
								 page_size,
								 2),
							0xe3e3e3e3U);

	printf("\n========== 7. second parent write page2 ==========\n");

	printf("minor faults         : %ld\n", p2_hot_fault.minflt);

	printf("major faults         : %ld\n", p2_hot_fault.majflt);

	/*
	 * ---------------------------------------------------------
	 * 8. Finally reap child.
	 * ---------------------------------------------------------
	 */
	int status = 0;

	pid_t waited = waitpid(child,
			       &status,
			       0);

	if (waited != child)
		die("waitpid");

	char proc_path[128];

	snprintf(proc_path, sizeof(proc_path), "/proc/%ld", (long)child);

	int proc_exists_after_wait = access(proc_path,
					    F_OK) == 0;

	printf("\n========== 8. after waitpid ==========\n");

	printf("waitpid child        : %ld\n", (long)waited);

	printf("child exited normally: %s\n", WIFEXITED(status) ? "yes" : "no");

	printf("child exit status    : %d\n",
	       WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	printf("/proc child exists   : %s\n",
	       proc_exists_after_wait ? "yes" : "no");

	/*
	 * ---------------------------------------------------------
	 * Final semantic checks.
	 * ---------------------------------------------------------
	 */
	int check_pre_fork = 1;

	for (size_t page = 0; page < TEST_PAGES; ++page) {

		if (!pre_fork.page[page].present ||
		    !pre_fork.page[page].exclusive ||
		    pre_fork.page[page].kpagecount != 1) {
			check_pre_fork = 0;
		}
	}

	int check_fork = all_shared_after_fork(&after_fork_parent,
					       &after_fork_child);

	int check_child_cow =
	    child_cow_parent.page[0].pfn !=
	    child_cow_child.page[0].pfn &&
	    child_cow_parent.page[0].exclusive &&
	    child_cow_child.page[0].exclusive &&
	    child_cow_parent.page[0].kpagecount == 1 &&
	    child_cow_child.page[0].kpagecount == 1;

	int check_parent_reuse =
	    p0_fault.minflt == 1 &&
	    p0_before.pfn == p0_reuse_parent.page[0].pfn;

	int check_parent_true_cow =
	    p1_fault.minflt == 1 &&
	    p1_before.pfn != parent_cow_parent.page[1].pfn;

	int check_exit_convergence =
	    parent_cow_parent.page[2].pfn ==
	    after_exit_parent.page[2].pfn &&
	    parent_cow_parent.page[2].kpagecount == 2 &&
	    !parent_cow_parent.page[2].exclusive &&
	    after_exit_parent.page[2].kpagecount == 1 &&
	    after_exit_parent.page[2].exclusive;

	int check_post_exit_reuse =
	    p2_fault.minflt == 1 &&
	    p2_before.pfn == p2_after_parent.page[2].pfn;

	int check_hot_write = p2_hot_fault.minflt == 0;

	printf("\n========== final semantic summary ==========\n");

	printf("pre-fork count1/exclusive1       : %s\n",
	       check_pre_fork ? "yes" : "NO");

	printf("fork count2/exclusive0           : %s\n",
	       check_fork ? "yes" : "NO");

	printf("child COW gives two exclusive PFNs: %s\n",
	       check_child_cow ? "yes" : "NO");

	printf("parent page0 same-PFN reuse      : %s\n",
	       check_parent_reuse ? "yes" : "NO");

	printf("parent page1 true COW            : %s\n",
	       check_parent_true_cow ? "yes" : "NO");

	printf("child exit count2->1/excl0->1    : %s\n",
	       check_exit_convergence ? "yes" : "NO");

	printf("post-exit page2 same-PFN reuse   : %s\n",
	       check_post_exit_reuse ? "yes" : "NO");

	printf("page2 second write no fault      : %s\n",
	       check_hot_write ? "yes" : "NO");

	printf("child /proc gone after waitpid   : %s\n",
	       !proc_exists_after_wait ? "yes" : "NO");

	printf("\nfinal parent values:\n");

	for (size_t page = 0; page < TEST_PAGES; ++page) {

		printf("page%zu                : 0x%08x\n",
		       page, *page_ptr(mapping, page_size, page));
	}

	close(parent_to_child[1]);
	close(child_to_parent[0]);

	munmap((void *)mapping, length);

	close(kpagecount_fd);

	return EXIT_SUCCESS;
}
