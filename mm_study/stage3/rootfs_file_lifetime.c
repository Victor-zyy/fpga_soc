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
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "perf_counter.h"

#ifndef RAMFS_MAGIC
#define RAMFS_MAGIC 0x858458f6
#endif

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

struct usage_snapshot {
	long minor_faults;
	long major_faults;
};

struct signatures {
	uint64_t offset0_sum;
	uint64_t offset1_sum;
};

struct measurement {
	uint64_t cycles;
	uint64_t instructions;

	long minor_faults;
	long major_faults;

	struct signatures signatures;

	int result;
	int error_number;
};

struct mapping_stats {
	unsigned long size_kb;
	unsigned long rss_kb;
	unsigned long pss_kb;

	unsigned long shared_clean_kb;
	unsigned long shared_dirty_kb;
	unsigned long private_clean_kb;
	unsigned long private_dirty_kb;

	unsigned long referenced_kb;
	unsigned long anonymous_kb;
	unsigned long vm_pte_kb;

	char header[512];
	char vm_flags[256];
};

typedef unsigned char (*value_function)(size_t page);

static volatile uint64_t read_sink;

static int starts_with(const char *line, const char *prefix)
{
	return strncmp(line, prefix, strlen(prefix)) == 0;
}

static struct usage_snapshot get_usage_snapshot(void)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage) != 0) {
		perror("getrusage");
		exit(EXIT_FAILURE);
	}

	struct usage_snapshot result = {
		.minor_faults = usage.ru_minflt,
		.major_faults = usage.ru_majflt,
	};

	return result;
}

static void warm_up_proc_files(void)
{
	static const char *paths[] = {
		"/proc/self/status",
		"/proc/self/maps",
		"/proc/self/smaps"
	};

	char line[512];

	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
		FILE *fp = fopen(paths[i], "r");

		if (fp == NULL) {
			perror(paths[i]);
			exit(EXIT_FAILURE);
		}

		while (fgets(line, sizeof(line), fp) != NULL) ;

		fclose(fp);
	}
}

static unsigned long read_vm_pte(void)
{
	FILE *fp;
	char line[512];
	unsigned long value = 0;

	fp = fopen("/proc/self/status", "r");

	if (fp == NULL) {
		perror("fopen /proc/self/status");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmPTE: %lu kB", &value) == 1)
			break;
	}

	fclose(fp);
	return value;
}

static void read_mapping_stats(const void *address, struct mapping_stats *stats)
{
	FILE *fp;
	char line[512];

	uintptr_t target = (uintptr_t) address;
	int found = 0;

	memset(stats, 0, sizeof(*stats));

	fp = fopen("/proc/self/smaps", "r");

	if (fp == NULL) {
		perror("fopen /proc/self/smaps");
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		unsigned long start;
		unsigned long end;

		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			if (found)
				break;

			if (target >= (uintptr_t) start &&
			    target < (uintptr_t) end) {
				found = 1;

				snprintf(stats->header,
					 sizeof(stats->header), "%s", line);

				stats->header[strcspn(stats->header, "\n")] =
				    '\0';
			}

			continue;
		}

		if (!found)
			continue;

		if (starts_with(line, "Size:")) {
			(void)sscanf(line, "Size: %lu kB", &stats->size_kb);
		} else if (starts_with(line, "Rss:")) {
			(void)sscanf(line, "Rss: %lu kB", &stats->rss_kb);
		} else if (starts_with(line, "Pss:")) {
			(void)sscanf(line, "Pss: %lu kB", &stats->pss_kb);
		} else if (starts_with(line, "Shared_Clean:")) {
			(void)sscanf(line, "Shared_Clean: %lu kB",
				     &stats->shared_clean_kb);
		} else if (starts_with(line, "Shared_Dirty:")) {
			(void)sscanf(line, "Shared_Dirty: %lu kB",
				     &stats->shared_dirty_kb);
		} else if (starts_with(line, "Private_Clean:")) {
			(void)sscanf(line, "Private_Clean: %lu kB",
				     &stats->private_clean_kb);
		} else if (starts_with(line, "Private_Dirty:")) {
			(void)sscanf(line, "Private_Dirty: %lu kB",
				     &stats->private_dirty_kb);
		} else if (starts_with(line, "Referenced:")) {
			(void)sscanf(line, "Referenced: %lu kB",
				     &stats->referenced_kb);
		} else if (starts_with(line, "Anonymous:")) {
			(void)sscanf(line, "Anonymous: %lu kB",
				     &stats->anonymous_kb);
		} else if (starts_with(line, "VmFlags:")) {
			snprintf(stats->vm_flags,
				 sizeof(stats->vm_flags),
				 "%s", line + strlen("VmFlags:"));

			stats->vm_flags[strcspn(stats->vm_flags, "\n")] = '\0';
		}
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr,
			"Could not find mapping containing %p\n", address);

		exit(EXIT_FAILURE);
	}

	stats->vm_pte_kb = read_vm_pte();
}

static void print_mapping_stats(const char *name,
				const struct mapping_stats *stats,
				unsigned long vm_pte_baseline)
{
	printf("\n========== %s ==========\n", name);

	printf("mapping              : %s\n", stats->header);
	printf("Size                 : %lu kB\n", stats->size_kb);
	printf("Rss                  : %lu kB\n", stats->rss_kb);
	printf("Pss                  : %lu kB\n", stats->pss_kb);

	printf("Shared_Clean         : %lu kB\n", stats->shared_clean_kb);
	printf("Shared_Dirty         : %lu kB\n", stats->shared_dirty_kb);
	printf("Private_Clean        : %lu kB\n", stats->private_clean_kb);
	printf("Private_Dirty        : %lu kB\n", stats->private_dirty_kb);

	printf("Referenced           : %lu kB\n", stats->referenced_kb);
	printf("Anonymous            : %lu kB\n", stats->anonymous_kb);

	printf("VmPTE                : %lu kB\n", stats->vm_pte_kb);
	printf("VmPTE delta          : %ld kB\n",
	       (long)stats->vm_pte_kb - (long)vm_pte_baseline);

	printf("VmFlags              :%s\n", stats->vm_flags);
}

static const char *filesystem_name(long type)
{
	if ((unsigned long)type == (unsigned long)RAMFS_MAGIC) {
		return "ramfs";
	}

	if ((unsigned long)type == (unsigned long)TMPFS_MAGIC) {
		return "tmpfs";
	}

	return "other/unknown";
}

static void print_filesystem_type(const char *path)
{
	struct statfs stats;

	if (statfs(path, &stats) != 0) {
		perror("statfs");
		exit(EXIT_FAILURE);
	}

	printf("filesystem type      : %s\n",
	       filesystem_name((long)stats.f_type));

	printf("filesystem magic     : 0x%lx\n", (unsigned long)stats.f_type);
}

static void print_file_identity(const char *name, int fd)
{
	struct stat stats;

	if (fstat(fd, &stats) != 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	printf("\n========== %s ==========\n", name);

	printf("device               : %u:%u\n",
	       major(stats.st_dev), minor(stats.st_dev));
	printf("inode                : %" PRIuMAX "\n",
	       (uintmax_t) stats.st_ino);
	printf("link count           : %" PRIuMAX "\n",
	       (uintmax_t) stats.st_nlink);
	printf("size                 : %" PRIuMAX " bytes\n",
	       (uintmax_t) stats.st_size);
}

static ino_t read_inode_number(int fd)
{
	struct stat stats;

	if (fstat(fd, &stats) != 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	return stats.st_ino;
}

static void print_path_lookup(const char *path)
{
	struct stat stats;

	errno = 0;

	int result = lstat(path, &stats);
	int saved_errno = errno;

	printf("path lookup          : %s\n",
	       result == 0 ? "exists" : "missing");

	if (result == 0) {
		printf("path inode           : %" PRIuMAX "\n",
		       (uintmax_t) stats.st_ino);
		printf("path link count      : %" PRIuMAX "\n",
		       (uintmax_t) stats.st_nlink);
	} else {
		printf("path errno           : %d (%s)\n",
		       saved_errno, strerror(saved_errno));
	}
}

static size_t count_mincore_resident(void *address,
				     size_t length, size_t page_size)
{
	size_t pages = length / page_size;

	unsigned char *vector = calloc(pages, sizeof(*vector));

	if (vector == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}

	if (mincore(address, length, vector) != 0) {
		perror("mincore");
		free(vector);
		exit(EXIT_FAILURE);
	}

	size_t resident = 0;

	for (size_t page = 0; page < pages; ++page) {
		if (vector[page] & 1U)
			++resident;
	}

	free(vector);
	return resident;
}

static unsigned char old_value(size_t page)
{
	return (unsigned char)((page % 251U) + 1U);
}

static unsigned char replacement_value(size_t page)
{
	return (unsigned char)(old_value(page) ^ 0xa5U);
}

static struct signatures expected_signatures(size_t pages,
					     value_function value_fn)
{
	struct signatures result = { 0, 0 };

	for (size_t page = 0; page < pages; ++page) {
		unsigned char value = value_fn(page);

		result.offset0_sum += value;
		result.offset1_sum += value;
	}

	return result;
}

static int signatures_equal(struct signatures left, struct signatures right)
{
	return left.offset0_sum == right.offset0_sum &&
	    left.offset1_sum == right.offset1_sum;
}

static void print_signature_check(const char *name,
				  struct signatures actual,
				  struct signatures expected)
{
	printf("\n========== %s ==========\n", name);

	printf("offset 0 sum         : %" PRIu64 "\n", actual.offset0_sum);
	printf("expected offset 0    : %" PRIu64 "\n", expected.offset0_sum);

	printf("offset 1 sum         : %" PRIu64 "\n", actual.offset1_sum);
	printf("expected offset 1    : %" PRIu64 "\n", expected.offset1_sum);

	printf("signature valid      : %s\n",
	       signatures_equal(actual, expected) ? "yes" : "NO");
}

static void pwrite_full(int fd, const void *buffer, size_t length, off_t offset)
{
	const unsigned char *current = buffer;
	size_t remaining = length;

	while (remaining != 0) {
		ssize_t result = pwrite(fd,
					current,
					remaining,
					offset);

		if (result < 0) {
			if (errno == EINTR)
				continue;

			perror("pwrite");
			exit(EXIT_FAILURE);
		}

		if (result == 0) {
			fprintf(stderr, "pwrite returned zero\n");
			exit(EXIT_FAILURE);
		}

		current += result;
		remaining -= (size_t)result;
		offset += result;
	}
}

static void initialize_file(int fd,
			    size_t pages,
			    size_t page_size, value_function value_fn)
{
	unsigned char *buffer = malloc(page_size);

	if (buffer == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for (size_t page = 0; page < pages; ++page) {
		memset(buffer, value_fn(page), page_size);

		pwrite_full(fd, buffer, page_size, (off_t) (page * page_size));
	}

	free(buffer);
}

static struct signatures read_fd_signatures(int fd,
					    size_t pages, size_t page_size)
{
	struct signatures result = { 0, 0 };

	for (size_t page = 0; page < pages; ++page) {
		unsigned char values[2];

		ssize_t read_result = pread(fd,
					    values,
					    sizeof(values),
					    (off_t) (page * page_size));

		if (read_result != (ssize_t) sizeof(values)) {
			if (read_result < 0)
				perror("pread");
			else
				fprintf(stderr,
					"short pread: %zd\n", read_result);

			exit(EXIT_FAILURE);
		}

		result.offset0_sum += values[0];
		result.offset1_sum += values[1];
	}

	return result;
}

static struct measurement measure_mapping_read(struct perf_group *perf_group,
					       volatile unsigned char *memory,
					       size_t pages, size_t page_size)
{
	struct measurement result;
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = 0; page < pages; ++page) {
		size_t offset = page * page_size;

		result.signatures.offset0_sum += memory[offset];

		result.signatures.offset1_sum += memory[offset + 1];
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	read_sink +=
	    result.signatures.offset0_sum + result.signatures.offset1_sum;

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	return result;
}

static struct measurement measure_dontneed(struct perf_group *perf_group,
					   void *memory, size_t length)
{
	struct measurement result;
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	errno = 0;

	result.result = madvise(memory, length, MADV_DONTNEED);

	result.error_number = errno;

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	return result;
}

static void print_measurement(const char *name,
			      const struct measurement *measurement,
			      size_t pages)
{
	printf("\n========== %s ==========\n", name);

	printf("return value          : %d\n", measurement->result);

	if (measurement->result != 0) {
		printf("errno                 : %d (%s)\n",
		       measurement->error_number,
		       strerror(measurement->error_number));
	}

	printf("minor faults         : %ld\n", measurement->minor_faults);
	printf("major faults         : %ld\n", measurement->major_faults);

	printf("cycles               : %" PRIu64 "\n", measurement->cycles);
	printf("instructions         : %" PRIu64 "\n",
	       measurement->instructions);

	if (pages != 0) {
		printf("cycles/page          : %.2f\n",
		       (double)measurement->cycles / (double)pages);

		printf("instructions/page    : %.2f\n",
		       (double)measurement->instructions / (double)pages);
	}

	printf("offset 0 sum         : %" PRIu64 "\n",
	       measurement->signatures.offset0_sum);
	printf("offset 1 sum         : %" PRIu64 "\n",
	       measurement->signatures.offset1_sum);
}

static int drop_global_caches(void)
{
	const char command[] = "3\n";

	sync();

	int fd = open("/proc/sys/vm/drop_caches",
		      O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;

	ssize_t result = write(fd,
			       command,
			       sizeof(command) - 1);

	int saved_errno = errno;

	close(fd);

	if (result != (ssize_t) (sizeof(command) - 1)) {
		errno = saved_errno;
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	int use_drop_caches = 0;

	if (argc >= 2)
		size_mib = (size_t)strtoul(argv[1], NULL, 0);

	if (argc >= 3) {
		if (strcmp(argv[2], "drop") == 0)
			use_drop_caches = 1;
		else if (strcmp(argv[2], "nodrop") != 0) {
			fprintf(stderr,
				"Second argument must be "
				"\"drop\" or \"nodrop\"\n");

			return EXIT_FAILURE;
		}
	}

	if (argc > 3 || size_mib == 0) {
		fprintf(stderr, "Usage: %s [MiB] [drop|nodrop]\n", argv[0]);

		return EXIT_FAILURE;
	}

	setvbuf(stdout, NULL, _IONBF, 0);

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0) {
		perror("sysconf");
		return EXIT_FAILURE;
	}

	size_t page_size = (size_t)page_size_long;
	size_t length = size_mib * 1024UL * 1024UL;

	length -= length % page_size;

	size_t pages = length / page_size;

	char path[128];

	snprintf(path,
		 sizeof(path), "/rootfs_file_lifetime_%ld.bin", (long)getpid());

	(void)unlink(path);

	int old_fd = open(path,
			  O_CREAT | O_EXCL | O_RDWR,
			  0600);

	if (old_fd < 0) {
		perror("open old file");
		return EXIT_FAILURE;
	}

	if (ftruncate(old_fd, (off_t) length) != 0) {
		perror("ftruncate old file");
		return EXIT_FAILURE;
	}

	initialize_file(old_fd, pages, page_size, old_value);

	print_filesystem_type(path);

	struct perf_group perf_group;
	struct perf_counts warmup_counts;

	if (perf_group_open(&perf_group) != 0)
		return EXIT_FAILURE;

	if (perf_group_start(&perf_group) != 0)
		return EXIT_FAILURE;

	asm volatile ("":::"memory");

	if (perf_group_stop(&perf_group, &warmup_counts) != 0) {
		return EXIT_FAILURE;
	}

	warm_up_proc_files();

	unsigned long vm_pte_baseline = read_vm_pte();

	volatile unsigned char *mapping = mmap(NULL,
					       length,
					       PROT_READ,
					       MAP_SHARED,
					       old_fd,
					       0);

	if (mapping == MAP_FAILED) {
		perror("mmap old file");
		return EXIT_FAILURE;
	}

	printf("PID                  : %ld\n", (long)getpid());
	printf("path                 : %s\n", path);
	printf("mapping address      : %p\n", (const void *)mapping);
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("page size            : %zu bytes\n", page_size);
	printf("pages                : %zu\n", pages);
	printf("drop_caches mode     : %s\n",
	       use_drop_caches ? "enabled" : "disabled");
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	ino_t old_inode = read_inode_number(old_fd);

	print_file_identity("1. old file before unlink", old_fd);

	struct mapping_stats mapping_stats;

	read_mapping_stats((const void *)mapping, &mapping_stats);

	print_mapping_stats("1. mapping immediately after mmap",
			    &mapping_stats, vm_pte_baseline);

	printf("mincore resident     : %zu / %zu pages\n",
	       count_mincore_resident((void *)mapping,
				      length, page_size), pages);

	struct signatures expected_old = expected_signatures(pages,
							     old_value);

	struct signatures expected_new = expected_signatures(pages,
							     replacement_value);

	struct measurement first_read = measure_mapping_read(&perf_group,
							     mapping,
							     pages,
							     page_size);

	print_measurement("2. first read of old mapping", &first_read, pages);

	print_signature_check("2. old mapping contents",
			      first_read.signatures, expected_old);

	if (unlink(path) != 0) {
		perror("unlink old path");
		return EXIT_FAILURE;
	}

	printf("\n========== 3. after unlink old pathname ==========\n");
	print_path_lookup(path);

	print_file_identity("3. old fd after unlink", old_fd);

	read_mapping_stats((const void *)mapping, &mapping_stats);

	print_mapping_stats("3. old mapping after unlink",
			    &mapping_stats, vm_pte_baseline);

	int new_fd = open(path,
			  O_CREAT | O_EXCL | O_RDWR,
			  0600);

	if (new_fd < 0) {
		perror("create replacement file");
		return EXIT_FAILURE;
	}

	if (ftruncate(new_fd, (off_t) length) != 0) {
		perror("ftruncate replacement");
		return EXIT_FAILURE;
	}

	initialize_file(new_fd, pages, page_size, replacement_value);

	ino_t new_inode = read_inode_number(new_fd);

	print_file_identity("4. replacement file at same pathname", new_fd);

	printf("old inode            : %" PRIuMAX "\n", (uintmax_t) old_inode);
	printf("new inode            : %" PRIuMAX "\n", (uintmax_t) new_inode);
	printf("different inode      : %s\n",
	       old_inode != new_inode ? "yes" : "NO");

	struct signatures old_fd_contents = read_fd_signatures(old_fd,
							       pages,
							       page_size);

	struct signatures new_fd_contents = read_fd_signatures(new_fd,
							       pages,
							       page_size);

	struct measurement old_mapping_again = measure_mapping_read(&perf_group,
								    mapping,
								    pages,
								    page_size);

	print_signature_check("4. unlinked old fd still sees old file",
			      old_fd_contents, expected_old);

	print_signature_check("4. old mapping still sees old file",
			      old_mapping_again.signatures, expected_old);

	print_signature_check("4. same pathname now contains new file",
			      new_fd_contents, expected_new);

	struct measurement discard_one = measure_dontneed(&perf_group,
							  (void *)mapping,
							  length);

	print_measurement("5. MADV_DONTNEED old mapping", &discard_one, pages);

	if (discard_one.result != 0)
		return EXIT_FAILURE;

	read_mapping_stats((const void *)mapping, &mapping_stats);

	print_mapping_stats("5. old mapping after MADV_DONTNEED",
			    &mapping_stats, vm_pte_baseline);

	printf("mincore before drop  : %zu / %zu pages\n",
	       count_mincore_resident((void *)mapping,
				      length, page_size), pages);

	if (use_drop_caches) {
		errno = 0;

		int result = drop_global_caches();
		int saved_errno = errno;

		printf("\n========== optional global drop_caches ==========\n");
		printf("return value          : %d\n", result);

		if (result != 0) {
			printf("errno                 : %d (%s)\n",
			       saved_errno, strerror(saved_errno));
		}

		printf("mincore after drop   : %zu / %zu pages\n",
		       count_mincore_resident((void *)mapping,
					      length, page_size), pages);
	}

	struct measurement read_after_discard =
	    measure_mapping_read(&perf_group,
				 mapping,
				 pages,
				 page_size);

	print_measurement("6. first read after discard/drop",
			  &read_after_discard, pages);

	print_signature_check("6. old mapping still resolves old inode",
			      read_after_discard.signatures, expected_old);

	if (close(old_fd) != 0) {
		perror("close old fd");
		return EXIT_FAILURE;
	}

	old_fd = -1;

	printf("\n========== 7. old fd closed ==========\n");
	printf("old fd               : closed\n");

	struct measurement discard_two = measure_dontneed(&perf_group,
							  (void *)mapping,
							  length);

	print_measurement("7. MADV_DONTNEED after closing old fd",
			  &discard_two, pages);

	struct measurement read_after_close = measure_mapping_read(&perf_group,
								   mapping,
								   pages,
								   page_size);

	print_measurement("7. mapping read after closing old fd",
			  &read_after_close, pages);

	print_signature_check("7. VMA keeps old file alive",
			      read_after_close.signatures, expected_old);

	read_mapping_stats((const void *)mapping, &mapping_stats);

	print_mapping_stats("7. old mapping remains valid",
			    &mapping_stats, vm_pte_baseline);

	if (munmap((void *)mapping, length) != 0) {
		perror("munmap old mapping");
		return EXIT_FAILURE;
	}

	printf("\n========== 8. old mapping removed ==========\n");
	printf("old fd               : closed\n");
	printf("old VMA              : unmapped\n");
	printf("old inode link count : 0\n");
	printf("old file references  : released by this process\n");

	int path_fd = open(path,
			   O_RDONLY | O_CLOEXEC);

	if (path_fd < 0) {
		perror("open replacement through pathname");
		return EXIT_FAILURE;
	}

	struct signatures path_contents = read_fd_signatures(path_fd,
							     pages,
							     page_size);

	print_signature_check("8. pathname still refers to replacement file",
			      path_contents, expected_new);

	close(path_fd);
	close(new_fd);

	if (unlink(path) != 0)
		perror("unlink replacement file");

	perf_group_close(&perf_group);

	printf("\nread_sink            : %" PRIu64 "\n", read_sink);

	return EXIT_SUCCESS;
}
