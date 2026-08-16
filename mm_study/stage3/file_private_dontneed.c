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
#include <sys/types.h>
#include <unistd.h>

#include "perf_counter.h"

#define TWO_MIB (2UL * 1024UL * 1024UL)

static volatile uint64_t read_sink;

struct usage_snapshot {
	long minor_faults;
	long major_faults;
};

struct signatures {
	uint64_t offset0_sum;
	uint64_t offset1_sum;
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

struct measurement {
	uint64_t cycles;
	uint64_t instructions;

	long minor_faults;
	long major_faults;

	struct signatures signatures;

	int result;
	int error_number;
};

typedef unsigned char (*value_function)(size_t page);

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

static unsigned char original_value(size_t page)
{
	return (unsigned char)((page % 251U) + 1U);
}

static unsigned char private_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0x5aU);
}

static unsigned char updated_file_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0xa5U);
}

static struct signatures expected_uniform_signatures(size_t first_page,
						     size_t page_count,
						     value_function value_fn)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		unsigned char value = value_fn(page);

		result.offset0_sum += value;
		result.offset1_sum += value;
	}

	return result;
}

static struct signatures expected_mixed_signatures(size_t first_page,
						   size_t page_count,
						   value_function offset0_fn,
						   value_function offset1_fn)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		result.offset0_sum += offset0_fn(page);
		result.offset1_sum += offset1_fn(page);
	}

	return result;
}

static int signatures_equal(struct signatures left, struct signatures right)
{
	return left.offset0_sum == right.offset0_sum &&
	    left.offset1_sum == right.offset1_sum;
}

static void print_signatures(const char *name,
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

static void write_file_range(int fd,
			     size_t first_page,
			     size_t page_count,
			     size_t page_size, value_function value_fn)
{
	unsigned char *buffer = malloc(page_size);

	if (buffer == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		memset(buffer, value_fn(page), page_size);

		pwrite_full(fd, buffer, page_size, (off_t) (page * page_size));
	}

	free(buffer);
}

static struct signatures read_file_signatures(int fd,
					      size_t first_page,
					      size_t page_count,
					      size_t page_size)
{
	struct signatures result = { 0, 0 };

	for (size_t page = first_page; page < first_page + page_count; ++page) {
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

static void *map_file_aligned(int fd, size_t length, size_t alignment)
{
	size_t reserve_length;

	if (length > SIZE_MAX - alignment) {
		errno = EOVERFLOW;
		return MAP_FAILED;
	}

	reserve_length = length + alignment;

	void *reservation = mmap(NULL,
				 reserve_length,
				 PROT_NONE,
				 MAP_PRIVATE | MAP_ANONYMOUS,
				 -1,
				 0);

	if (reservation == MAP_FAILED)
		return MAP_FAILED;

	uintptr_t raw = (uintptr_t) reservation;

	uintptr_t aligned =
	    (raw + alignment - 1) & ~((uintptr_t) alignment - 1);

	if (munmap(reservation, reserve_length) != 0)
		return MAP_FAILED;

	void *mapping = mmap((void *)aligned,
			     length,
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_FIXED_NOREPLACE,
			     fd,
			     0);

	if (mapping == MAP_FAILED)
		return MAP_FAILED;

	if ((uintptr_t) mapping != aligned) {
		(void)munmap(mapping, length);
		errno = EFAULT;
		return MAP_FAILED;
	}

	return mapping;
}

static struct measurement measure_read_range(struct perf_group *perf_group,
					     volatile unsigned char *memory,
					     size_t first_page,
					     size_t page_count,
					     size_t page_size)
{
	struct measurement result;
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = first_page; page < first_page + page_count; ++page) {
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

static struct measurement measure_private_write(struct perf_group *perf_group,
						volatile unsigned char *memory,
						size_t first_page,
						size_t page_count,
						size_t page_size)
{
	struct measurement result;
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = first_page; page < first_page + page_count; ++page) {
		memory[page * page_size] = private_value(page);
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;

	result.minor_faults = after.minor_faults - before.minor_faults;

	result.major_faults = after.major_faults - before.major_faults;

	return result;
}

static struct measurement measure_dontneed(struct perf_group *perf_group,
					   void *address, size_t length)
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

	result.result = madvise(address, length, MADV_DONTNEED);

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
			      size_t operations)
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

	if (operations != 0) {
		printf("cycles/page          : %.2f\n",
		       (double)measurement->cycles / (double)operations);

		printf("instructions/page    : %.2f\n",
		       (double)measurement->instructions / (double)operations);
	}

	printf("offset 0 sum         : %" PRIu64 "\n",
	       measurement->signatures.offset0_sum);
	printf("offset 1 sum         : %" PRIu64 "\n",
	       measurement->signatures.offset1_sum);
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t cow_pages = 512;

	if (argc >= 2)
		size_mib = (size_t)strtoul(argv[1], NULL, 0);

	if (argc >= 3)
		cow_pages = (size_t)strtoul(argv[2], NULL, 0);

	if (argc > 3 || size_mib == 0) {
		fprintf(stderr, "Usage: %s [MiB] [cow_pages]\n", argv[0]);

		return EXIT_FAILURE;
	}

	long page_size_long = sysconf(_SC_PAGESIZE);

	if (page_size_long <= 0) {
		perror("sysconf");
		return EXIT_FAILURE;
	}

	size_t page_size = (size_t)page_size_long;
	size_t length = size_mib * 1024UL * 1024UL;

	length -= length % page_size;

	size_t pages = length / page_size;

	if (cow_pages == 0 || cow_pages > pages) {
		fprintf(stderr,
			"Invalid cow_pages=%zu, total pages=%zu\n",
			cow_pages, pages);

		return EXIT_FAILURE;
	}

	size_t cow_length = cow_pages * page_size;

	char file_path[128];

	snprintf(file_path,
		 sizeof(file_path),
		 "/file_private_dontneed_%ld.bin", (long)getpid());

	int fd = open(file_path,
		      O_CREAT | O_TRUNC | O_RDWR,
		      0600);

	if (fd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

    /**
     * to change the length of file to length parameter
     *
     */
	if (ftruncate(fd, (off_t) length) != 0) { 
		perror("ftruncate");
		close(fd);
		unlink(file_path);
		return EXIT_FAILURE;
	}

    /**
     * write to file contents of original_value
     */
	write_file_range(fd, 0, pages, page_size, original_value);

	struct perf_group perf_group;
	struct perf_counts warmup_counts;

	if (perf_group_open(&perf_group) != 0) {
		close(fd);
		unlink(file_path);
		return EXIT_FAILURE;
	}

	if (perf_group_start(&perf_group) != 0)
		return EXIT_FAILURE;

	asm volatile ("":::"memory");

	if (perf_group_stop(&perf_group, &warmup_counts) != 0)
		return EXIT_FAILURE;

	warm_up_proc_files();

	unsigned long vm_pte_baseline = read_vm_pte();

	volatile unsigned char *memory = map_file_aligned(fd,
							  length,
							  TWO_MIB);

	if (memory == MAP_FAILED) {
		perror("map_file_aligned");
		perf_group_close(&perf_group);
		close(fd);
		unlink(file_path);
		return EXIT_FAILURE;
	}

	printf("PID                  : %ld\n", (long)getpid());
	printf("file                 : %s\n", file_path);
	printf("mapping address      : %p\n", (const void *)memory);
	printf("address mod 2 MiB    : 0x%lx\n", (unsigned long)
	       ((uintptr_t) memory & (TWO_MIB - 1)));
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("pages                : %zu\n", pages);
	printf("COW pages            : %zu\n", cow_pages);
	printf("COW size             : %zu kB\n", cow_length / 1024);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	struct mapping_stats stats;

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("1. immediately after mmap",
			    &stats, vm_pte_baseline);

	printf("mincore resident     : %zu / %zu pages\n",
	       count_mincore_resident((void *)memory,
				      length, page_size), pages);

	/*
	 * 第一次读取全部映射，建立文件页PTE。
	 */
	struct measurement first_read = measure_read_range(&perf_group,
							   memory,
							   0,
							   pages,
							   page_size);

	print_measurement("2. first read of all file pages",
			  &first_read, pages);

	struct signatures expected_initial = expected_uniform_signatures(0,
									 pages,
									 original_value);

	print_signatures("2. initial mapping verification",
			 first_read.signatures, expected_initial);

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("2. state after first read",
			    &stats, vm_pte_baseline);

	/*
	 * 第一次COW：只修改前512页的第0字节。
	 */
	struct measurement first_cow = measure_private_write(&perf_group,
							     memory,
							     0,
							     cow_pages,
							     page_size);

	print_measurement("3. first private COW writes", &first_cow, cow_pages);

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("3. state after first private COW",
			    &stats, vm_pte_baseline);

	/*
	 * 修改底层文件的同一范围。
	 * COW匿名页不应跟随这些变化。
	 */
	write_file_range(fd, 0, cow_pages, page_size, updated_file_value);

	printf("\n========== 4. backing file rewritten ==========\n");
	printf("rewritten pages      : %zu\n", cow_pages);
	printf("rewritten size       : %zu kB\n", cow_length / 1024);

	struct measurement mapping_before_discard =
	    measure_read_range(&perf_group,
			       memory,
			       0,
			       cow_pages,
			       page_size);

	struct signatures expected_old_cow = expected_mixed_signatures(0,
								       cow_pages,
								       private_value,
								       original_value);

	print_signatures("4. private mapping before discard",
			 mapping_before_discard.signatures, expected_old_cow);

	struct signatures file_after_rewrite = read_file_signatures(fd,
								    0,
								    cow_pages,
								    page_size);

	struct signatures expected_updated_file = expected_uniform_signatures(0,
									      cow_pages,
									      updated_file_value);

	print_signatures("4. backing file after rewrite",
			 file_after_rewrite, expected_updated_file);

	/*
	 * 丢弃前512页的私有COW页面。
	 */
	struct measurement dontneed = measure_dontneed(&perf_group,
						       (void *)memory,
						       cow_length);

	print_measurement("5. MADV_DONTNEED on COW range",
			  &dontneed, cow_pages);

	if (dontneed.result != 0)
		return EXIT_FAILURE;

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("5. state immediately after MADV_DONTNEED",
			    &stats, vm_pte_baseline);

	printf("mincore resident     : %zu / %zu pages\n",
	       count_mincore_resident((void *)memory,
				      length, page_size), pages);

	/*
	 * 再次读取被丢弃范围。
	 * 应重新映射当前文件内容。
	 */
	struct measurement read_after_discard = measure_read_range(&perf_group,
								   memory,
								   0,
								   cow_pages,
								   page_size);

	print_measurement("6. first read after MADV_DONTNEED",
			  &read_after_discard, cow_pages);

	print_signatures("6. mapping reloaded from current file",
			 read_after_discard.signatures, expected_updated_file);

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("6. state after file pages are mapped again",
			    &stats, vm_pte_baseline);

	/*
	 * 第二次COW。
	 * 这次新匿名页应复制更新后的文件内容。
	 */
	struct measurement second_cow = measure_private_write(&perf_group,
							      memory,
							      0,
							      cow_pages,
							      page_size);

	print_measurement("7. second private COW writes",
			  &second_cow, cow_pages);

	read_mapping_stats((const void *)memory, &stats);

	print_mapping_stats("7. state after second private COW",
			    &stats, vm_pte_baseline);

	struct measurement mapping_after_second_cow =
	    measure_read_range(&perf_group,
			       memory,
			       0,
			       cow_pages,
			       page_size);

	struct signatures expected_new_cow = expected_mixed_signatures(0,
								       cow_pages,
								       private_value,
								       updated_file_value);

	print_signatures("7. second COW copied current file contents",
			 mapping_after_second_cow.signatures, expected_new_cow);

	struct signatures final_file = read_file_signatures(fd,
							    0,
							    cow_pages,
							    page_size);

	print_signatures("7. backing file remains unchanged by COW",
			 final_file, expected_updated_file);

	printf("\nread_sink            : %" PRIu64 "\n", read_sink);

	if (munmap((void *)memory, length) != 0)
		perror("munmap");

	perf_group_close(&perf_group);
	close(fd);

	if (unlink(file_path) != 0)
		perror("unlink");

	return EXIT_SUCCESS;
}
