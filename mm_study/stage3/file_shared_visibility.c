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
#include <unistd.h>

#include "perf_counter.h"

static volatile uint64_t read_sink;

struct usage_snapshot {
	long minor_faults;
	long major_faults;
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
	uint64_t value;
	int result;
	int error_number;
};

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

static int starts_with(const char *line, const char *prefix)
{
	return strncmp(line, prefix, strlen(prefix)) == 0;
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

static unsigned char shared_value(size_t page)
{
	return (unsigned char)(original_value(page) ^ 0xa5U);
}

static uint64_t expected_original_sum(size_t pages)
{
	uint64_t sum = 0;

	for (size_t page = 0; page < pages; ++page)
		sum += original_value(page);

	return sum;
}

static uint64_t expected_shared_sum(size_t pages, size_t changed_pages)
{
	uint64_t sum = 0;

	for (size_t page = 0; page < pages; ++page) {
		if (page < changed_pages)
			sum += shared_value(page);
		else
			sum += original_value(page);
	}

	return sum;
}

static void initialize_file(int fd, size_t pages, size_t page_size)
{
	unsigned char *buffer = malloc(page_size);

	if (buffer == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for (size_t page = 0; page < pages; ++page) {
		memset(buffer, original_value(page), page_size);

		off_t offset = (off_t) (page * page_size);

		ssize_t result = pwrite(fd,
					buffer,
					page_size,
					offset);

		if (result != (ssize_t) page_size) {
			if (result < 0)
				perror("pwrite");
			else
				fprintf(stderr, "short pwrite: %zd\n", result);

			free(buffer);
			exit(EXIT_FAILURE);
		}
	}

	free(buffer);

	if (fsync(fd) != 0)
		perror("fsync");
}

static struct measurement measure_read(struct perf_group *perf_group,
				       volatile unsigned char *memory,
				       size_t pages, size_t page_size)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct measurement result;
	uint64_t sum = 0;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = 0; page < pages; ++page)
		sum += memory[page * page_size];

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	read_sink += sum;

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;
	result.minor_faults = after.minor_faults - before.minor_faults;
	result.major_faults = after.major_faults - before.major_faults;
	result.value = sum;
	result.result = 0;

	return result;
}

static struct measurement measure_shared_write(struct perf_group *perf_group,
					       volatile unsigned char *memory,
					       size_t changed_pages,
					       size_t page_size)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct measurement result;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	for (size_t page = 0; page < changed_pages; ++page) {
		memory[page * page_size] = shared_value(page);
	}

	if (perf_group_stop(perf_group, &perf) != 0)
		exit(EXIT_FAILURE);

	after = get_usage_snapshot();

	result.cycles = perf.cycles;
	result.instructions = perf.instructions;
	result.minor_faults = after.minor_faults - before.minor_faults;
	result.major_faults = after.major_faults - before.major_faults;
	result.result = 0;

	return result;
}

static struct measurement measure_msync(struct perf_group *perf_group,
					void *memory, size_t length)
{
	struct usage_snapshot before;
	struct usage_snapshot after;
	struct perf_counts perf;
	struct measurement result;

	memset(&result, 0, sizeof(result));

	before = get_usage_snapshot();

	if (perf_group_start(perf_group) != 0)
		exit(EXIT_FAILURE);

	errno = 0;
	result.result = msync(memory, length, MS_SYNC);
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

static uint64_t read_file_sum(int fd, size_t pages, size_t page_size)
{
	uint64_t sum = 0;

	for (size_t page = 0; page < pages; ++page) {
		unsigned char value = 0;

		off_t offset = (off_t) (page * page_size);

		ssize_t result = pread(fd,
				       &value,
				       sizeof(value),
				       offset);

		if (result != (ssize_t) sizeof(value)) {
			if (result < 0)
				perror("pread");
			else
				fprintf(stderr, "short pread: %zd\n", result);

			exit(EXIT_FAILURE);
		}

		sum += value;
	}

	return sum;
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
		printf("cycles/op            : %.2f\n",
		       (double)measurement->cycles / (double)operations);
		printf("instructions/op      : %.2f\n",
		       (double)measurement->instructions / (double)operations);
	}

	printf("value/sum            : %" PRIu64 "\n", measurement->value);
}

int main(int argc, char **argv)
{
	size_t size_mib = 16;
	size_t changed_pages = 512;

	if (argc >= 2)
		size_mib = (size_t)strtoul(argv[1], NULL, 0);

	if (argc >= 3)
		changed_pages = (size_t)strtoul(argv[2], NULL, 0);

	if (argc > 3 || size_mib == 0) {
		fprintf(stderr, "Usage: %s [MiB] [changed_pages]\n", argv[0]);
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

	if (changed_pages > pages) {
		fprintf(stderr,
			"changed_pages=%zu exceeds pages=%zu\n",
			changed_pages, pages);
		return EXIT_FAILURE;
	}

	char file_path[128];

	snprintf(file_path,
		 sizeof(file_path),
		 "/file_shared_visibility_%ld.bin", (long)getpid());

	int fd = open(file_path,
		      O_CREAT | O_TRUNC | O_RDWR,
		      0600);

	if (fd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

	if (ftruncate(fd, (off_t) length) != 0) {
		perror("ftruncate");
		close(fd);
		unlink(file_path);
		return EXIT_FAILURE;
	}

	initialize_file(fd, pages, page_size);

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

	unsigned long vm_pte_baseline = read_vm_pte();

    /**
     * MAP_SHARED --- to map the same file
     */
	volatile unsigned char *shared_rw = mmap(NULL,
						 length,
						 PROT_READ | PROT_WRITE,
						 MAP_SHARED,
						 fd,
						 0);

	if (shared_rw == MAP_FAILED) {
		perror("mmap shared_rw");
		return EXIT_FAILURE;
	}

    /**
     * MAP_SHARED --- to map the same file
     */
	volatile unsigned char *shared_ro = mmap(NULL,
						 length,
						 PROT_READ,
						 MAP_SHARED,
						 fd,
						 0);

	if (shared_ro == MAP_FAILED) {
		perror("mmap shared_ro");
		munmap((void *)shared_rw, length);
		return EXIT_FAILURE;
	}

	uint64_t original_sum = expected_original_sum(pages);

	uint64_t shared_sum = expected_shared_sum(pages,
						  changed_pages);

	printf("PID                  : %ld\n", (long)getpid());
	printf("file                 : %s\n", file_path);
	printf("shared_rw address    : %p\n", (const void *)shared_rw);
	printf("shared_ro address    : %p\n", (const void *)shared_ro);
	printf("mapping size         : %zu MiB\n", length / 1024 / 1024);
	printf("page size            : %zu bytes\n", page_size);
	printf("pages                : %zu\n", pages);
	printf("changed pages        : %zu\n", changed_pages);
	printf("changed size         : %zu kB\n",
	       changed_pages * page_size / 1024);
	printf("expected original sum: %" PRIu64 "\n", original_sum);
	printf("expected shared sum  : %" PRIu64 "\n", shared_sum);
	printf("VmPTE baseline       : %lu kB\n", vm_pte_baseline);

	struct mapping_stats rw_stats;
	struct mapping_stats ro_stats;

	read_mapping_stats((const void *)shared_rw, &rw_stats);

	read_mapping_stats((const void *)shared_ro, &ro_stats);

	print_mapping_stats("shared_rw immediately after mmap",
			    &rw_stats, vm_pte_baseline);

	print_mapping_stats("shared_ro immediately after mmap",
			    &ro_stats, vm_pte_baseline);

	printf("shared_rw mincore    : %zu / %zu pages\n",
	       count_mincore_resident((void *)shared_rw,
				      length, page_size), pages);

	printf("shared_ro mincore    : %zu / %zu pages\n",
	       count_mincore_resident((void *)shared_ro,
				      length, page_size), pages);

	struct measurement first_rw_read = measure_read(&perf_group,
							shared_rw,
							pages,
							page_size);

	print_measurement("first read through shared_rw",
			  &first_rw_read, pages);

	struct measurement first_ro_read = measure_read(&perf_group,
							shared_ro,
							pages,
							page_size);

	print_measurement("first read through shared_ro",
			  &first_ro_read, pages);

	printf("shared_rw initial valid: %s\n",
	       first_rw_read.value == original_sum ? "yes" : "NO");

	printf("shared_ro initial valid: %s\n",
	       first_ro_read.value == original_sum ? "yes" : "NO");

	read_mapping_stats((const void *)shared_rw, &rw_stats);

	read_mapping_stats((const void *)shared_ro, &ro_stats);

	print_mapping_stats("shared_rw after both mappings are read",
			    &rw_stats, vm_pte_baseline);

	print_mapping_stats("shared_ro after both mappings are read",
			    &ro_stats, vm_pte_baseline);

	struct measurement shared_write = measure_shared_write(&perf_group,
							       shared_rw,
							       changed_pages,
							       page_size);

	print_measurement("first shared writes through shared_rw",
			  &shared_write, changed_pages);

	read_mapping_stats((const void *)shared_rw, &rw_stats);

	read_mapping_stats((const void *)shared_ro, &ro_stats);

	print_mapping_stats("shared_rw after shared writes",
			    &rw_stats, vm_pte_baseline);

	print_mapping_stats("shared_ro after shared writes",
			    &ro_stats, vm_pte_baseline);

	/*
	 * 关键验证：在msync之前观察另一个映射和pread。
	 */
	struct measurement ro_before_msync = measure_read(&perf_group,
							  shared_ro,
							  pages,
							  page_size);

	uint64_t file_before_msync = read_file_sum(fd,
						   pages,
						   page_size);

	printf("\n========== visibility before msync ==========\n");

	printf("shared_ro sum        : %" PRIu64 "\n", ro_before_msync.value);
	printf("expected shared sum  : %" PRIu64 "\n", shared_sum);
	printf("other mapping sees writes: %s\n",
	       ro_before_msync.value == shared_sum ? "yes" : "NO");

	printf("pread file sum       : %" PRIu64 "\n", file_before_msync);
	printf("pread sees writes    : %s\n",
	       file_before_msync == shared_sum ? "yes" : "NO");

	struct measurement sync_measurement = measure_msync(&perf_group,
							    (void *)shared_rw,
							    length);

	print_measurement("msync MS_SYNC", &sync_measurement, pages);

	struct measurement ro_after_msync = measure_read(&perf_group,
							 shared_ro,
							 pages,
							 page_size);

	uint64_t file_after_msync = read_file_sum(fd,
						  pages,
						  page_size);

	printf("\n========== visibility after msync ==========\n");

	printf("shared_ro sum        : %" PRIu64 "\n", ro_after_msync.value);
	printf("expected shared sum  : %" PRIu64 "\n", shared_sum);
	printf("other mapping valid  : %s\n",
	       ro_after_msync.value == shared_sum ? "yes" : "NO");

	printf("pread file sum       : %" PRIu64 "\n", file_after_msync);
	printf("file content valid   : %s\n",
	       file_after_msync == shared_sum ? "yes" : "NO");

	printf("Anonymous shared_rw  : %lu kB\n", rw_stats.anonymous_kb);
	printf("Anonymous shared_ro  : %lu kB\n", ro_stats.anonymous_kb);
	printf("read_sink            : %" PRIu64 "\n", read_sink);

	if (munmap((void *)shared_ro, length) != 0)
		perror("munmap shared_ro");

	if (munmap((void *)shared_rw, length) != 0)
		perror("munmap shared_rw");

	perf_group_close(&perf_group);
	close(fd);

	if (unlink(file_path) != 0)
		perror("unlink");

	return EXIT_SUCCESS;
}
