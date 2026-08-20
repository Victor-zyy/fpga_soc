#define _GNU_SOURCE

#include <asm/unistd.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "perf_counter.h"

#define ALIGN_2M	(2UL * 1024 * 1024)
#define SPREAD_SIZE	(1UL * 1024 * 1024)
#define PACKED_SIZE	4096UL

#define PAGE_SIZE	4096UL
#define CACHE_LINE	64UL
#define STUB_SIZE	16UL

#define MAX_STUBS	256
#define HOPS		65536
#define REPEATS		5
#define WARM_ROUNDS	64

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

#define RISCV_ZERO	0
#define RISCV_RA	1
#define RISCV_A0	10

typedef uint64_t(*chain_fn_t) (uint64_t hops);

static volatile uint64_t global_sink;

struct sample {
	uint64_t cycles;
	uint64_t instructions;
};

struct result {
	double median_cycles;
	double best_cycles;
	double median_instructions;
};

static void die(const char *what)
{
	perror(what);
	exit(EXIT_FAILURE);
}

static unsigned char *map_spread_region(void)
{
	const size_t reserve_size = 2 * ALIGN_2M;
	unsigned char *reservation;
	uintptr_t raw, aligned;
	size_t prefix, suffix;

	reservation = mmap(NULL, reserve_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (reservation == MAP_FAILED)
		die("mmap spread");

	raw = (uintptr_t) reservation;
	aligned = (raw + ALIGN_2M - 1) & ~(uintptr_t) (ALIGN_2M - 1);

	prefix = aligned - raw;
	suffix = raw + reserve_size - (aligned + SPREAD_SIZE);

	if (prefix && munmap(reservation, prefix))
		die("munmap spread prefix");

	if (suffix && munmap((void *)(aligned + SPREAD_SIZE), suffix))
		die("munmap spread suffix");

	return (unsigned char *)aligned;
}

static unsigned char *map_packed_region(void)
{
	unsigned char *base;

	base = mmap(NULL, PACKED_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		die("mmap packed");

	return base;
}

/*
 * RV64 instruction encoders.
 *
 * Only the small subset required by the generated code is implemented.
 */

static uint32_t encode_addi(unsigned int rd, unsigned int rs1, int imm)
{
	uint32_t uimm = (uint32_t) imm & 0xfff;

	return (uimm << 20) | (rs1 << 15) | (rd << 7) | 0x13;
}

static uint32_t encode_beq(unsigned int rs1, unsigned int rs2, int offset)
{
	uint32_t imm = (uint32_t) offset;

	if ((offset & 1) || offset < -4096 || offset > 4094) {
		fprintf(stderr, "invalid BEQ offset: %d\n", offset);
		exit(EXIT_FAILURE);
	}

	return (((imm >> 12) & 0x1) << 31) |
	    (((imm >> 5) & 0x3f) << 25) |
	    (rs2 << 20) |
	    (rs1 << 15) |
	    (((imm >> 1) & 0xf) << 8) | (((imm >> 11) & 0x1) << 7) | 0x63;
}

static uint32_t encode_jal(unsigned int rd, intptr_t offset)
{
	uint32_t imm = (uint32_t) offset;

	if ((offset & 1) || offset < -(1L << 20) || offset >= (1L << 20)) {
		fprintf(stderr, "invalid JAL offset: %ld\n", (long)offset);
		exit(EXIT_FAILURE);
	}

	return (((imm >> 20) & 0x1) << 31) |
	    (((imm >> 1) & 0x3ff) << 21) |
	    (((imm >> 11) & 0x1) << 20) |
	    (((imm >> 12) & 0xff) << 12) | (rd << 7) | 0x6f;
}

static uint32_t encode_ret(void)
{
	/* jalr x0, 0(ra) */
	return 0x00008067;
}

static unsigned char *spread_stub(unsigned char *base, size_t index)
{
	size_t offset = (index & 63UL) * CACHE_LINE;

	return base + index * PAGE_SIZE + offset;
}

static unsigned char *packed_stub(unsigned char *base, size_t index)
{
	return base + index * STUB_SIZE;
}

static void write_stub(unsigned char *stub, unsigned char *next)
{
	uint32_t *insn = (uint32_t *) stub;
	intptr_t jal_offset;

	/*
	 * stub:
	 *
	 *   addi a0, a0, -1
	 *   beq  a0, zero, +8
	 *   jal  zero, next
	 *   jalr zero, 0(ra)
	 *
	 * The BEQ at offset +4 jumps to the RET at offset +12.
	 */
	insn[0] = encode_addi(RISCV_A0, RISCV_A0, -1);
	insn[1] = encode_beq(RISCV_A0, RISCV_ZERO, 8);

	jal_offset = (intptr_t) next - (intptr_t) (stub + 8);
	insn[2] = encode_jal(RISCV_ZERO, jal_offset);

	insn[3] = encode_ret();
}

static void flush_icache(void *start, void *end)
{
#ifdef __NR_riscv_flush_icache
	if (syscall(__NR_riscv_flush_icache, start, end, 0))
		die("riscv_flush_icache");
#else
	__builtin___clear_cache(start, end);
#endif
}

static void configure_spread_ring(unsigned char *base, size_t nstubs)
{
	size_t i;

	if (mprotect(base, SPREAD_SIZE, PROT_READ | PROT_WRITE))
		die("mprotect spread RW");

	for (i = 0; i < nstubs; i++) {
		unsigned char *stub = spread_stub(base, i);
		unsigned char *next;

		if (i + 1 == nstubs)
			next = spread_stub(base, 0);
		else
			next = spread_stub(base, i + 1);

		write_stub(stub, next);
	}

	if (mprotect(base, SPREAD_SIZE, PROT_READ | PROT_EXEC))
		die("mprotect spread RX");

	flush_icache(base, base + SPREAD_SIZE);
}

static void configure_packed_ring(unsigned char *base, size_t nstubs)
{
	size_t i;

	if (mprotect(base, PACKED_SIZE, PROT_READ | PROT_WRITE))
		die("mprotect packed RW");

	for (i = 0; i < nstubs; i++) {
		unsigned char *stub = packed_stub(base, i);
		unsigned char *next;

		if (i + 1 == nstubs)
			next = packed_stub(base, 0);
		else
			next = packed_stub(base, i + 1);

		write_stub(stub, next);
	}

	if (mprotect(base, PACKED_SIZE, PROT_READ | PROT_EXEC))
		die("mprotect packed RX");

	flush_icache(base, base + PACKED_SIZE);
}

static void warm_chain(chain_fn_t fn, size_t nstubs)
{
	uint64_t hops = nstubs * WARM_ROUNDS;

	global_sink ^= fn(hops);
}

static struct sample measure(struct perf_group *perf, chain_fn_t fn)
{
	struct perf_counts counts;
	struct sample sample;

	if (perf_group_start(perf))
		die("perf_group_start");

	asm volatile ("":::"memory");

	global_sink ^= fn(HOPS);

	asm volatile ("":::"memory");

	if (perf_group_stop(perf, &counts))
		die("perf_group_stop");

	sample.cycles = counts.cycles;
	sample.instructions = counts.instructions;

	return sample;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t aa = *(const uint64_t *)a;
	uint64_t bb = *(const uint64_t *)b;

	if (aa < bb)
		return -1;
	if (aa > bb)
		return 1;

	return 0;
}

static struct result run_test(struct perf_group *perf, chain_fn_t fn,
			      size_t nstubs)
{
	uint64_t cycles[REPEATS];
	uint64_t instructions[REPEATS];
	uint64_t cycles_sorted[REPEATS];
	uint64_t instructions_sorted[REPEATS];
	struct result result;
	unsigned int i;

	for (i = 0; i < REPEATS; i++) {
		struct sample sample;

		warm_chain(fn, nstubs);
		sample = measure(perf, fn);

		cycles[i] = sample.cycles;
		instructions[i] = sample.instructions;
	}

	for (i = 0; i < REPEATS; i++) {
		cycles_sorted[i] = cycles[i];
		instructions_sorted[i] = instructions[i];
	}

	qsort(cycles_sorted, REPEATS, sizeof(cycles_sorted[0]), cmp_u64);
	qsort(instructions_sorted, REPEATS,
	      sizeof(instructions_sorted[0]), cmp_u64);

	result.median_cycles = (double)cycles_sorted[REPEATS / 2] / HOPS;
	result.best_cycles = (double)cycles_sorted[0] / HOPS;
	result.median_instructions =
	    (double)instructions_sorted[REPEATS / 2] / HOPS;

	return result;
}

static void get_faults(long *minor, long *major)
{
	struct rusage usage;

	if (getrusage(RUSAGE_SELF, &usage))
		die("getrusage");

	*minor = usage.ru_minflt;
	*major = usage.ru_majflt;
}

int main(void)
{
	static const size_t stub_counts[] = {
		4, 8, 16, 24,
		28, 30, 31, 32,
		33, 34, 36, 40,
		48, 64, 96, 128,
		192, 256,
	};

	struct perf_group perf;
	unsigned char *spread;
	unsigned char *packed;
	size_t test;

	setvbuf(stdout, NULL, _IONBF, 0);

	if (sysconf(_SC_PAGESIZE) != PAGE_SIZE) {
		fprintf(stderr, "expected %lu-byte pages\n", PAGE_SIZE);
		return EXIT_FAILURE;
	}

	if (perf_group_open(&perf)) {
		fprintf(stderr, "failed to open perf events\n");
		return EXIT_FAILURE;
	}

	spread = map_spread_region();
	packed = map_packed_region();

	printf("PID                  : %ld\n", (long)getpid());
	printf("spread mapping       : %p\n", spread);
	printf("packed mapping       : %p\n", packed);
	printf("spread 2MiB aligned  : %s\n",
	       ((uintptr_t) spread & (ALIGN_2M - 1)) ? "NO" : "yes");
	printf("stub size            : %lu B\n", STUB_SIZE);
	printf("max stubs            : %d\n", MAX_STUBS);
	printf("timed hops           : %d\n", HOPS);
	printf("repeats/test         : %d\n", REPEATS);
	printf("spread max I$ lines  : %d\n", MAX_STUBS);
	printf("spread I$ footprint  : %d KiB\n", MAX_STUBS * 64 / 1024);
	printf("spread max lines/set : %d\n", MAX_STUBS / 64);
	printf("packed footprint     : %lu KiB\n", PACKED_SIZE / 1024);
	printf("counter mode         : independent perf events\n");

	printf("\n"
	       " Nstubs | packed cyc/hop | spread cyc/hop |"
	       " spread best | packed insn/hop | spread insn/hop |"
	       " minflt | majflt\n"
	       "--------+----------------+----------------+"
	       "-------------+-----------------+-----------------+"
	       "--------+-------\n");

	for (test = 0; test < ARRAY_SIZE(stub_counts); test++) {
		struct result packed_result;
		struct result spread_result;
		chain_fn_t packed_fn;
		chain_fn_t spread_fn;
		long min_before, maj_before;
		long min_after, maj_after;
		size_t nstubs = stub_counts[test];

		configure_packed_ring(packed, nstubs);
		configure_spread_ring(spread, nstubs);

		packed_fn = (chain_fn_t) packed_stub(packed, 0);
		spread_fn = (chain_fn_t) spread_stub(spread, 0);

		/*
		 * Warm both rings before the fault-counting window.
		 */
		warm_chain(packed_fn, nstubs);
		warm_chain(spread_fn, nstubs);

		get_faults(&min_before, &maj_before);

		packed_result = run_test(&perf, packed_fn, nstubs);
		spread_result = run_test(&perf, spread_fn, nstubs);

		get_faults(&min_after, &maj_after);

		printf("%7zu | %14.2f | %14.2f | %11.2f |"
		       " %15.2f | %15.2f | %6ld | %6ld\n",
		       nstubs,
		       packed_result.median_cycles,
		       spread_result.median_cycles,
		       spread_result.best_cycles,
		       packed_result.median_instructions,
		       spread_result.median_instructions,
		       min_after - min_before, maj_after - maj_before);
	}

	printf("\nglobal sink          : 0x%016" PRIx64 "\n", global_sink);

	if (munmap(spread, SPREAD_SIZE))
		die("munmap spread");

	if (munmap(packed, PACKED_SIZE))
		die("munmap packed");

	perf_group_close(&perf);

	return EXIT_SUCCESS;
}
