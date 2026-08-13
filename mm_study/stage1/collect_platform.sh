#!/bin/sh

OUT=platform.txt #output file name

{
    # 2>/dev/null means the stderr to out to the null device
    # command > file 2>&1 means stderr to out to the file for the direction of >
    echo "============== DATE =============="
    date 2>/dev/null || true

    echo 
    echo "============== KERNEL =============="
    uname -a

    echo
    echo "============== CPU INFO =============="
    cat /proc/cpuinfo 2>/dev/null || true

    echo 
    echo "============== PAGE SIZE =============="
    if command -v getconf >/dev/null 2>&1; then
        getconf PAGE_SIZE
    else
        echo "getconf is not installed"
    fi
    
    echo
    echo "============== MEMORY =============="
    cat /proc/meminfo 2>/dev/null || true

    echo
    echo "============== CURRENT PROCESS MAP  =============="
    cat /proc/self/maps 2>/dev/null || true

    echo
    echo "============== CURRENT PROCESS STATUS  =============="
    cat /proc/self/status 2>/dev/null || true

    echo
    echo "============== PERF =============="
    if command -v perf >/dev/null 2>&1; then
        perf --version
        perf list
    else
        echo "perf is not installed!"
    fi
    
    echo
    echo "============== EVENT SOURCES =============="
    ls -la /sys/bus/event_source/devices 2>/dev/null || true

    echo
    echo "============== TRACEFS =============="
    mount | grep -E 'tracefs|debugfs' || true
    ls -la /sys/kernel/tracing 2>/dev/null || true

    echo 
    echo "============== SBI / PMU LOG =============="
    dmesg 2>/dev/null | grep -Ei 'riscv|sbi|pmu|perf|cache|tlb' || true

    echo
    echo "============== KERNEL CONFIG =============="
    if [ -r /proc/config.gz ]; then
        zcat /proc/config.gz | grep -E 'CONFIG_(MMU|PERF_EVENTS|RISCV_PMU|RISCV_PMU_SBI|FTRACE|FUNCTION_TRACER|KPROBES|DEBUG_FS|TRANSPARENT_HUGEPAGE)'
    else
        echo "/proc/config.gz is unavailable"
    fi
} > "$OUT" 2>&1

echo "Saved to $OUT"
