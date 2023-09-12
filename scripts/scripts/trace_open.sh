#!/bin/bash
trace_dir=/sys/kernel/debug/tracing/
echo 'p:fp do_filp_open+155 fp=+64(%ax):u32' >> $trace_dir/kprobe_events
echo 1 > $trace_dir/events/kprobes/fp/enable
echo 1 > $trace_dir/tracing_on
cat 0224-ext4-fix-reserved-space-counter-leakage.patch
echo 0 > $trace_dir/events/kprobes/fp/enable
echo 0 > $trace_dir/tracing_on
echo > $trace_dir/kprobe_events
