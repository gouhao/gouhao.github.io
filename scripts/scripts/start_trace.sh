#!/bin/bash
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo function > /sys/kernel/debug/tracing/current_tracer
echo nop > /sys/kernel/debug/tracing/current_tracer

echo 1 > /sys/kernel/debug/tracing/tracing_on
echo 1 > /sys/kernel/debug/tracing/events/block/enable
echo 1 > /sys/kernel/debug/tracing/events/xfs/enable
echo 1 > /sys/kernel/debug/tracing/events/scsi/enable
echo 1 > /sys/kernel/debug/tracing/events/writeback/enable
/opt/ltp/runltp -d /home  -f gouhao_dio
sleep 1
echo 0 > /sys/kernel/debug/tracing/events/block/enable
echo 0 > /sys/kernel/debug/tracing/events/xfs/enable
echo 0 > /sys/kernel/debug/tracing/events/scsi/enable
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo 0 > /sys/kernel/debug/tracing/events/writeback/enable
