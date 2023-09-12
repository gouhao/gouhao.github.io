#!/bin/bash

symbol_array="hyperv_fill_flush_guest_mapping_list hyperv_flush_guest_mapping_range perf_event_create_kernel_counter perf_event_pause"

for s in $symbol_array
do
	cat $1 | grep $s
	
done
