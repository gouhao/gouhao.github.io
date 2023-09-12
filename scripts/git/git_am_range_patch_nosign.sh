#!/bin/bash
for p in `eval echo {$2..$3}`
do
	git am  $1/$p-*
	if [ $? -ne 0 ];then
		echo "am: patch $p error"
		exit 1
	fi
done
