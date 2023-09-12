#!/bin/bash
for i in `eval echo {$3..$4}`
do
	$1 $2/$i-* $5
done
