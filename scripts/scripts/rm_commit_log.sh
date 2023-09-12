#!/bin/bash
files=`ls $1`
for f in $files
do
    sed -i "1,/diff --git/d" $1/$f
done