#!/bin/bash
patches=`ls $1`
for p in $patches
do
    sed -i -e '/Signed-off-by: Gou Hao/d' $1/$p
    sed -i -e '/^Change-Id:/d' $1/$p
#    sed -i -e '1d' $1/$p
done
