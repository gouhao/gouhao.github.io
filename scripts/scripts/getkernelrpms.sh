#!/bin/bash
maj_ver=$1
min_ver=$2
if [ -z "$maj_ver" ] || [ -z "$min_ver" ];then
	echo "Need version"
	exit 1
fi
wget http://10.30.38.131/kojifiles/packages/kernel/$maj_ver/$min_ver.uelc20/x86_64/kernel-$maj_ver-$min_ver.uelc20.x86_64.rpm
wget http://10.30.38.131/kojifiles/packages/kernel/$maj_ver/$min_ver.uelc20/x86_64/kernel-core-$maj_ver-$min_ver.uelc20.x86_64.rpm
wget http://10.30.38.131/kojifiles/packages/kernel/$maj_ver/$min_ver.uelc20/x86_64/kernel-modules-$maj_ver-$min_ver.uelc20.x86_64.rpm
wget http://10.30.38.131/kojifiles/packages/kernel/$maj_ver/$min_ver.uelc20/aarch64/kernel-$maj_ver-$min_ver.uelc20.aarch64.rpm
wget http://10.30.38.131/kojifiles/packages/kernel/$maj_ver/$min_ver.uelc20/aarch64/kernel-core-$maj_ver-$min_ver.uelc20.aarch64.rpm
wget http://10.30.38.131/kojifiles/packages/kernel/$maj_ver/$min_ver.uelc20/aarch64/kernel-modules-$maj_ver-$min_ver.uelc20.aarch64.rpm
