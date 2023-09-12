#!/bin/python
# -*- coding:utf-8 -*-

"""
获取补丁commit-id
"""

import sys, os
from common import *

features = [
    ("phram",1397, 1398),
    ("kasan",1648, 1658),
    ("ima-kexec",3512, 3524),
    ("smmu-v3",4544, 4562),
    ("thp",6722, 6745),
    ("vmalloc", 6766, 6786),
    ("sppedup-mremap", 6845, 6861),
    ("bulk-alloctor", 6865, 6882),
    ("hisi-crypto", 7134, 7280),
    ("prempt-dync", 7446, 7453),
    ("hisi-i2c", 7505, 7507),
    ("hisi-spi", 7553, 7554),
    ("hisi-crypto2", 7588, 7601),
    ("KFence", 10141, 10186),
    ("mm-Damon", 10660, 10672)
]

def get_patch_commit_id(path):
    fp = open(path, "r")
    line = fp.readline()
    commit_id = line.split(" ")[1][:12]

    fp.readline()
    fp.readline()

    line = fp.readline()
    sub = line[len("Subject: "):]
    if sub.startswith("["):
        index = sub.find("]")
        if index != -1:
            sub = sub[index+1 : ].strip()

    line = fp.readline().strip()
    if line != "":
        sub = "%s %s" % (sub, line)

    return (commit_id, sub)
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        log("error")
        exit(1)
    parent_dir = sys.argv[1]
    patches = os.listdir(parent_dir)
    patches.sort(patch_name_cmp)
    
    i = -1
    (fea_name, fea_start, fea_end) = ("", 0, 0)
    fp = open("feature-commits", "w")
    for p in patches:
        if p.startswith("."):
            continue
        patch_no = int(get_patch_number(p))
        if patch_no > fea_end:
            i += 1

            if (i >= len(features)):
                break
            (fea_name, fea_start, fea_end) = features[i]
            fp.write("%s:\n" % fea_name)
        if patch_no >= fea_start and patch_no <= fea_end:
            fp.write("%s %s\n" % get_patch_commit_id("%s/%s" % (parent_dir, p)))
            
    fp.close()