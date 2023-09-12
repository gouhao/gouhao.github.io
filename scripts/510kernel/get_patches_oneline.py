#!/bin/python
# -*- coding:utf-8 -*-

"""
提取一个目录里补丁的git oneline信息
"""

from common import *

import sys, os

if __name__ == "__main__":
    if len(sys.argv) < 2: 
        log("Need path!")
        exit(1)
    p = sys.argv[1]

    patches = os.listdir(p)
    patches.sort(patch_name_cmp)

    fp = open("git_oneline", "w")
    for patch in patches:
        if patch.startswith("."):
            continue
        patch_path = "%s/%s" % (p, patch)
        number = get_patch_number_str(patch)
        (id, subj) = get_patch_commit_oneline(patch_path)
        fp.write("%s: %s %s\n" % (number, id, subj))
    fp.close()
