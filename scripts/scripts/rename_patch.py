#!/bin/python
# -*- coding:utf-8 -*-

"""
按序号重命令名文件夹补丁

作者：苟浩 <gouhao@uniontech.com>
日期：2021年11月18日
"""

import common
import sys, os

if __name__ == "__main__":
    if len(sys.argv) < 2:
        common.log("Need path!")
        exit(1)
    p = sys.argv[1]

    p_tmp = "%s_tmp" % p
    os.system("rm -rf %s" % p_tmp)

    os.mkdir(p_tmp)
    files = os.listdir(p)
    files.sort(common.patch_name_cmp)
    count = 0
    for f in files:
        count += 1
        name = common.get_patch_name(f)
        os.system("mv %s/%s %s/%d-%s.patch" % (p, f, p_tmp, count, name))

