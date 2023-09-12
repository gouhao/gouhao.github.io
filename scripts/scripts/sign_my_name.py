#!/bin/python
# -*- coding:utf-8 -*-

"""
给patch里签我的名字
"""

import sys, os

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Need Path!")
        exit(1)

    patches_dir = sys.argv[1]
    files = os.listdir(patches_dir)

    for f in files:
        file_abs_path = "%s/%s" % (patches_dir, f)
        tmp_fp = open("%s_tmp" % file_abs_path, "w")
        fp = open(file_abs_path, "r")

        signed_by_section = False
        signed_by_prefix = ""
        signed = False
        for line in fp:
            if signed:
                tmp_fp.write(line)
                continue
            signed_by_index = line.find("Signed-off-by:")
            if  signed_by_index != -1:
                signed_by_section = True
                # 前面可能有空格或者\t, 以最后一个signed-by为主
                signed_by_prefix = line[:signed_by_index]

            if signed_by_section and line.startswith("---"):
                # signed by 结束，写入我的名字
                tmp_fp.write("%sSigned-off-by: Gou Hao <gouhao@uniontech.com>\n" % signed_by_prefix)
                signed = True

            tmp_fp.write(line)
        tmp_fp.close()
        fp.close()
        os.rename("%s_tmp" % file_abs_path, file_abs_path)
            