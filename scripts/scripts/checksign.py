#!/bin/python
# -*- coding:utf-8 -*-

"""
检查补丁没有签名或者签名重复

用法：./checksign.py 补丁目录
"""
import os, sys

if __name__ == "__main__":
    patch_dir = sys.argv[1]
    for f in os.listdir(patch_dir):
        fp = open("%s/%s" % (patch_dir, f), "r")
        sign_counter = 0
	cherry_from = 0
        for line in fp:
            if line.startswith("diff --git"):
                break
            if line.find("Signed-off-by: Gou Hao <gouhao@uniontech.com>") != -1:
                sign_counter += 1
            elif line.find("Cherryfrom:") != -1:
		cherry_from += 1
        if sign_counter == 0 or cherry_from == 0:
            print("no sign line or no cherry from: %s" % f)
        elif sign_counter > 1 or cherry_from > 1:
            print("more sign line or more cherry from: %s" % f)
