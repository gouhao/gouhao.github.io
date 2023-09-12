#!/bin/python
# -*- coding:utf-8 -*-

"""
读取git oneline文件，按序号导出相应的补丁

作者：苟浩 <gouhao@uniontech.com>
日期：2022年02月08日

使用：
./export_patches_by_oneline.py repo_path oneline_file
"""
import os, sys

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Need oneline file")
        exit(1)
    repo_path = sys.argv[1]
    oneline_file = sys.argv[2]

    fp = open(oneline_file, "r")
    if not fp:
        print("Open file error")
        exit(1)
    curr_dir = os.getcwd()
    os.chdir(repo_path)
    start=1
    for line in fp:
        line = line.strip()
	cm_len = 12
	if len(line) < cm_len:
		cm_len = len(line)
        commit = line[:cm_len]
        if len(commit) == 0:
            continue
        cmd = "git format-patch -1 --start-number=%d %s -o %s" % (start, commit, curr_dir)
        os.system(cmd)
        start += 1
    fp.close()
