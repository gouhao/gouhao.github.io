#!/bin/python
# -*- coding:utf-8 -*-

"""
按标题查找仓库是否已合入补丁
./check_merged_in_repo.py repo list
"""
from os import popen
import sys
import os

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("param error!")
		exit(1)
	repo = sys.argv[1]
	subj = sys.argv[2]

	fp_subj = open(subj, "r")
	fp_tmp = open("tmp_", "w")
	fp_repo = open(repo, "r")
	target = fp_subj.readline().strip()

	for line1 in fp_repo:
		line1 = line1.strip()
		if line1.find(target) != -1:
			target = fp_subj.readline().strip()

	fp_tmp.write("%s\n" % target)
	for line1 in fp_subj:
		fp_tmp.write("%s" % line1)
	fp_subj.close()
	fp_tmp.close()
	fp_repo.close()


