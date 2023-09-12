#!/bin/python
# -*- coding:utf-8 -*-

"""
按标题查找仓库是否已合入补丁
./check_merged_in_repo.py repo list
"""
import sys

def get_subj(line):
	i = line.find(" ")
	if i == -1:
		return line
	return line[i+1:]

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("param error!")
		exit(1)
	repo = sys.argv[1]
	subj = sys.argv[2]

	fp_repo = open(repo, "r")
	repo_line = fp_repo.readlines()
	fp_repo.close()

	fp_subj = open(subj, "r")
	subjs = fp_subj.readlines()
	fp_subj.close()

	unmerged = list(subjs)

	for line in subjs:
		subj = get_subj(line)
		for i in repo_line:
			tmp = get_subj(i)
			if tmp == subj:
				# 删除已经从repo合入的补丁
				repo_line.remove(i)
				unmerged.remove(line)
				break
	print("unmerged:")
	for i in unmerged:
		print(i.strip("\n"))


