#!/bin/python
# -*- coding:utf-8 -*-

"""
按标题查找仓库是否已合入补丁
./check_merged_in_repo.py repo list [mode]
mode: 1: 精确匹配; 2: 模糊匹配。默认 1

"""
import sys,time

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

	mode = 1
	if len(sys.argv) > 3:
		mode = int(sys.argv[3])
	fp_subj = open(subj, "r")
	subjs = fp_subj.readlines()
	fp_subj.close()
	
	subjs_cp = []
	subjs_cp.extend(subjs)

	fp_repo = open(repo, "r")
	repo_line = fp_repo.readlines()
	fp_repo.close()

	merged = []
	t = int(round(time.time() * 1000)) 
	for line in subjs_cp:
		subj = get_subj(line)
		for i in repo_line:
			tmp = get_subj(i)
			if (mode == 1 and tmp == subj) or \
				(mode == 2 and (tmp.find(subj) != -1 or subj.find(tmp) != -1)):
				# 删除已经从repo合入的补丁
				repo_line.remove(i)
				subjs.remove(line)
				merged.append(line)
				break
	
	print("time=%d\n" % (int(round(time.time() * 1000)) - t))
	print("merged:")
	for i in merged:
		print(i)
	
	print("\nunmerged:")
	for i in subjs:
		print(i)


