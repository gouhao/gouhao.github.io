#!/bin/python
# -*- coding:utf-8 -*-

"""
对比2个excel文档的不同，把new的更新到old里
./compile_excel.py old.xlsx new.xlsx
"""
import sys
import openpyxl

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("param error!")
		exit(1)
	oneline = sys.argv[1]
	subj = sys.argv[2]

	fp_oneline = open(oneline, "r")
	fp_subj = open(subj, "r")
	fp_tmp = open("tmp-file", "w")

	for target in fp_subj:
		found = False
		fp_oneline.seek(0)
		target = target.strip()
		for line2 in fp_oneline:
			if line2.find(target) != -1:
				fp_tmp.write(line2)
				found = True
				break
		if not found:
			print("not found: %s" % target)
			fp_tmp.write("%s\n" % target)

	fp_tmp.close()
	fp_subj.close()
	fp_oneline.close()


