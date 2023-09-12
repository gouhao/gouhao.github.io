#!/bin/python
# -*- coding:utf-8 -*-

"""
从仓库里检查各补丁的状态

主要检查任务列表中的已合入和未合入的状态是否正确

用法：
./check_patch_status_from_repo -m excel表 -g gitoneline_list --force_write -s anolis

-m: excel表, 要检查的任务表。注意：表的第0~5列分别是：特性名称, 状态, 负责人, 备注, Commit-Id, Subject, Bug-ID
-g: gitoneline_list, 从仓库导的git oneline 列表
--force_write: 当补丁与excel里状态不同时，是否要修改原始表。默认False
-s: excel的sheet名称，不指定的话用默认sheet
例如：
./check_patch_status_from_repo patches_info.xlsx gitoneline_list
"""

import openpyxl, sys
import argparse

INDEX_STATUS = 1
INDEX_OWNER = 2
INDEX_COMMITID = 4
INDEX_SUBJECT = 5

def print_list(msg, l):
	if len(l) == 0:
		return
	print(msg)
	for i in l:
		print(i)

def parse_args():
	"""
	解析命令行参数
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument("-m", "--main")
	parser.add_argument("-g","--git_list")
	parser.add_argument("--force_write", action="store_true", default=False)
	parser.add_argument("-s","--sheet_name", default=None)

	return parser.parse_args()

def get_sheet(wb, sheed_name):
	try:
		return wb.get_sheet_by_name(name = sheed_name)
	except:
		return None

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("Params error!\nUsage: ./check_patch_status_from_repo"\
			" excel.xlsx repo_path")
		exit(1)
	args = parse_args()
	excel_path = args.main
	gitoneline_path = args.git_list

	force_write = args.force_write

	fp = open(gitoneline_path, "r")
	git_onelines = fp.readlines()
	fp.close()

	excel_wb = openpyxl.load_workbook(excel_path)
	if not args.sheet_name:
		ws = excel_wb.active
	else:
		ws = get_sheet(excel_wb, args.sheet_name)

	if not ws:
		exit(1)

	nm_list = []
	y_not_in_repo = []
	in_repo_not_y = []

	for row in ws.rows:
		found = False
		subject = row[INDEX_SUBJECT].value
		subject = subject.strip()
		if subject == "Subject":
			continue

		for line in git_onelines:
			try:
				if line.startswith(subject):
					found = True
					git_onelines.remove(line)
					break
			except:
				pass

		if not found and row[INDEX_STATUS].value == 'Y':
			y_not_in_repo.append("%s %s %s" % (row[INDEX_OWNER].value, row[INDEX_COMMITID].value, subject))
			if force_write:
				row[INDEX_STATUS].value = 'N'
		elif found and (row[INDEX_STATUS].value == 'Y' or row[INDEX_STATUS].value == 'E'):
			continue
		elif found and row[INDEX_STATUS].value == 'NM':
			nm_list.append("%s %s %s" % (row[INDEX_OWNER].value, row[INDEX_COMMITID].value, subject))
		elif found and row[INDEX_STATUS].value != 'Y':
			in_repo_not_y.append("%s %s %s" % (row[INDEX_OWNER].value, row[INDEX_COMMITID].value, subject))
			if force_write:
				row[INDEX_STATUS].value = 'Y'

	print_list("\nnm_in_repo:", nm_list)
	print_list("\ny_not_in_repo:", y_not_in_repo)
	print_list("\nin_repo_not_y:", in_repo_not_y)

	excel_wb.save(excel_path)