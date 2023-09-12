#!/bin/python
# -*- coding:utf-8 -*-

"""
补丁解析器

作者：苟浩 <gouhao@uniontech.com>
日期：2021年11月16日

将patch信息解析，并生成excel表。
使用git format-patch 导出标准的补丁集，把导出的补丁放到一个文件夹里，然后使用下面命令进行解析

usage: parse_patches_info.py [-h] [-p PATH] [-t TYPE] [-e EXCEL]

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  补丁文件夹路径
  -t TYPE, --type TYPE  要解析的补丁类型：0: 欧拉, 1: 龙蜥. defalut=0，默认为解析欧拉补丁
  -e EXCEL, --excel EXCEL 要生成的excel类型：0: complete, 1: task, 2: merged_record. default=0
	complete: 完整的补丁信息表
	task: 每个月任务表类型
	merged_record: 已合入仓库的补丁表类型

"""
import os
import openpyxl
import argparse
import re
import time, datetime

def get_patch_number_str(p):
    """
    获取patch序号
    
    p: patch文件名

    return: 解析成功，返回文件序号；否则返回0
    """
    index = p.find("-")
    if index == -1:
        return None
    no = p[:index]
    return no

def get_patch_number(p):
    no = get_patch_number_str(p)
    if no and no.isdigit():
        return int(no)
    return 0



def patch_name_cmp(p1, p2):
    """
    patch文件名比较器
    p1, p2: 两个patch文件名
    """
    return get_patch_number(os.path.basename(p1)) - get_patch_number(os.path.basename(p2))

class PathInfo:
	def __init__(self):
		self.commit_id = None
		self.name = None
		self.origin = None
		self.origin_version = None
		self.origin_commit_id = None
		self.author = None
		self.category = None
		self.bug_no = None
		self.date = None
		self.subject = None
		self.cve = None
		self.signed_by = []
		self.change_files = []

class PatchParser:
    """
    补丁解析器父类
    """

    # 补丁段类别
    __SECTION_HEADER = 0
    __SECTION_COMMIT_MSG = 1
    __SECTION_SIGNBY = 2
    __SECTION_FILE_LIST = 3
    __SECTION_CHANGE = 4

    def __init__(self, path):
        """
        path: 补丁路径
        """
        self.__patches_path = path

        # 解析函数列表，按补丁段类别的顺序排列
        self.__parse_funcs = [
            self._parse_header,
            self._parse_commit_msg,
            self._parse_signby,
            self._parse_file_list,
            self._parse_change
        ]

        # 解析结果列表。每个元素是PathInfo
        self.__parse_results = []
        
    def start_parse(self):
        """
        解析补丁
        """

        # 获取补丁列表，并按补丁序号排序
        patches = os.listdir(self.__patches_path)
        patches.sort(patch_name_cmp)

        for patch in patches:
            if patch.startswith("."): 
                continue

            info = PathInfo()
            info.name = patch
            patch_abs_patch = "%s/%s" % (self.__patches_path, patch)

            self._start_parse(patch_abs_patch)

            # 解析补丁的第一行
            patch_file = open(patch_abs_patch, "r")
            line_count = 0

            for line in patch_file:
                line_count += 1                
                line = line.strip()
                
                # 计算当前行的类型
                self.__calc_section_type(line, line_count)

                # 根据类型解析当前行
                self.__parse_funcs[self.section_type](line, line_count, info)

            # 如果是stable但是没有类别，则默认为bugfix
            if not info.category and info.bug_no:
                info.category = "bugfix"

            self.__parse_results.append(info)

    def get_results(self):
        """
        获取解析结果
        """
        return self.__parse_results

    def __calc_section_type(self, line, line_count):
        """
        计算当前行的段类型
        """
        if line_count <= 4:
            self.section_type = PatchParser.__SECTION_HEADER
        elif self.section_type == PatchParser.__SECTION_HEADER:
            # 头部信息完了是提交日志
            self.section_type = PatchParser.__SECTION_COMMIT_MSG
        elif self.section_type == PatchParser.__SECTION_COMMIT_MSG and line.find("Signed-off-by") != -1:
            # 特殊头部完了是
            self.section_type = PatchParser.__SECTION_SIGNBY
        elif self.section_type == PatchParser.__SECTION_SIGNBY and line.startswith("---"):
                # 签名段结束了是文件列表段
                self.section_type = PatchParser.__SECTION_FILE_LIST
        elif self.section_type == PatchParser.__SECTION_FILE_LIST:
                if line.find("files changed") != -1 \
                    or line.find("file changed") != -1 \
                    or line.find("insertion") != -1 \
                        or line.find("deletion") != -1:
                    # 遇到这些值时，文件列表段结束
                    self.section_type = PatchParser.__SECTION_CHANGE

    def _parse_header(self, line, line_count, info):
        """
        解析补丁头
        """
        if line_count == 1:
            # commit id
            info.commit_id = line.split(" ")[1][:12]
        elif line_count == 2:
            # 作者
            info.author = line[len("From: "):]
        elif line_count == 3:
            # 日期
            info.date = line[len("Date: "):]
        elif line_count == 4:
            # 主题
            sub = line[len("Subject: "):]
            if sub.startswith("["):
                index = sub.find("]")
                if index != -1:
                    sub = sub[index+1 : ].strip()
            info.subject = sub

    def _start_parse(self, patch_name):
        """
        开始解析一个补丁时的回调
        """
        pass

    def _parse_commit_msg(self, line, line_count, info):
        """
        解析特殊补丁头

        这个只有欧拉的补丁才有
        """
        pass

    def _parse_signby(self, line, line_count, info):
        """
	解析签名段信息
	"""
        ret = re.match(".*<(.*)@uniontech.com>.*", line)
        if ret:
                info.signed_by.append(ret.group(1))

    def _parse_file_list(self, line, line_count, info):
        """
        解析修改的文件列表
        """
        i = line.find("|")
        if i == -1:
            return
        info.change_files.append(line[:i - 1].strip())

    def _parse_change(self, line, line_count, info):
        """
        解析修改的内容
        """
        pass

class EulerPatchParser(PatchParser):
    """
    欧拉补丁解析器
    """
    def __init__(self, path):
        PatchParser.__init__(self, path)        
        self.__euler_commit_header_end = False

    def _start_parse(self, patch_name):
        self.__euler_commit_header_end = False

    def _parse_commit_msg(self, line, line_count, info):
        if self.__euler_commit_header_end:
            return
        # 如果提交日志中出现---，则说明欧拉的特殊头部信息结束
        # 如果没有这个，则有可能将提交信息中其它带from的信息解析出来
        if line.startswith("---"):
            self.__euler_commit_header_end = True
            return

        if line.find("inclusion") != -1:
            # 来源
            info.origin = line.split(" ")[0]
        elif line.startswith("from"):
            # 来源版本
            info.origin_version = line[line.find("from") + 5 : len(line)].strip()
        elif line.startswith("bugzilla:"):
            # Bug号
            info.bug_no = line[line.find("bugzilla:") + 9: len(line)].strip()
        elif line.startswith("commit"):
            # commit id
            info.origin_commit_id = line[line.find("commit") + 7: len(line)].strip()
        elif line.startswith("category:"):
            # 类别
            info.category = line[line.find("category:") + 9: len(line)].strip()
        elif line.startswith("CVE:"):
            # cve号
            info.cve = line[line.find("CVE:") + 4: len(line)].strip()

class AnolisPatchParser(PatchParser):
    """
    龙蜥补丁解析器
    """
    def __init__(self, path):
        PatchParser.__init__(self, path)
    
    def _parse_header(self, line, line_count, info):
        # 龙蜥补丁里，Subject中带ck: 都是龙晰自己的补丁
        PatchParser._parse_header(self, line, line_count, info)
        if info.subject and info.subject.find("ck:") != -1 and not info.category:
            info.category = "feature"

    def _parse_signby(self, line, line_count, info):
        # 龙蜥补丁里根据签名段的这个邮件地址，识别该补丁是否来自stable
        PatchParser._parse_signby(self, line, line_count, info)
        if line.find("stable@vger.kernel.org") != -1:
            info.category = "bugfix"
            info.origin = "stable"

    def _parse_commit_msg(self, line, line_count, info):
        # 龙蜥补丁的提交日志里带fix的认为是bugfix类型补丁
        if line.lower().find("fix") != -1:
            info.category = "bugfix"
        if line.find("OpenAnolis Bug") != -1:
            info.category = "bugfix"
            info.bug_no = line.split(":")[1].strip()
        elif line.startswith("to #") or line.startswith("ANBZ: #") \
             or line.startswith("fix #"):
            info.category = "bugfix"
            info.bug_no = line.split("#")[1].strip()

class BaseExcel:
	DEFAULT_VALUE = "-"
	def __init__(self, headers):
		self.item_count = len(headers)
		self.headers = headers

	def create_header(self, ws):
		"""
		创建Excel表头
		wb: Workbook对象
		"""
		ws.append(self.headers)

	def _get_real_value(self, content, defstr, i):
		if not content or len(content) == 0:
			return defstr
		return content

	def _get_values(self, info):
		pass

	def create_excel(self, ws, results):
		for info in results:
			row_items = [self.DEFAULT_VALUE] * self.item_count
			values = self._get_values(info)
			for i in range(0, self.item_count):
				row_items[i] = self._get_real_value(values[i], self.DEFAULT_VALUE, i)

			ws.append(row_items)

class EmptyValueExcel(BaseExcel):
	def _get_real_value(self, content, defstr, i):
		v = BaseExcel._get_real_value(self, content, defstr, i)
		if v == self.DEFAULT_VALUE and i < 4:
			return ""
		return v

"""
完整的Excel信息
"""
class CompleteExcel(BaseExcel):
	HEADERS = [
		"Patch Name", "Type", "Category",
		"CVE",  "Bug Number", "Version",
		"Commit Id", "Subject", "Date",
		"Author", "Files"
	]

	def __init__(self):
		BaseExcel.__init__(self, self.HEADERS)

	def _get_values(self, info):
		return [
			info.name, info.origin, info.category, info.cve,  
            		info.bug_no, info.origin_version,  info.commit_id, 
            		info.subject, info.date, info.author, str(info.change_files)
        	]

"""
工作任务Excel
"""
class TaskExcel(EmptyValueExcel):
	HEADERS = [
		"Feature", "Status", "Owner", 
		"Remarks", "Commit-id", "Subject", "Bug-ID"
	]
	def __init__(self):
		BaseExcel.__init__(self, self.HEADERS)

	def _get_values(self, info):
		return ["", "", "", "", info.commit_id, 
            		info.subject, info.bug_no
		]

"""
已合入补丁记录
"""
class MergedRecordExcel(EmptyValueExcel):
	HEADERS = [
		"Feature", "Owner", "Commit-id",
		"Subject", "Date"
	]

	def __init__(self):
		EmptyValueExcel.__init__(self, self.HEADERS)

	def get_owner_name(self, name):
		if name.startswith("jiazhenyuan"):
			return "贾镇源"
	
	def get_time_stamp(self, date):
		result = re.search(r"[\-\+]\d+", date)
		if result:
			time_area = result.group()
			symbol = time_area[0]
			offset = int(time_area[1]) + int(time_area[2])
			if symbol == "+":
				format_str = '%a, %d %b %Y %H:%M:%S '+ time_area
				if "UTC" in date:
					format_str = '%a, %d %b %Y %H:%M:%S '+ time_area+ ' (UTC)'
				if "GMT" in date:
					format_str = '%a, %d %b %Y %H:%M:%S ' + time_area + ' (GMT)'
				if "CST" in date:
					format_str = '%a, %d %b %Y %H:%M:%S ' + time_area + ' (CST)'
				utcdatetime = time.strptime(date, format_str)
				tempsTime = time.mktime(utcdatetime)
				tempsTime = datetime.datetime.fromtimestamp(tempsTime)
				if offset > 8:
					offset = offset -8
				tempsTime = tempsTime + datetime.timedelta(hours=offset)
				localtimestamp = tempsTime.strftime("%Y/%m/%d %H:%M:%S")
			else:
				format_str = '%a, %d %b %Y %H:%M:%S ' + time_area
				utcdatetime = time.strptime(date, format_str)
				tempsTime = time.mktime(utcdatetime)
				tempsTime = datetime.datetime.fromtimestamp(tempsTime)
				tempsTime = tempsTime + datetime.timedelta(hours=(offset + 8))
				localtimestamp = tempsTime.strftime("%Y/%m/%d %H:%M:%S")
			return localtimestamp

	def _get_values(self, info):
		owner = ""
		ret = re.match(".*<(.*)@uniontech.com>.*", info.author)
		if ret:
			owner = ret.group(1)
		elif len(info.signed_by) != 0:
			owner = ", ".join(info.signed_by)

		return ["", owner, info.commit_id, 
            		info.subject, self.get_time_stamp(info.date)
		]

PARSERS = [
    (EulerPatchParser, "openeuler_patch_info.xlsx"),
    (AnolisPatchParser, "openanolis_patch_info.xlsx")
]

EXCELS = [
	CompleteExcel,
	TaskExcel,
	MergedRecordExcel
]

def parse_args():
	"""
	解析命令行参数
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", "--path", help="patchset path")
	parser.add_argument("-t","--type", type=int, default=0,
			help="0: euler, 1: anolis. defalut=0")
	parser.add_argument("-e","--excel", type=int, default=0,
			help="0: complete, 1: task, 2: merged_record. default=0")

	return parser.parse_args()

if __name__ == "__main__":
	args = parse_args()
    

	""" 
	补丁类型:
	0: 欧拉
	1: 龙晰
	"""
	patch_type = args.type

	(classs, filename) = PARSERS[patch_type]
	patch_parser = classs(args.path)

	patch_parser.start_parse()
	results = patch_parser.get_results()

	""" 
	补丁类型:
	0: 完整信息表
	1: 任务列表
	"""
	excel = EXCELS[args.excel]()

	wb = openpyxl.Workbook()
	ws = wb.worksheets[0]
	ws.number_format = '@'
	excel.create_header(ws)
	excel.create_excel(ws, results)
	wb.save(os.path.basename(filename))
