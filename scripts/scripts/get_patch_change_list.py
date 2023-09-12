#!/bin/python
# -*- coding:utf-8 -*-

"""
获取补丁的文件变化列表

作者：苟浩 <gouhao@uniontech.com>
日期：2021年12月21日

使用示例：
./get_patch_change_list.py /home/patches_dir

输入：
补丁集路径

输出：
json格式的文件变化列表，key:目录， value:commit列表
"""

import sys, os
import openpyxl
from common import *
from patch_parser import *
import json

def get_file_dir(file_path):
    index = file_path.rfind("/")
    if index == -1:
        return file_path
    return file_path[:index]

def has_commit(commit_list, commit_id):
    for commit in commit_list:
        if commit.startswith(commit_id):
            return True
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        log("Need path!")
        exit(1)
    
    patches_path = sys.argv[1]
    parser = EulerPatchParser(patches_path)
    parser.start_parse()
    patch_infos = parser.get_results()

    change_dict = {}

    for info in patch_infos:
        short_commit_id = info.commit_id[:12]
        for change_file in info.change_files:
            key = get_file_dir(change_file)
            if not change_dict.has_key(key):
                change_dict[key] = []
            elif (has_commit(change_dict[key], short_commit_id)):
                continue
            change_dict[key].append("%s %s" % (short_commit_id, info.name))

    fp = open("change_list.json", "w")
    fp.write(json.dumps(change_dict, indent=4))
    fp.close()