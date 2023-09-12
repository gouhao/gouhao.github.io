#!/bin/python
# -*- coding:utf-8 -*-

"""
解析欧拉非stable的bugfix补丁

解析每个补丁中的文件列表，并将文件按一级目录归类

作者：苟浩 <gouhao@uniontech.com>
日期：2021年11月22日


用法：
./patch_filelist.py -p path -t patch_type
patches_path: 补丁路径
patch_type: 补丁类型。0：欧拉（默认）；1：龙蜥

输出：
1.euler-non-stable-bugfix-list
    非stable的bugfix信息，每行数据由：commit-id subject组成

2.change-folders
    这是一个目录，每个目录里的每个文件代表这一个文件夹里的改变的commit-id

3.non-stable-bugfix-patches
    存放的非stable的bug修复patch
"""
import sys, os
import argparse
from common import *
from patch_parser import *

FILE_BUGFIX_LIST = "euler-non-stable-bugfix-list"
FOLDER_CHANGE = "change-folders"
FOLDER_PATCHES = "non-stable-bugfix-patches"
# 解析器数组
PATCH_PARSERS = [EulerPatchParser,AnolisPatchParser]

def parse_args():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path")
    parser.add_argument("-t","--type", default=0)

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if not args.path:
        log("Need pathes path!")
        exit(1)

    patches_path = args.path
    patches_type = args.type

    # 解析补丁并获取结果
    parser = PATCH_PARSERS[patches_type](patches_path)
    parser.start_parse()
    results = parser.get_results()

    # 过滤非stable的buxfix
    non_stable_bugfix = []
    for info in results:
        if info.category == "feature" and info.origin == "mainline":
            non_stable_bugfix.append(info)
    
    files_dict = {}

    os.system("rm -rf %s && mkdir %s" % (FOLDER_PATCHES, FOLDER_PATCHES))
    # 按文件目录分类
    for info in non_stable_bugfix:
        os.system("cp %s/%s %s" % (patches_path, info.name, FOLDER_PATCHES))
        short_commit_id = info.commit_id[:12]
        last_key = None
        for f in info.change_files:
            key = None

            # 找第一个不为.开头的目录
            while True:
                i = f.find("/")
                if i == -1:
                    break

                key = f[:i]
                if not key.startswith("."):
                        break
                f = f[i+1:]

            if not key:
                continue

            # patch 文件里目录都是排好序的，
            # 如果上次目录和这次目录相同就不用重复添加
            if last_key == key:
                continue

            last_key = key
            # 如果没有列表，则创建列表
            if not files_dict.has_key(key):
                files_dict[key] = []
            
            files_dict[key].append((short_commit_id, info.name))

    os.system("rm -rf %s %s" %(FILE_BUGFIX_LIST, FOLDER_CHANGE))

    # 写入commit 和 主题信息
    f = open(FILE_BUGFIX_LIST, "w")
    for info in non_stable_bugfix:
        f.write("%s %s\n" % (info.commit_id[:12], info.subject))
    f.close

    # 按文件目录分类
    os.mkdir(FOLDER_CHANGE)
    os.chdir("%s/%s" % (os.getcwd(), FOLDER_CHANGE))

    for (folder, recs) in files_dict.items():
        f = open(folder, "w")
        for c,n in recs:
            f.write("%s %s\n" % (c, n))
        f.close()
