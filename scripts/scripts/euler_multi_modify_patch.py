#!/bin/python
# -*- coding:utf-8 -*-

"""
找出欧拉修改了多个顶级目录的提交

作者：苟浩 <gouhao@uniontech.com>
日期：2021年11月25日


用法：
./euler_multi_modify_patch.py -p path -t patch_type
patches_path: 补丁路径
patch_type: 补丁类型。0：欧拉（默认）；1：龙蜥

输出：
1.euler-multi-modify-list
    非stable的bugfix信息，每行数据由：commit-id subject组成
"""

import sys, os
import argparse
from common import *
from patch_parser import *

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
        if info.category == "bugfix" and info.origin != "stable":
            non_stable_bugfix.append(info)

    multi_modify_infos = {}
    for info in non_stable_bugfix:
        short_commit_id = info.commit_id[:8]
        last_folder = None
        for f in info.change_files:
            folder = None

            # 找第一个不为.开头的目录
            while True:
                i = f.find("/")
                if i == -1:
                    break

                folder = f[:i]
                if not folder.startswith("."):
                        break
                f = f[i+1:]

            if not folder:
                continue
            
            # patch 文件里目录都是排好序的，
            # 如果上次目录和这次目录相同就不用重复添加
            if last_folder == folder:
                continue

            last_folder = folder
            # 如果没有列表，则创建列表
            if not multi_modify_infos.has_key(short_commit_id):
                multi_modify_infos[short_commit_id] = []
            
            multi_modify_infos[short_commit_id].append(folder)
        if multi_modify_infos.has_key(short_commit_id):
            multi_modify_infos[short_commit_id] = list(set(multi_modify_infos[short_commit_id])) 
        else:
            print("no folder: %s" % short_commit_id)
        
    fp = open("euler-multi-modify-list", "w")
    count = 0
    for (commit, filelist) in multi_modify_infos.items():
        if len(filelist) == 1:
            count += 1
            continue
        
        fp.write("%s " % commit)
        for f in filelist:
            fp.write("%s " % f)
        
        fp.write("\n")
    
    fp.close()
    print("count=%d" % count)
