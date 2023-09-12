#!/bin/python
# -*- coding:utf-8 -*-

"""
检查patch能否打进去

作者：苟浩 <gouhao@uniontech.com>
日期：2021年11月30日

"""
import os
import argparse
from common import *

def parse_args():
    """
    解析命令行参数

    -r: 仓库路径，必须。
    -p: 补丁路径，必须。
    -l: 补丁列表，非必须。如果不传默认打-p底下所有补丁
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--repo_path")
    parser.add_argument("-p", "--patches_path")
    parser.add_argument("-l", "--patches_list")

    return parser.parse_args()

def write_file(data, filename):
    fp = open(filename, "w")
    fp.writelines(data)
    fp.close()

if __name__ == "__main__":
    args = parse_args()

    if not args.repo_path or not args.patches_path:
        log("Need repo_path, patches_path")
        exit(1)

    patches_path = args.patches_path
    patches_list = args.patches_list
    if not patches_list:
        patches_list = os.listdir(patches_path)
        patches_list.sort(patch_name_cmp)
    else:
        tf = open(patches_list, "r")
        patches_list = tf.readlines()
        tf.close()

    save_dir = os.getcwd()

    os.chdir(args.repo_path)

    can_apply_list = []
    cannot_apply_list = []

    for p in patches_list:
        tmp_path = "%s/%s" % (patches_path, p)
        if os.system("git am %s &> /dev/null" % tmp_path):
            os.system("git am --abort")
            cannot_apply_list.append(p)
        else:
            can_apply_list.append(p)
    os.chdir(save_dir)

    write_file(cannot_apply_list, "cannot_apply_list")
    write_file(can_apply_list, "can_apply_list")  
    