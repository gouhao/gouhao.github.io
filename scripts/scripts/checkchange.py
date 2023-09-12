#!/bin/python
# -*- coding:utf-8 -*-

"""
比较两个仓库的文件是否相同。用法：
./checkchange.py change_file path1 path2

change_file: 把任务表格的最后一列change_list复制到一个文件里，如下格式：
['drivers/tty/serial/amba-pl011.c']
['drivers/vfio/pci/vfio_pci.c']
['drivers/usb/gadget/composite.c', 'drivers/usb/gadget/function/rndis.c']
['drivers/irqchip/irq-gic-v3-its.c']
....


path1/2: 两个仓库的路径
"""
import os, sys,ast

if __name__ == "__main__":
    change_file = sys.argv[1]
    path1 = sys.argv[2]
    path2 = sys.argv[3]
    ## get change list
    change_list = []
    fp = open(change_file, "r")
    for line in fp:
        if line[-1] == "\n":
            line = line[:-1]
        change_list.append(ast.literal_eval(line))

    fp.close()

    os.system("rm -f file.diff")

    ## compare
    for list1 in change_list:
        for file in list1:
            cmd = "diff -Nur %s/%s %s/%s 2>&1 >> file.diff" % (path1, file, path2, file)
            print(cmd)
            os.system(cmd)
