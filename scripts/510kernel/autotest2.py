#!/bin/python
# -*- coding:utf-8 -*-

"""
自动测试unixbench脚本
作者：苟浩 <gouhao@uniontech.com>
日期：2022年05月13日

用一个testlist.json文件记录测试列表
{
    "enable": true, // 是否使能。true: 开机自动执行测试用例，false：不执行
    "base_kernel": "5.10.0_10try+", // 要比较的基础内核
    "tests":[ // 要测试的kernel列表
        {
            "kernel":"5.10.0-10-base", // kernel名称
            "count":10, // 要测试的次数
            // 测试状态，有3种状态：running(正在运行测试)， finish(已经执行完成)
            // error(执行错误)，执行错误时会在msg里写出错误原因
            "status":"running" 
        },
        { # 这是已经完成的测试
            "kernel":"5.10.0-10-base",
            "count":0,
            "status":"finish"
        },
        { # 这是出错的测试
            "kernel":"5.10.0-10-base",
            "count":10,
            "status":"error",
            "msg":"can not found kernel"
        }
    ]
}

我们在填写这个文件的时候，只需要写kernel, count这两个字段就行，其它字段是脚本自己填写。

---

脚本流程：
1. 解析testlist.json文件
2. 判断json.enable变量是否使能，不使能则退出
3. 根据当前系统运行的kernel，从json.tests里匹配
    3.1 没有找到当前kernel或者找到当前kernel在json.tests的status为finish或者error, 
        则从json.tests里选一个没有status字段或status为runing的kernel，并修改grub配置，然后重启，
        如果json.tests没有可运行的kernel，则修改json.enable为false，结束脚本
    3.2 找到当前kernel，且json.tests里status为runing或者没有status，则继续
4. 运行unixbench测试用例
5. 修改json.tests里对应kernel的status和count
6. 如果count为0，则从json.tests里选一个没有status字段或status为runing的kernel，并修改grub配置，然后重启，
    如果json.tests没有可运行的kernel，则修改json.enable为false，结束脚本
"""

import json
import os
import time

CONFIG="testlist.json"

ERR_UNKNOWN = -1
ERR_NOT_FOUND_KERNEL = -2
ERR_NOT_FOUND_ENTRY = -3
ERR_DO_TEST = -4

class AutoTest:
    def __init__(self):
        self.json_obj = None
        self.test_obj = None

        uname = os.uname()
        self.sys_kernel = uname[2]
        self.sys_arch = uname[4]
    
    def read_config(self):
        if not os.path.exists(CONFIG):
            print("Can not found %s" % CONFIG)
            exit(1)

        jsonstr = ""
        fp = open(CONFIG, "r")
        for line in fp:
            jsonstr += line.strip()
        fp.close()

        self.json_obj = json.loads(jsonstr)

    def do_test(self):
        time.sleep(60)
        curr_dir = os.curdir()
        os.chdir("/home/performance-510/UnixBench5.1.3-1/")
        if os.system("./Run -c 1 -c 64 > /tmp/unixbench_%s_result" % self.sys_kernel) \
            or os.system("./unixbench_result_chk  -k %s -f /tmp/unixbench_%s_result \
                        >> /tmp/unixbench_%s_%s_report" % (self.json_obj["base_kernel"], \
                            self.sys_kernel, self.sys_kernel, self.sys_arch)) \
            or os.system("./unixbench_result_chk  -b -f /tmp/unixbench_%s_result" % self.sys_kernel):
            return ERR_DO_TEST
        os.chdir(curr_dir)
        return 0

    def get_entry_kernel(self, entry):
        start = entry.find("-")
        end = entry.rfind(".")
        if start == -1 or end == -1:
            return None
        return entry[start+1:end]

    def update_grub(self):
        kernel = self.test_obj["kernel"]
        if not os.path.exists("/boot/vmlinuz-%s" % kernel) \
            or not os.path.exists("/boot/initramfs-%s.img" % kernel):
            return ERR_NOT_FOUND_KERNEL

        if self.sys_arch == "aarch64":
            entry = None
            for f in os.listdir("/boot/loader/entries/"):
                if not os.path.isfile("/boot/loader/entries/%s" % f):
                    continue
                ek = self.get_entry_kernel(f)
                if not ek:
                    continue
                if ek == kernel:
                    entry = f
                    break
            if not entry:
                return ERR_NOT_FOUND_ENTRY
            os.system("sed -i -e '/saved_entry=/d' /boot/grub2/grubenv")
            os.system("sed -i '/kernelopts/i saved_entry=%s' /boot/grub2/grubenv" % entry)
        elif self.sys_arch == "x86_64":
            os.system("sed -i 's/%s/%s/g' /boot/grub2/grub.cfg" % (self.sys_kernel, kernel))
        return 0

    def get_err_msg(self, err_code):

        if err_code == ERR_NOT_FOUND_KERNEL:
            return "Can not found kernel vmlinuz or initram"
        elif err_code == ERR_NOT_FOUND_ENTRY:
            return "Can not found kernel entry"
        elif err_code == ERR_DO_TEST:
            return "Do test error"
        else:
            return "Unknown error"
        
    def set_test_error(self, err):
        self.test_obj["status"] = "error"
        self.test_obj["msg"] = self.get_err_msg(err)

    def select_other_kernel(self):
        for test in self.json_obj["tests"]:
            if not test.has_key("status") or test["status"] == "running":
                self.test_obj = test
                err = self.update_grub()
                if err < 0:
                    self.set_test_error(err)
                    self.test_obj = None
                break
    
    def write_config(self):
        os.unlink(CONFIG)
        fp = open(CONFIG, "w")
        fp.write(json.dumps(self.json_obj))
        fp.flush()
        fp.close()

    def start(self):
        # 解析testlist.json
        self.read_config()

        # 没能使能，直接退出
        if not self.json_obj["enable"]:
            exit(0)

        # 找当前系统运行的kernel对应的测试对象
        for test in self.json_obj["tests"]:

            if test["kernel"] != self.sys_kernel:
                continue

            if not test.has_key("status") or test["status"] == "running":
                # 如果还没有运行，或者状态为running，则运行这个内核的测试
                self.test_obj = test
                err = self.do_test()
                if err < 0:
                    self.set_test_error(err)
                    self.test_obj = None
            else:
                    self.test_obj["count"] -= 1
                    if self.test_obj["count"] > 0:
                        self.test_obj["status"] = "running"
                    else:
                        self.test_obj["status"] = "finish"
                        # 这个用例已经完成，把test_obj标成None，在下面重新选择一个内核
                        self.test_obj = None
            
            # 这里直接退出
            break
        
        # 如果没有当前kernel对应的测试对象，则重新选择一个内核
        if not self.test_obj:
            self.select_other_kernel()
        
        # 如果没有测试对象，则禁用自动测试
        if not self.test_obj:
            self.json_obj["enable"] = False
        
        # 重新写配置文件
        self.write_config()

        # 把文件同步到磁盘
        os.system("sync")

        # 如果还要测试，就重启
        if self.json_obj["enable"]:
            os.system("reboot")

if __name__ == "__main__":
    AutoTest().start()

