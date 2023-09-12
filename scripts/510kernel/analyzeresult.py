#!/bin/python
# -*- coding:utf-8 -*-

"""
分析autotest.sh跑完的结果
用法：./analyzeresult.py filepath
"""

import sys, re

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage: ./analyzeresult.py filepath")
		exit(1)
	fp = open(sys.argv[1], "r")
	bad = False
	ret = {}
	for line in fp:
		line = line.strip()
		if len(line) == 0:
			continue
		if bad:
			bad = False
			match_ret = re.match(".* (.*)% Poor for (.*) test.*", line)
			if not match_ret:
				continue
			rate = int(match_ret.group(1))

			if (rate > -2):
				continue
			name = match_ret.group(2)
			if not ret.has_key(name):
				value = {}
				ret[name] = value

				value["count"] = 0
				value["rates"] = []

			value = ret[name]
			value["count"] = value["count"] + 1
			value["rates"].append(rate)
			continue
		if line.find("Bad") == -1:
			continue
		bad = True
	fp.close()

	if len(ret) == 0:
		print("No Bad item.")
		exit(0)
	print("Bad items:")
	for k in ret.keys():
		i = ret[k]
		if i["count"] < 3:
			continue
		print("name: %s\ncount: %s\nrates: %s\n" \
			% (k, i["count"], str(i["rates"])))
