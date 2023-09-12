#!/bin/python

import sys, re

"""
Usage: ./count_ltp.py result.log mode

mode: default: 1
	1: failed
	2: success
	3: all
"""
if __name__ == "__main__":
	
	if (len(sys.argv) < 2):
		print("Err: Usage: ./count_ltp.py result.log [mode]")
		exit(1)

	fp = open(sys.argv[1], "r")
	results = fp.readlines()
	fp.close()

	mode = 1
	if (len(sys.argv) > 2):
		mode = int(sys.argv[2])
		if (mode < 1 or mode > 3):
			print("Err: Usage: ./count_ltp.py result.log [mode]")
			exit(1)
		
	count = {}
	for r in results:
		if (mode == 1):
			cond = ".*FAIL.*"
		elif (mode == 2):
			cond = ".*PASS.*"
		else:
		 	cond = ".*(FAIL|PASS).*"

        	if not re.match(cond, r):
			continue
		k = r.split()[0]
		if not count.has_key(k):
			count[k] = 0
		count[k] = count[k] + 1
	
	for k in sorted(count):
		print("%s: %d" % (k, count[k]))



