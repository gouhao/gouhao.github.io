#!/bin/bash

has_kdump=`systemctl list-units|grep kdump`
if [ ! "$has_kdump" ]; then
	exit 1
fi

ret=`systemctl status kdump 2> /dev/null | grep "Active:" | grep fail`
if ["$ret" ]; then
	exit 1
fi