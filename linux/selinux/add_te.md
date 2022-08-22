# 增加SELinux TE 规则方法

1. 执行semanage dontaudit off。因为有时审计日志打印的不全。

2. 判断是不是因为selinux权限导致的问题。打开selinux，命令无法执行；关闭selinux，命令可以执行，则可以确定是selinux的问题。

3. 执行setenforce 0，关闭selinux。

4. tail -f /var/log/audit/audit.log，再执行相应的命令。这样可以只获取在这个命令执行期间出现的AVC日志，在加权限的时候要保证最小权限。

5. 将第4步中的命令执行期间出现的日志保存到文件中，比如test_log。

6. 生成te规则：audit2allow -i test_log > test.te。生成的te规则可以直接添加到selinux-policy相关模块的te规则中。

7. 生成pp文件: audit2allow -i test_log -M test。

8. 安装第7步中生成的pp文件： semodule -i test.pp。

9. 验证是否解决了此命令的权限问题：打开selinux，然后再执行命令，看是否正常执行。

10. 如果第9步无法正常执行，则跳到第3步，重做第3步和第9步之间操作，直到命令可以正常执行。