# mdadm
软raid管理工具

1. 创建4个块的raid 10
```sh
$ mdadm -Cv /dev/md0 -n4 -l 10 /dev/vdc /dev/vdd /dev/vde /dev/vdf 
mdadm: layout defaults to n2
mdadm: layout defaults to n2
mdadm: chunk size defaults to 512K
mdadm: size set to 20954112K
mdadm: Defaulting to version 1.2 metadata
mdadm: array /dev/md0 started.

```

2. 查询 
```sh
$ mdadm -Q /dev/md0 
/dev/md0: 39.97GiB raid10 4 devices, 0 spares. Use mdadm --detail for more detail.
$ mdadm --detail /dev/md0 
/dev/md0:
           Version : 1.2
     Creation Time : Mon Jul 24 13:51:04 2023
        Raid Level : raid10
        Array Size : 41908224 (39.97 GiB 42.91 GB)
     Used Dev Size : 20954112 (19.98 GiB 21.46 GB)
      Raid Devices : 4
     Total Devices : 4
       Persistence : Superblock is persistent

       Update Time : Mon Jul 24 13:54:34 2023
             State : clean 
    Active Devices : 4
   Working Devices : 4
    Failed Devices : 0
     Spare Devices : 0

            Layout : near=2
        Chunk Size : 512K

Consistency Policy : resync

              Name : localhost.localdomain:0  (local to host localhost.localdomain)
              UUID : 761e1614:44725656:12209ccd:6c438631
            Events : 17

    Number   Major   Minor   RaidDevice State
       0     253       32        0      active sync set-A   /dev/vdc
       1     253       48        1      active sync set-B   /dev/vdd
       2     253       64        2      active sync set-A   /dev/vde
       3     253       80        3      active sync set-B   /dev/vdf
```