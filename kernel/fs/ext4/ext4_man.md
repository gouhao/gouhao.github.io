
```man
MKE2FS(8)                                           System Manager's Manual                                           MKE2FS(8)

NAME
       mke2fs - create an ext2/ext3/ext4 filesystem

SYNOPSIS
       mke2fs [ -c | -l filename ] [ -b block-size ] [ -C cluster-size ] [ -d root-directory ] [ -D ] [ -g blocks-per-group ] [
       -G number-of-groups ] [ -i bytes-per-inode ] [ -I inode-size ] [ -j ] [ -J journal-options ] [ -N number-of-inodes  ]  [
       -n  ]  [ -m reserved-blocks-percentage ] [ -o creator-os ] [ -O [^]feature[,...]  ] [ -q ] [ -r fs-revision-level ] [ -E
       extended-options ] [ -v ] [ -F ] [ -L volume-label ] [ -M last-mounted-directory ] [ -S ] [ -t fs-type ] [ -T usage-type
       ] [ -U UUID ] [ -V ] [ -e errors-behavior ] [ -z undo_file ] device [ fs-size ]

       mke2fs -O journal_dev [ -b block-size ] [ -L volume-label ] [ -n ] [ -q ] [ -v ] external-journal [ fs-size ]

DESCRIPTION
	mke2fs被用来创建ext2/3/4文件系统，通常在由设备命名的磁盘分区（或文件）中。
	文件系统的大小由 fs-size 指定。如果 fs-size 没有后缀，它被解释为kb的幂，除非指定了 -b blocksize 选项，在这种情况下，fs-size 被卧解释为
	blocksize的数量块。如果 fs-size 以 k/m/g/t（无论大小写）作为后缀，它被解释为kb/mb/gb/tb的人次幂。如果 fs-size 被省略，mke2fs将根据设
	备大小创建文件系统。

	如果mke2fs以mkfs.XXX（例如：mkfs.ext2, mkfs.ext3, or mkfs.ext4），则隐含了选项 -t XXX；所以 mkfs.ext3 将创建一个用于ext3的文件系
	统，mkfs.ext4将创建一个用于ext4的文件，等等。

	新创建文件系统的默认参数，如果没有被下面列出的选项覆盖，由 /etc/mke2fs.conf 文件控制，有关详情，请参阅 mke2fs.conf(5) 手册页面。

OPTIONS
       -b block-size
              Specify  the size of blocks in bytes.  Valid block-size values are 1024, 2048 and 4096 bytes per block.  If omit‐
              ted, block-size is heuristically determined by the filesystem size and the expected usage of the filesystem  (see
              the -T option).  If block-size is preceded by a negative sign ('-'), then mke2fs will use heuristics to determine
              the appropriate block size, with the constraint that the block size will be at least block-size bytes.   This  is
              useful for certain hardware devices which require that the blocksize be a multiple of 2k.

       -c     Check  the  device  for  bad  blocks  before creating the file system.  If this option is specified twice, then a
              slower read-write test is used instead of a fast read-only test.

       -C  cluster-size
              Specify the size of cluster in bytes for filesystems using the bigalloc feature.  Valid cluster-size  values  are
              from  2048  to  256M bytes per cluster.  This can only be specified if the bigalloc feature is enabled.  (See the
              ext4 (5) man page for more details about bigalloc.)   The default cluster size if bigalloc is enabled is 16 times
              the block size.

       -d root-directory
              Copy the contents of the given directory into the root directory of the filesystem.

       -D     Use direct I/O when writing to the disk.  This avoids mke2fs dirtying a lot of buffer cache memory, which may im‐
              pact other applications running on a busy server.  This option will cause mke2fs to run much  more  slowly,  how‐
              ever, so there is a tradeoff to using direct I/O.

       -e error-behavior
              Change  the  behavior  of  the kernel code when errors are detected.  In all cases, a filesystem error will cause
              e2fsck(8) to check the filesystem on the next boot.  error-behavior can be one of the following:

                   continue    Continue normal execution.

                   remount-ro  Remount filesystem read-only.

                   panic       Cause a kernel panic.

       -E extended-options
              Set extended options for the filesystem.  Extended options are comma separated, and may take  an  argument  using
              the  equals  ('=')  sign.  The -E option used to be -R in earlier versions of mke2fs.  The -R option is still ac‐
              cepted for backwards compatibility, but is deprecated.  The following extended options are supported:

                   mmp_update_interval=interval
                          Adjust the initial MMP update interval to interval seconds.  Specifying an interval of 0 means to use
                          the  default  interval.  The specified interval must be less than 300 seconds.  Requires that the mmp
                          feature be enabled.

                   stride=stride-size
                          Configure the filesystem for a RAID array with stride-size filesystem blocks. This is the  number  of
                          blocks  read or written to disk before moving to the next disk, which is sometimes referred to as the
                          chunk size.  This mostly affects placement of filesystem metadata like  bitmaps  at  mke2fs  time  to
                          avoid  placing  them  on a single disk, which can hurt performance.  It may also be used by the block
                          allocator.

                   stripe_width=stripe-width
                          Configure the filesystem for a RAID array with stripe-width filesystem blocks  per  stripe.  This  is
                          typically  stride-size  * N, where N is the number of data-bearing disks in the RAID (e.g. for RAID 5
                          there is one parity disk, so N will be the number of disks in the array minus 1).   This  allows  the
                          block allocator to prevent read-modify-write of the parity in a RAID stripe if possible when the data
                          is written.

                   offset=offset
                          Create the filesystem at an offset from the beginning of the device or file.  This can be useful when
                          creating disk images for virtual machines.

                   resize=max-online-resize
                          Reserve  enough  space so that the block group descriptor table can grow to support a filesystem that
                          has max-online-resize blocks.

                   lazy_itable_init[= <0 to disable, 1 to enable>]
                          If enabled and the uninit_bg feature is enabled, the inode table will not  be  fully  initialized  by
                          mke2fs.   This  speeds  up filesystem initialization noticeably, but it requires the kernel to finish
                          initializing the filesystem in the background when the filesystem is first mounted.   If  the  option
                          value is omitted, it defaults to 1 to enable lazy inode table zeroing.

                   lazy_journal_init[= <0 to disable, 1 to enable>]
                          If enabled, the journal inode will not be fully zeroed out by mke2fs.  This speeds up filesystem ini‐
                          tialization noticeably, but carries some small risk if the system crashes before the journal has been
                          overwritten entirely one time.  If the option value is omitted, it defaults to 1 to enable lazy jour‐
                          nal inode zeroing.

                   no_copy_xattrs
                          Normally mke2fs will copy the extended attributes of the files in the directory  hierarchy  specified
                          via  the  (optional) -d option.  This will disable the copy and leaves the files in the newly created
                          file system without any extended attributes.

                   num_backup_sb=<0|1|2>
                          If the sparse_super2 file system feature is enabled this option controls whether there will be 0,  1,
                          or 2 backup superblocks created in the file system.

                   packed_meta_blocks[= <0 to disable, 1 to enable>]
                          Place  the allocation bitmaps and the inode table at the beginning of the disk.  This option requires
                          that the flex_bg file system feature to be enabled in order for it to have effect, and will also cre‐
                          ate  the  journal  at the beginning of the file system.  This option is useful for flash devices that
                          use SLC flash at the beginning of the disk.  It also maximizes the range of contiguous  data  blocks,
                          which can be useful for certain specialized use cases, such as supported Shingled Drives.

                   root_owner[=uid:gid]
                          Specify  the  numeric  user  and group ID of the root directory.  If no UID:GID is specified, use the
                          user and group ID of the user running mke2fs.  In mke2fs 1.42 and earlier the UID and GID of the root
                          directory  were  set  by  default  to  the  UID  and GID of the user running the mke2fs command.  The
                          root_owner= option allows explicitly specifying these values, and avoid side-effects for  users  that
                          do not expect the contents of the filesystem to change based on the user running mke2fs.

                   test_fs
                          Set  a  flag in the filesystem superblock indicating that it may be mounted using experimental kernel
                          code, such as the ext4dev filesystem.

                   discard
                          Attempt to discard blocks at mkfs time (discarding blocks initially is useful on solid state  devices
                          and sparse / thin-provisioned storage). When the device advertises that discard also zeroes data (any
                          subsequent read after the discard and before write returns zero), then mark all not-yet-zeroed  inode
                          tables as zeroed. This significantly speeds up filesystem initialization. This is set as default.

                   nodiscard
                          Do not attempt to discard blocks at mkfs time.

                   quotatype
                          Specify  the which  quota types (usrquota, grpquota, prjquota) which should be enabled in the created
                          file system.  The argument of this extended option should be a colon separated list.  This option has
                          effect  only  if the quota feature is set.   The default quota types to be initialized if this option
                          is not specified is both user and group quotas.  If the project feature is enabled that project  quo‐
                          tas will be initialized as well.

       -F     Force  mke2fs  to create a filesystem, even if the specified device is not a partition on a block special device,
              or if other parameters do not make sense.  In order to force mke2fs to create a filesystem even if the filesystem
              appears to be in use or is mounted (a truly dangerous thing to do), this option must be specified twice.

       -g blocks-per-group
              Specify the number of blocks in a block group.  There is generally no reason for the user to ever set this param‐
              eter, as the default is optimal for the filesystem.  (For administrators who are creating filesystems on RAID ar‐
              rays,  it  is  preferable  to use the stride RAID parameter as part of the -E option rather than manipulating the
              number of blocks per group.)  This option is generally used by developers who are developing test cases.

              If the bigalloc feature is enabled, the -g option will specify the number of clusters in a block group.

       -G number-of-groups
              Specify the number of block groups that will be packed together to  create  a  larger  virtual  block  group  (or
              "flex_bg  group")  in  an  ext4  filesystem.  This improves meta-data locality and performance on meta-data heavy
              workloads.  The number of groups must be a power of 2 and may only be specified if the flex_bg filesystem feature
              is enabled.

       -i bytes-per-inode
              Specify  the  bytes/inode  ratio.   mke2fs creates an inode for every bytes-per-inode bytes of space on the disk.
              The larger the bytes-per-inode ratio, the fewer inodes will  be  created.   This  value  generally  shouldn't  be
              smaller than the blocksize of the filesystem, since in that case more inodes would be made than can ever be used.
              Be warned that it is not possible to change this ratio on a filesystem after it is created, so be careful  decid‐
              ing  the correct value for this parameter.  Note that resizing a filesystem changes the number of inodes to main‐
              tain this ratio.

       -I inode-size
              Specify the size of each inode in bytes.  The inode-size value must be a power of 2 larger or equal to 128.   The
              larger  the  inode-size  the  more  space  the inode table will consume, and this reduces the usable space in the
              filesystem and can also negatively impact performance.  It is  not  possible  to  change  this  value  after  the
              filesystem is created.

              In kernels after 2.6.10 and some earlier vendor kernels it is possible to utilize inodes larger than 128 bytes to
              store extended attributes for improved performance.  Extended attributes stored in large inodes are  not  visible
              with older kernels, and such filesystems will not be mountable with 2.4 kernels at all.

              The default inode size is controlled by the mke2fs.conf(5) file.  In the mke2fs.conf file shipped with e2fsprogs,
              the default inode size is 256 bytes for most file systems, except for small file systems  where  the  inode  size
              will be 128 bytes.

       -j     Create  the  filesystem  with an ext3 journal.  If the -J option is not specified, the default journal parameters
              will be used to create an appropriately sized journal (given the  size  of  the  filesystem)  stored  within  the
              filesystem.   Note  that  you  must be using a kernel which has ext3 support in order to actually make use of the
              journal.

       -J journal-options
              Create the ext3 journal using options specified on the command-line.  Journal options are  comma  separated,  and
              may take an argument using the equals ('=')  sign.  The following journal options are supported:

                   size=journal-size
                          Create  an internal journal (i.e., stored inside the filesystem) of size journal-size megabytes.  The
                          size of the journal must be at least 1024 filesystem blocks (i.e., 1MB if using 1k blocks, 4MB if us‐
                          ing  4k  blocks,  etc.)   and may be no more than 10,240,000 filesystem blocks or half the total file
                          system size (whichever is smaller)

                   location=journal-location
                          Specify the location of the journal.  The argument journal-location can  either  be  specified  as  a
                          block  number,  or if the number has a units suffix (e.g., 'M', 'G', etc.) interpret it as the offset
                          from the beginning of the file system.

                   device=external-journal
                          Attach the filesystem to the journal block device located on external-journal.  The external  journal
                          must already have been created using the command

                          mke2fs -O journal_dev external-journal

                          Note that external-journal must have been created with the same block size as the new filesystem.  In
                          addition, while there is support for attaching multiple filesystems to a single external journal, the
                          Linux kernel and e2fsck(8) do not currently support shared external journals yet.

                          Instead  of  specifying  a device name directly, external-journal can also be specified by either LA‐
                          BEL=label or UUID=UUID to locate the external journal by either the volume label or  UUID  stored  in
                          the  ext2 superblock at the start of the journal.  Use dumpe2fs(8) to display a journal device's vol‐
                          ume label and UUID.  See also the -L option of tune2fs(8).

              Only one of the size or device options can be given for a filesystem.

       -l filename
              Read the bad blocks list from filename.  Note that the block numbers in the bad block list must be generated  us‐
              ing  the  same block size as used by mke2fs.  As a result, the -c option to mke2fs is a much simpler and less er‐
              ror-prone method of checking a disk for bad blocks before formatting it, as mke2fs will  automatically  pass  the
              correct parameters to the badblocks program.

       -L new-volume-label
              Set the volume label for the filesystem to new-volume-label.  The maximum length of the volume label is 16 bytes.

       -m reserved-blocks-percentage
              Specify  the percentage of the filesystem blocks reserved for the super-user.  This avoids fragmentation, and al‐
              lows root-owned daemons, such as syslogd(8), to continue to function correctly after non-privileged processes are
              prevented from writing to the filesystem.  The default percentage is 5%.

       -M last-mounted-directory
              Set  the  last mounted directory for the filesystem.  This might be useful for the sake of utilities that key off
              of the last mounted directory to determine where the filesystem should be mounted.

       -n     Causes mke2fs to not actually create a filesystem, but display what it would do if it were to create  a  filesys‐
              tem.   This  can be used to determine the location of the backup superblocks for a particular filesystem, so long
              as the mke2fs parameters that were passed when the filesystem was originally created are used again.   (With  the
              -n option added, of course!)

       -N number-of-inodes
              Overrides  the  default  calculation of the number of inodes that should be reserved for the filesystem (which is
              based on the number of blocks and the bytes-per-inode ratio).  This allows the user to specify the number of  de‐
              sired inodes directly.

       -o creator-os
              Overrides  the default value of the "creator operating system" field of the filesystem.  The creator field is set
              by default to the name of the OS the mke2fs executable was compiled for.

       -O [^]feature[,...]
              Create a filesystem with the given features (filesystem options), overriding the default filesystem options.  The
              features  that  are enabled by default are specified by the base_features relation, either in the [defaults] sec‐
              tion in the /etc/mke2fs.conf configuration file, or in the [fs_types] subsections for the usage types  as  speci‐
              fied  by  the  -T  option,  further modified by the features relation found in the [fs_types] subsections for the
              filesystem and usage types.  See the mke2fs.conf(5) manual page for more details.  The  filesystem  type-specific
              configuration setting found in the [fs_types] section will override the global default found in [defaults].

              The  filesystem  feature  set will be further edited using either the feature set specified by this option, or if
              this option is not given, by the default_features relation for the filesystem type being created, or in the  [de‐
              faults] section of the configuration file.

              The  filesystem  feature set is comprised of a list of features, separated by commas, that are to be enabled.  To
              disable a feature, simply prefix the feature name with a caret ('^') character.  Features with dependencies  will
              not be removed successfully.  The pseudo-filesystem feature "none" will clear all filesystem features.

       For more information about the features which can be set, please see
              the manual page ext4(5).

       -q     Quiet execution.  Useful if mke2fs is run in a script.

       -r revision
              Set  the  filesystem revision for the new filesystem.  Note that 1.2 kernels only support revision 0 filesystems.
              The default is to create revision 1 filesystems.

       -S     Write superblock and group descriptors only.  This is an extreme measure to be taken only in  the  very  unlikely
              case that all of the superblock and backup superblocks are corrupted, and a last-ditch recovery method is desired
              by experienced users.  It causes mke2fs to reinitialize the superblock and group descriptors, while not  touching
              the  inode table and the block and inode bitmaps.  The e2fsck program should be run immediately after this option
              is used, and there is no guarantee that any data will be salvageable.  Due to the wide variety  of  possible  op‐
              tions  to  mke2fs that affect the on-disk layout, it is critical to specify exactly the same format options, such
              as blocksize, fs-type, feature flags, and other tunables when using this option, or the filesystem will  be  fur‐
              ther  corrupted.   In  some cases, such as filesystems that have been resized, or have had features enabled after
              format time, it is impossible to overwrite all of the superblocks correctly, and at least some filesystem corrup‐
              tion  will  occur.  It is best to run this on a full copy of the filesystem so other options can be tried if this
              doesn't work.

       -t fs-type
              Specify the filesystem type (i.e., ext2, ext3, ext4, etc.) that is to be created.  If this option is  not  speci‐
              fied,  mke2fs  will  pick  a  default  either  via how the command was run (for example, using a name of the form
              mkfs.ext2, mkfs.ext3, etc.) or via a default as defined by the  /etc/mke2fs.conf  file.    This  option  controls
              which filesystem options are used by default, based on the fstypes configuration stanza in /etc/mke2fs.conf.

              If  the  -O option is used to explicitly add or remove filesystem options that should be set in the newly created
              filesystem, the resulting filesystem may not be supported by the requested fs-type.  (e.g., "mke2fs  -t  ext3  -O
              extent /dev/sdXX" will create a filesystem that is not supported by the ext3 implementation as found in the Linux
              kernel; and "mke2fs -t ext3 -O ^has_journal /dev/hdXX" will create a filesystem that does not have a journal  and
              hence will not be supported by the ext3 filesystem code in the Linux kernel.)

       -T usage-type[,...]
              Specify  how the filesystem is going to be used, so that mke2fs can choose optimal filesystem parameters for that
              use.  The usage types that are supported are defined in the configuration file /etc/mke2fs.conf.   The  user  may
              specify one or more usage types using a comma separated list.

              If  this  option  is  is  not  specified,  mke2fs  will pick a single default usage type based on the size of the
              filesystem to be created.  If the filesystem size is less than 3 megabytes, mke2fs will use the  filesystem  type
              floppy.  If the filesystem size is greater than or equal to 3 but less than 512 megabytes, mke2fs(8) will use the
              filesystem type small.  If the filesystem size is greater than or equal to 4 terabytes  but  less  than  16  ter‐
              abytes,  mke2fs(8)  will use the filesystem type big.  If the filesystem size is greater than or equal to 16 ter‐
              abytes, mke2fs(8) will use the filesystem type huge.  Otherwise, mke2fs(8) will use the default  filesystem  type
              default.

       -U UUID
              Set  the  universally  unique identifier (UUID) of the filesystem to UUID.  The format of the UUID is a series of
              hex digits separated by hyphens, like this: "c1b9d5a2-f162-11cf-9ece-0020afc76f16".  The UUID parameter may  also
              be one of the following:

                   clear  clear the filesystem UUID

                   random generate a new randomly-generated UUID

                   time   generate a new time-based UUID

       -v     Verbose execution.

       -V     Print the version number of mke2fs and exit.

       -z undo_file
              Before  overwriting a file system block, write the old contents of the block to an undo file.  This undo file can
              be used with e2undo(8) to restore the old contents of the file system should something go wrong.   If  the  empty
              string is passed as the undo_file argument, the undo file will be written to a file named mke2fs-device.e2undo in
              the directory specified via the E2FSPROGS_UNDO_DIR environment variable or the undo_dir directive in the configu‐
              ration file.

              WARNING: The undo file cannot be used to recover from a power or system crash.

ENVIRONMENT
       MKE2FS_SYNC
              If  set  to non-zero integer value, its value is used to determine how often sync(2) is called during inode table
              initialization.

       MKE2FS_CONFIG
              Determines the location of the configuration file (see mke2fs.conf(5)).

       MKE2FS_FIRST_META_BG
              If set to non-zero integer value, its value is used to determine first meta block group. This is mostly  for  de‐
              bugging purposes.

       MKE2FS_DEVICE_SECTSIZE
              If set to non-zero integer value, its value is used to determine logical sector size of the device.

       MKE2FS_DEVICE_PHYS_SECTSIZE
              If set to non-zero integer value, its value is used to determine physical sector size of the device.

       MKE2FS_SKIP_CHECK_MSG
              If set, do not show the message of filesystem automatic check caused by mount count or check interval.

AUTHOR
       这个版本的mke2fs是由 Theodore Ts'o <tytso@mit.edu> 编写。

AVAILABILITY
       mke2fs是e2fsprogs软件包的一部分，可从 http://e2fsprogs.sourceforge.net 获取。

SEE ALSO
       mke2fs.conf(5), badblocks(8), dumpe2fs(8), e2fsck(8), tune2fs(8), ext4(5)

E2fsprogs version 1.44.5                                 December 2018                                                MKE2FS(8)

```

```
mke2fs.conf(5)                                        File Formats Manual                                        mke2fs.conf(5)

NAME
       mke2fs.conf - Configuration file for mke2fs

DESCRIPTION
       mke2fs.conf  is  the  configuration file for mke2fs(8).  It controls the default parameters used by mke2fs(8) when it is
       creating ext2, ext3, or ext4 filesystems.

       The mke2fs.conf file uses an INI-style format.  Stanzas, or top-level sections, are delimited by  square  braces:  [  ].
       Within each section, each line defines a relation, which assigns tags to values, or to a subsection, which contains fur‐
       ther relations or subsections.  An example of the INI-style format used by this configuration file follows below:

            [section1]
                 tag1 = value_a
                 tag1 = value_b
                 tag2 = value_c

            [section 2]
                 tag3 = {
                      subtag1 = subtag_value_a
                      subtag1 = subtag_value_b
                      subtag2 = subtag_value_c
                 }
                 tag1 = value_d
                 tag2 = value_e
            }

       Comments are delimited by a semicolon (';') or a hash ('#') character at the beginning of the comment,  and  are  termi‐
       nated by the end of line character.

       Tags  and  values must be quoted using double quotes if they contain spaces.  Within a quoted string, the standard back‐
       slash interpretations apply: "\n" (for the newline character), "\t" (for the tab character),  "\b"  (for  the  backspace
       character), and "\\" (for the backslash character).

       Some  relations  expect  a  boolean  value.  The parser is quite liberal on recognizing ``yes'', '`y'', ``true'', ``t'',
       ``1'', ``on'', etc. as a boolean true value, and ``no'', ``n'', ``false'', ``nil'', ``0'', ``off'' as  a  boolean  false
       value.

       The  following  stanzas  are  used in the mke2fs.conf file.  They will be described in more detail in future sections of
       this document.

       [options]
              Contains relations which influence how mke2fs behaves.

       [defaults]
              Contains relations which define the default parameters used by mke2fs(8).  In  general,  these  defaults  may  be
              overridden by a definition in the fs_types stanza, or by a command-line option provided by the user.

       [fs_types]
              Contains  relations which define defaults that should be used for specific file system and usage types.  The file
              system type and usage type can be specified explicitly using the -tand-T options to mke2fs(8), respectively.

       [devices]
              Contains relations which define defaults for specific devices.

THE [options] STANZA
       The following relations are defined in the [options] stanza.

       proceed_delay
              If this relation is set to a positive integer, then mke2fs will wait proceed_delay seconds after asking the  user
              for  permission  to  proceed  and  then continue, even if the user has not answered the question.  Defaults to 0,
              which means to wait until the user answers the question one way or another.

       sync_kludge
              If this relation is set to a positive integer, then while writing the inode table, mke2fs will request the  oper‐
              ating  system  flush  out  pending writes to initialize the inode table every sync_kludge block groups.   This is
              needed to work around buggy kernels that don't handle writeback throttling correctly.

THE [defaults] STANZA
       The following relations are defined in the [defaults] stanza.

       fs_type
              This relation specifies the default filesystem type if the user does not specify it via  the  -t  option,  or  if
              mke2fs  is  not started using a program name of the form mkfs.fs-type.  If both the user and the mke2fs.conf file
              do not specify a default filesystem type, mke2fs will use a default filesystem type of ext3 if a journal was  re‐
              quested via a command-line option, or ext2 if not.

       undo_dir
              This  relation  specifies  the  directory  where  the  undo  file should be stored.  It can be overridden via the
              E2FSPROGS_UNDO_DIR environment variable.  If the directory location is set to the value  none,  mke2fs  will  not
              create an undo file.

       In  addition,  any  tags  that  can be specified in a per-file system tags subsection as defined below (e.g., blocksize,
       hash_alg, inode_ratio, inode_size, reserved_ratio, etc.) can also be specified in the defaults stanza to specify the de‐
       fault value to be used if the user does not specify one on the command line, and the filesystem-type specific section of
       the configuration file does not specify a default value.

THE [fs_types] STANZA
       Each tag in the [fs_types] stanza names a filesystem type or usage type which can be specified via the -t or -T  options
       to mke2fs(8), respectively.

       The  mke2fs program constructs a list of fs_types by concatenating the filesystem type (i.e., ext2, ext3, etc.) with the
       usage type list.  For most configuration options, mke2fs will look for a subsection in the [fs_types] stanza correspond‐
       ing with each entry in the constructed list, with later entries overriding earlier filesystem or usage types.  For exam‐
       ple, consider the following mke2fs.conf fragment:

       [defaults]
            base_features = sparse_super,filetype,resize_inode,dir_index
            blocksize = 4096
            inode_size = 256
            inode_ratio = 16384

       [fs_types]
            ext3 = {
                 features = has_journal
            }
            ext4 = {
                 features = extents,flex_bg
                 inode_size = 256
            }
            small = {
                 blocksize = 1024
                 inode_ratio = 4096
            }
            floppy = {
                 features = ^resize_inode
                 blocksize = 1024
                 inode_size = 128
            }

       If mke2fs started with a program name of mke2fs.ext4, then the filesystem type of ext4 will be used.  If the  filesystem
       is  smaller than 3 megabytes, and no usage type is specified, then mke2fs will use a default usage type of floppy.  This
       results in an fs_types list of "ext4, floppy".   Both the ext4 subsection and the floppy subsection define an inode_size
       relation,  but  since  the  later  entries  in the fs_types list supersede earlier ones, the configuration parameter for
       fs_types.floppy.inode_size will be used, so the filesystem  will have an inode size of 128.

       The exception to this resolution is the features tag, which specifies a set of changes  to  the  features  used  by  the
       filesystem,  and  which is cumulative.  So in the above example, first the configuration relation defaults.base_features
       would enable an initial feature set with the sparse_super, filetype, resize_inode, and dir_index features enabled.  Then
       configuration  relation fs_types.ext4.features would enable the extents and flex_bg features, and finally the configura‐
       tion relation fs_types.floppy.features would remove the resize_inode feature, resulting in a filesystem feature set con‐
       sisting of the sparse_super, filetype, dir_index, extents_and flex_bg features.

       For  each filesystem type, the following tags may be used in that fs_type's subsection.   These tags may also be used in
       the default section:

       base_features
              This relation specifies the features which are initially enabled for this filesystem type.   Only  one  base_fea‐
              tures  will be used, so if there are multiple entries in the fs_types list whose subsections define the base_fea‐
              tures relation, only the last will be used by mke2fs(8).

       enable_periodic_fsck
              This boolean relation specifies whether periodic filesystem checks should be enforced at boot time.   If  set  to
              true,  checks  will  be  forced  every 180 days, or after a random number of mounts.  These values may be changed
              later via the -i and -c command-line options to tune2fs(8).

       errors Change the behavior of the kernel code when errors are detected.  In all cases, a  filesystem  error  will  cause
              e2fsck(8) to check the filesystem on the next boot.  errors can be one of the following:

                   continue    Continue normal execution.

                   remount-ro  Remount filesystem read-only.

                   panic       Cause a kernel panic.

       features
              This relation specifies a comma-separated list of features edit requests which modify the feature set used by the
              newly constructed filesystem.  The syntax is the same as the -O command-line option to mke2fs(8); that is, a fea‐
              ture  can be prefixed by a caret ('^') symbol to disable a named feature.  Each feature relation specified in the
              fs_types list will be applied in the order found in the fs_types list.

       force_undo
              This boolean relation, if set to a value of true, forces mke2fs to always try to create an undo file, even if the
              undo file might be huge and it might extend the time to create the filesystem image because the inode table isn't
              being initialized lazily.

       default_features
              This relation specifies set of features which should be enabled or disabled after applying the features listed in
              the base_features and features relations.  It may be overridden by the -O command-line option to mke2fs(8).

       auto_64-bit_support
              This  relation  is  a boolean which specifies whether mke2fs(8) should automatically add the 64bit feature if the
              number of blocks for the file system requires this feature to be enabled.  The resize_inode feature is also auto‐
              matically disabled since it doesn't support 64-bit block numbers.

       default_mntopts
              This  relation  specifies the set of mount options which should be enabled by default.  These may be changed at a
              later time with the -o command-line option to tune2fs(8).

       blocksize
              This relation specifies the default blocksize if the user does not specify a blocksize on the command line.

       lazy_itable_init
              This boolean relation specifies whether the inode table should be lazily initialized.  It only has meaning if the
              uninit_bg feature is enabled.  If lazy_itable_init is true and the uninit_bg feature is enabled,  the inode table
              will not be fully initialized by mke2fs(8).  This speeds up filesystem initialization noticeably, but it requires
              the kernel to finish initializing the filesystem in the background when the filesystem is first mounted.

       lazy_journal_init
              This  boolean  relation  specifies whether the journal inode should be lazily initialized. It only has meaning if
              the has_journal feature is enabled. If lazy_journal_init is true, the journal inode will not be fully zeroed  out
              by  mke2fs.   This  speeds  up  filesystem  initialization  noticeably, but carries some small risk if the system
              crashes before the journal has been overwritten entirely one time.

       journal_location
              This relation specifies the location of the journal.

       num_backup_sb
              This relation indicates whether file systems with the sparse_super2 feature enabled should be created with 0,  1,
              or 2 backup superblocks.

       packed_meta_blocks
              This boolean relation specifies whether the allocation bitmaps, inode table, and journal should be located at the
              beginning of the file system.

       inode_ratio
              This relation specifies the default inode ratio if the user does not specify one on the command line.

       inode_size
              This relation specifies the default inode size if the user does not specify one on the command line.

       reserved_ratio
              This relation specifies the default percentage of filesystem blocks reserved for the super-user, if the user does
              not specify one on the command line.

       hash_alg
              This  relation  specifies the default hash algorithm used for the new filesystems with hashed b-tree directories.
              Valid algorithms accepted are: legacy, half_md4, and tea.

       flex_bg_size
              This relation specifies the number of block groups that will be packed together to create one large virtual block
              group on an ext4 filesystem.  This improves meta-data locality and performance on meta-data heavy workloads.  The
              number of groups must be a power of 2 and may only be specified if the flex_bg filesystem feature is enabled.

       options
              This relation specifies additional extended options which  should  be  treated  by  mke2fs(8)  as  if  they  were
              prepended  to  the argument of the -E option.  This can be used to configure the default extended options used by
              mke2fs(8) on a per-filesystem type basis.

       discard
              This boolean relation specifies whether the mke2fs(8) should attempt to discard device prior to  filesystem  cre‐
              ation.

       cluster_size
              This relation specifies the default cluster size if the bigalloc file system feature is enabled.  It can be over‐
              ridden via the -C command line option to mke2fs(8)

       make_hugefiles
              This boolean relation enables the creation of pre-allocated files as part of formatting the file system.  The ex‐
              tent  tree  blocks for these pre-allocated files will be placed near the beginning of the file system, so that if
              all of the other metadata blocks are also configured to be placed near the beginning of the file system (by  dis‐
              abling  the  backup superblocks, using the packed_meta_blocks option, etc.), the data blocks of the pre-allocated
              files will be contiguous.

       hugefiles_dir
              This relation specifies the directory where huge files are created, relative to the filesystem root.

       hugefiles_uid
              This relation controls the user ownership for all of the files and directories created by the make_hugefiles fea‐
              ture.

       hugefiles_gid
              This  relation  controls  the  group ownership for all of the files and directories created by the make_hugefiles
              feature.

       hugefiles_umask
              This relation specifies the umask used when creating the files and directories by the make_hugefiles feature.

       num_hugefiles
              This relation specifies the number of huge files to be created.  If this relation is not specified, or is set  to
              zero,  and the hugefiles_size relation is non-zero, then make_hugefiles will create as many huge files as can fit
              to fill the entire file system.

       hugefiles_slack
              This relation specifies how much space should be reserved for other files.

       hugefiles_size
              This relation specifies the size of the huge files.  If this relation is not specified, the default  is  to  fill
              the entire file system.

       hugefiles_align
              This  relation  specifies  the  alignment for the start block of the huge files.  It also forces the size of huge
              files to be a multiple of the requested alignment.  If this relation is not specified, no  alignment  requirement
              will be imposed on the huge files.

       hugefiles_align_disk
              This  relations  specifies  whether the alignment should be relative to the beginning of the hard drive (assuming
              that the starting offset of the partition is available to mke2fs).  The default value is false, which will  cause
              hugefile alignment to be relative to the beginning of the file system.

       hugefiles_name
              This relation specifies the base file name for the huge files.

       hugefiles_digits
              This relation specifies the (zero-padded) width of the field for the huge file number.

       zero_hugefiles
              This  boolean  relation  specifies whether or not zero blocks will be written to the hugefiles while mke2fs(8) is
              creating them.  By default, zero blocks will be written to the huge files to avoid stale  data  from  being  made
              available  to potentially untrusted user programs, unless the device supports a discard/trim operation which will
              take care of zeroing the device blocks.  By setting zero_hugefiles to false, this step will  always  be  skipped,
              which  can  be  useful if it is known that the disk has been previously erased, or if the user programs that will
              have access to the huge files are trusted to not reveal stale data.

THE [devices] STANZA
       Each tag in the [devices] stanza names device name so that per-device defaults can be specified.

       fs_type
              This relation specifies the default parameter for the -t option, if this option isn't specified  on  the  command
              line.

       usage_types
              This  relation  specifies  the default parameter for the -T option, if this option isn't specified on the command
              line.

FILES
       /etc/mke2fs.conf
              The configuration file for mke2fs(8).

SEE ALSO
       mke2fs(8)

E2fsprogs version 1.44.5                                 December 2018                                           mke2fs.conf(5)

```