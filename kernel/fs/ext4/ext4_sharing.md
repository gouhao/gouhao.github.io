# ext4文件系统应用及调试

## 1. ext简史
以下内容来自: [https://zhuanlan.zhihu.com/p/44267768](https://zhuanlan.zhihu.com/p/44267768)

### 1.1 MINIX 文件系统
在有 ext 之前，使用的是 MINIX 文件系统。MINIX 是用于 IBM PC/AT 微型计算机的一个非常小的类 Unix 系统。Andrew Tannenbaum 为了教学的目的而开发了它，并于 1987 年发布了源代码（以印刷版的格式！）。

虽然你可以细读 MINIX 的源代码，但实际上它并不是自由开源软件（FOSS）。出版 Tannebaum 著作的出版商要求你花 69 美元的许可费来运行 MINIX，而这笔费用包含在书籍的费用中。尽管如此，在那时来说非常便宜，并且 MINIX 的使用得到迅速发展，很快超过了 Tannebaum 当初使用它来教授操作系统编码的意图。在整个 20 世纪 90 年代，你可以发现 MINIX 的安装在世界各个大学里面非常流行。而此时，年轻的 Linus Torvalds 使用 MINIX 来开发原始 Linux 内核，并于 1991 年首次公布，而后在 1992 年 12 月在 GPL 开源协议下发布。

MINIX 有自己的文件系统，早期的 Linux 版本依赖于它。跟 MINIX 一样，Linux 的文件系统也如同玩具那般小 —— MINIX 文件系统最多能处理 14 个字符的文件名，并且只能处理 64MB 的存储空间。到了 1991 年，一般的硬盘尺寸已经达到了 40-140 MB。很显然，Linux 需要一个更好的文件系统。

### 1.2 ext
当 Linus 开发出刚起步的 Linux 内核时，Rémy Card 从事第一代的 ext 文件系统的开发工作。ext 文件系统在 1992 年首次实现并发布 —— 仅在 Linux 首次发布后的一年！—— ext 解决了 MINIX 文件系统中最糟糕的问题。

1992年的ext使用在 Linux 内核中的新虚拟文件系统（VFS）抽象层。与之前的 MINIX 文件系统不同的是，ext 可以处理高达 2 GB 存储空间并处理 255 个字符的文件名。

但 ext 并没有长时间占统治地位，主要是由于它原始的时间戳（每个文件仅有一个时间戳，而不是今天我们所熟悉的有 inode、最近文件访问时间和最新文件修改时间的时间戳。）仅仅一年后，ext2 就替代了它。

### 1.3 ext2
Rémy 很快就意识到 ext 的局限性，所以一年后他设计出 ext2 替代它。当 ext 仍然根植于 “玩具” 操作系统时，ext2 从一开始就被设计为一个商业级文件系统，沿用 BSD 的 Berkeley 文件系统的设计原理。

ext2 提供了 GB 级别的最大文件大小和 TB 级别的文件系统大小，使其在 20 世纪 90 年代的地位牢牢巩固在文件系统大联盟中。很快它被广泛地使用，无论是在 Linux 内核中还是最终在 MINIX 中，且利用第三方模块可以使其应用于 MacOS 和 Windows。

但这里仍然有一些问题需要解决：ext2 文件系统与 20 世纪 90 年代的大多数文件系统一样，如果在将数据写入到磁盘的时候，系统发生崩溃或断电，则容易发生灾难性的数据损坏。随着时间的推移，由于碎片（单个文件存储在多个位置，物理上其分散在旋转的磁盘上），它们也遭受了严重的性能损失。

尽管存在这些问题，但今天 ext2 还是用在某些特殊的情况下 —— 最常见的是，作为便携式 USB 驱动器的文件系统格式。

### 1.3 ext3
1998 年，在 ext2 被采用后的 6 年后，Stephen Tweedie 宣布他正在致力于改进 ext2。这成了 ext3，并于 2001 年 11 月在 2.4.15 内核版本中被采用到 Linux 内核主线中。

在大部分情况下，ext2 在 Linux 发行版中工作得很好，但像 FAT、FAT32、HFS 和当时的其它文件系统一样 —— 在断电时容易发生灾难性的破坏。如果在将数据写入文件系统时候发生断电，则可能会将其留在所谓 不一致 的状态 —— 事情只完成一半而另一半未完成。这可能导致大量文件丢失或损坏，这些文件与正在保存的文件无关甚至导致整个文件系统无法卸载。

ext3 和 20 世纪 90 年代后期的其它文件系统，如微软的 NTFS，使用 日志 来解决这个问题。日志是磁盘上的一种特殊的分配区域，其写入被存储在事务中；如果该事务完成磁盘写入，则日志中的数据将提交给文件系统自身。如果系统在该操作提交前崩溃，则重新启动的系统识别其为未完成的事务而将其进行回滚，就像从未发生过一样。这意味着正在处理的文件可能依然会丢失，但文件系统 本身 保持一致，且其它所有数据都是安全的。

在使用 ext3 文件系统的 Linux 内核中实现了三个级别的日志记录方式： 日记(journal)、 顺序(ordered)和 回写(writeback)。

日记 是最低风险模式，在将数据和元数据提交给文件系统之前将其写入日志。这可以保证正在写入的文件与整个文件系统的一致性，但其显著降低了性能。  
顺序 是大多数 Linux 发行版默认模式；顺序模式将元数据写入日志而直接将数据提交到文件系统。顾名思义，这里的操作顺序是固定的：首先，元数据提交到日志；其次，数据写入文件系统，然后才将日志中关联的元数据更新到文件系统。这确保了在发生崩溃时，那些与未完整写入相关联的元数据仍在日志中，且文件系统可以在回滚日志时清理那些不完整的写入事务。在顺序模式下，系统崩溃可能导致在崩溃期间文件的错误被主动写入，但文件系统它本身 —— 以及未被主动写入的文件 —— 确保是安全的。  
回写 是第三种模式 —— 也是最不安全的日志模式。在回写模式下，像顺序模式一样，元数据会被记录到日志，但数据不会。与顺序模式不同，元数据和数据都可以以任何有利于获得最佳性能的顺序写入。这可以显著提高性能，但安全性低很多。尽管回写模式仍然保证文件系统本身的安全性，但在崩溃或崩溃之前写入的文件很容易丢失或损坏。  
跟之前的 ext2 类似，ext3 使用 16 位内部寻址。这意味着对于有着 4K 块大小的 ext3 在最大规格为 16 TiB 的文件系统中可以处理的最大文件大小为 2 TiB。

### 1.4 ext4
Theodore Ts'o（是当时 ext3 主要开发人员）在 2006 年发表的 ext4，于两年后在 2.6.28 内核版本中被加入到了 Linux 主线。

Ts'o 将 ext4 描述为一个显著扩展 ext3 但仍然依赖于旧技术的临时技术。他预计 ext4 终将会被真正的下一代文件系统所取代。  
ext4 在功能上与 ext3 在功能上非常相似，但支持大文件系统，提高了对碎片的抵抗力，有更高的性能以及更好的时间戳。


### 1.5 ext4 vs ext3
ext3 和 ext4 有一些非常明确的差别，在这里集中讨论下。

1. 向后兼容性  
ext4 特地设计为尽可能地向后兼容 ext3。这不仅允许 ext3 文件系统原地升级到 ext4；也允许 ext4 驱动程序以 ext3 模式自动挂载 ext3 文件系统，因此使它无需单独维护两个代码库。

2. 大文件系统  
ext3 文件系统使用 32 位寻址，这限制它仅支持 2 TiB 文件大小和 16 TiB 文件系统系统大小（这是假设在块大小为 4 KiB 的情况下，一些 ext3 文件系统使用更小的块大小，因此对其进一步被限制）。

ext4 使用 48 位的内部寻址，理论上可以在文件系统上分配高达 16 TiB 大小的文件，其中文件系统大小最高可达 1000000 TiB（1 EiB）。在早期 ext4 的实现中有些用户空间的程序仍然将其限制为最大大小为 16 TiB 的文件系统，但截至 2011 年，e2fsprogs 已经直接支持大于 16 TiB 大小的 ext4 文件系统。例如，红帽企业 Linux 在其合同上仅支持最高 50 TiB 的 ext4 文件系统，并建议 ext4 卷不超过 100 TiB。

3. 分配方式改进  
ext4 在将存储块写入磁盘之前对存储块的分配方式进行了大量改进，这可以显著提高读写性能。

区段(extent)是一系列连续的物理块 (最多达 128 MiB，假设块大小为 4 KiB），可以一次性保留和寻址。使用区段可以减少给定文件所需的 inode 数量，并显著减少碎片并提高写入大文件时的性能。

4. 多块分配  
ext3 为每一个新分配的块调用一次块分配器。当多个写入同时打开分配器时，很容易导致严重的碎片。然而，ext4 使用延迟分配，这允许它合并写入并更好地决定如何为尚未提交的写入分配块。

5. 持久的预分配  
在为文件预分配磁盘空间时，大部分文件系统必须在创建时将零写入该文件的块中。ext4 允许替代使用 fallocate()，它保证了空间的可用性（并试图为它找到连续的空间），而不需要先写入它。这显著提高了写入和将来读取流和数据库应用程序的写入数据的性能。

6. 延迟分配  
这是一个耐人寻味而有争议性的功能。延迟分配允许 ext4 等待分配将写入数据的实际块，直到它准备好将数据提交到磁盘。（相比之下，即使数据仍然在往写入缓存中写入，ext3 也会立即分配块。）

当缓存中的数据累积时，延迟分配块允许文件系统对如何分配块做出更好的选择，降低碎片（写入，以及稍后的读）并显著提升性能。然而不幸的是，它 增加 了还没有专门调用 fsync() 方法（当程序员想确保数据完全刷新到磁盘时）的程序的数据丢失的可能性。

假设一个程序完全重写了一个文件：

fd=open("file", O_TRUNC); write(fd, data); close(fd);
使用旧的文件系统，close(fd); 足以保证 file 中的内容刷新到磁盘。即使严格来说，写不是事务性的，但如果文件关闭后发生崩溃，则丢失数据的风险很小。

如果写入不成功（由于程序上的错误、磁盘上的错误、断电等），文件的原始版本和较新版本都可能丢失数据或损坏。如果其它进程在写入文件时访问文件，则会看到损坏的版本。如果其它进程打开文件并且不希望其内容发生更改 —— 例如，映射到多个正在运行的程序的共享库。这些进程可能会崩溃。

为了避免这些问题，一些程序员完全避免使用 O_TRUNC。相反，他们可能会写入一个新文件，关闭它，然后将其重命名为旧文件名：

fd=open("newfile"); write(fd, data); close(fd); rename("newfile", "file");
在 没有 延迟分配的文件系统下，这足以避免上面列出的潜在的损坏和崩溃问题：因为 rename() 是原子操作，所以它不会被崩溃中断；并且运行的程序将继续引用旧的文件。现在 file 的未链接版本只要有一个打开的文件文件句柄即可。但是因为 ext4 的延迟分配会导致写入被延迟和重新排序，rename("newfile", "file") 可以在 newfile 的内容实际写入磁盘内容之前执行，这出现了并行进行再次获得 file 坏版本的问题。

为了缓解这种情况，Linux 内核（自版本 2.6.30）尝试检测这些常见代码情况并强制立即分配。这会减少但不能防止数据丢失的可能性 —— 并且它对新文件没有任何帮助。如果你是一位开发人员，请注意：保证数据立即写入磁盘的唯一方法是正确调用 fsync()。

8. 无限制的子目录
ext3 仅限于 32000 个子目录；ext4 允许无限数量的子目录。从 2.6.23 内核版本开始，ext4 使用 HTree 索引来减少大量子目录的性能损失。

9. 日志校验
ext3 没有对日志进行校验，这给处于内核直接控制之外的磁盘或自带缓存的控制器设备带来了问题。如果控制器或具自带缓存的磁盘脱离了写入顺序，则可能会破坏 ext3 的日记事务顺序，从而可能破坏在崩溃期间（或之前一段时间）写入的文件。

理论上，这个问题可以使用写入 障碍(barrier) —— 在安装文件系统时，你在挂载选项设置 barrier=1，然后设备就会忠实地执行 fsync 一直向下到底层硬件。通过实践，可以发现存储设备和控制器经常不遵守写入障碍 —— 提高性能（和跟竞争对手比较的性能基准），但增加了本应该防止数据损坏的可能性。

对日志进行校验和允许文件系统崩溃后第一次挂载时意识到其某些条目是无效或无序的。因此，这避免了回滚部分条目或无序日志条目的错误，并进一步损坏的文件系统 —— 即使部分存储设备假做或不遵守写入障碍。

10. 快速文件系统检查
在 ext3 下，在 fsck 被调用时会检查整个文件系统 —— 包括已删除或空文件。相比之下，ext4 标记了 inode 表未分配的块和扇区，从而允许 fsck 完全跳过它们。这大大减少了在大多数文件系统上运行 fsck 的时间，它实现于内核 2.6.24。

11. 改进的时间戳
ext3 提供粒度为一秒的时间戳。虽然足以满足大多数用途，但任务关键型应用程序经常需要更严格的时间控制。ext4 通过提供纳秒级的时间戳，使其可用于那些企业、科学以及任务关键型的应用程序。

ext3 文件系统也没有提供足够的位来存储 2038 年 1 月 18 日以后的日期。ext4 在这里增加了两个位，将 Unix 纪元扩展了 408 年。如果你在公元 2446 年读到这篇文章，你很有可能已经转移到一个更好的文件系统 —— 如果你还在测量自 1970 年 1 月 1 日 00:00（UTC）以来的时间，这会让我死后得以安眠。

12. 在线碎片整理
ext2 和 ext3 都不直接支持在线碎片整理 —— 即在挂载时会对文件系统进行碎片整理。ext2 有一个包含的实用程序 e2defrag，它的名字暗示 —— 它需要在文件系统未挂载时脱机运行。（显然，这对于根文件系统来说非常有问题。）在 ext3 中的情况甚至更糟糕 —— 虽然 ext3 比 ext2 更不容易受到严重碎片的影响，但 ext3 文件系统运行 e2defrag 可能会导致灾难性损坏和数据丢失。

尽管 ext3 最初被认为“不受碎片影响”，但对同一文件（例如 BitTorrent）采用大规模并行写入过程的过程清楚地表明情况并非完全如此。一些用户空间的手段和解决方法，例如 Shake，以这样或那样方式解决了这个问题 —— 但它们比真正的、文件系统感知的、内核级碎片整理过程更慢并且在各方面都不太令人满意。

ext4 通过 e4defrag 解决了这个问题，且是一个在线、内核模式、文件系统感知、块和区段级别的碎片整理实用程序。

13. 元数据校验和
由于 ext4 具有冗余超级块，因此为文件系统校验其中的元数据提供了一种方法，可以自行确定主超级块是否已损坏并需要使用备用块。可以在没有校验和的情况下，从损坏的超级块恢复 —— 但是用户首先需要意识到它已损坏，然后尝试使用备用方法手动挂载文件系统。由于在某些情况下，使用损坏的主超级块安装文件系统读写可能会造成进一步的损坏，即使是经验丰富的用户也无法避免，这也不是一个完美的解决方案！

与 Btrfs 或 ZFS 等下一代文件系统提供的极其强大的每块校验和相比，ext4 的元数据校验和的功能非常弱。但它总比没有好。虽然校验 所有的事情 都听起来很简单！—— 事实上，将校验和与文件系统连接到一起有一些重大的挑战；请参阅设计文档了解详细信息。

14. 一流的配额支持
等等，配额？！从 ext2 出现的那天开始我们就有了这些！是的，但它们一直都是事后的添加的东西，而且它们总是犯傻。这里可能不值得详细介绍，但设计文档列出了配额将从用户空间移动到内核中的方式，并且能够更加正确和高效地执行。

15. 大分配块
随着时间的推移，那些讨厌的存储系统不断变得越来越大。由于一些固态硬盘已经使用 8K 硬件块大小，因此 ext4 对 4K 模块的当前限制越来越受到限制。较大的存储块可以显著减少碎片并提高性能，代价是增加“松弛”空间（当你只需要块的一部分来存储文件或文件的最后一块时留下的空间）。

你可以在[设计文档](https://ext4.wiki.kernel.org/index.php/Design_for_Large_Allocation_Blocks)中查看详细说明。

## 2. 磁盘布局
ext4fs将磁盘分成一个个块组(block group)，如下：
|group0|group1|group2|group3|....|
|---|---|---|---|---|
分成块组的原因：
|boot block|super block|group descriptors|reverse GDT blocks|block bitmap|inode bitmap|inode table|data blocks|
|---|---|---|---|---|---|---|---|
|1 block|1 block|many blocks|many blocks|1 block|1 block|many blocks|many blocks|

## 2.1 目录组织形式
```c
struct ext4_dir_entry_2 {
	__le32	inode;			/* inode号 */
	__le16	rec_len;		/* entry长度 */
	__u8	name_len;		/* 文件长度 */
	__u8	file_type;		/* 文件类型 */
	char	name[EXT4_NAME_LEN];	/* 文件名 */
};
每个目录文件里的数据存储的是`struct ext4_dir_entry_2`结构，在搜索时按照文件名比对，然后找到对应文件的inode。

为了加速文件查找，ext4引入了新特性，把目录的形式组织成了哈希表，key是具体文件名的哈希值，value是对应的数据块。

```

## 2.2 数据块的组织形式
具体文件数据采用extent形式组织。数据结构上采用b+树来存储，根结点存在`struct ext4_inode_info->i_data`里。  
叶子节点存储具体的extent数据，数据结构为`struct ext4_extent`。中间的节点为索引节点，数据结构为`struct ext4_extent_idx`。  
每个索引或extent树的开头是`struct ext4_extent_header`，示例图：[https://blog.csdn.net/hu1610552336/article/details/128509011](https://blog.csdn.net/hu1610552336/article/details/128509011)。

```c
struct ext4_extent_header {
	__le16	eh_magic;	/* probably will support different formats */
	__le16	eh_entries;	/* number of valid entries */
	__le16	eh_max;		/* capacity of store in entries */
	__le16	eh_depth;	/* has tree real underlying blocks? */
	__le32	eh_generation;	/* generation of the tree */
};

struct ext4_extent_idx {
	__le32	ei_block;	/* index covers logical blocks from 'block' */
	__le32	ei_leaf_lo;	/* pointer to the physical block of the next *
				 * level. leaf or next index could be there */
	__le16	ei_leaf_hi;	/* high 16 bits of physical block */
	__u16	ei_unused;
};

struct ext4_extent {
	__le32	ee_block;	/* first logical block extent covers */
	__le16	ee_len;		/* number of blocks covered by extent */
	__le16	ee_start_hi;	/* high 16 bits of physical block */
	__le32	ee_start_lo;	/* low 32 bits of physical block */
};
```
## 3. 创建文件流程
1. 从父目录所在的组开始，找一个有空闲inode的组  
2. 读inode-bitmap，找一个有空闲的位置  
3. 加到父目录的文件里  
4. inode标脏，并把inode与dentry关联  


## 2. 工具

### 2.1 mkfs.ext4/mke2fs
大多系统上mkfs.ext4是指向mke2fs的软链接，mke2fs程序是制作ext2/3/4的用户层工具。

1. 块大小1K
```sh
# 创建一个120k块大小为1k的虚拟设备
$ dd if=/dev/zero of=ext4dev bs=1k count=120
120+0 records in
120+0 records out
122880 bytes (123 kB, 120 KiB) copied, 0.000564468 s, 218 MB/s
$ mkfs.ext
mkfs.ext2  mkfs.ext3  mkfs.ext4  
$ mkfs.ext4 ext4dev 
mke2fs 1.44.5 (15-Dec-2018)
# 磁盘空间太小，无法创建日志系统
Filesystem too small for a journal
Discarding device blocks: done        
# 创建了120个1k大小的块，16个inode                    
Creating filesystem with 120 1k blocks and 16 inodes

Allocating group tables: done                            
Writing inode tables: done                            
Writing superblocks and filesystem accounting information: done
```

2. 块大小4K
```sh
# 创建一个4M的块大小为4k的虚拟设备
$ dd if=/dev/zero of=ext4dev4k bs=4k count=1024
1024+0 records in
1024+0 records out
4194304 bytes (4.2 MB, 4.0 MiB) copied, 0.00264267 s, 1.6 GB/s
$ mkfs.ext4 ext4dev4k
mke2fs 1.44.5 (15-Dec-2018)
Discarding device blocks: done     
# 创建了120个1k大小的块，16个inode                        
Creating filesystem with 4096 1k blocks and 1024 inodes

Allocating group tables: done                            
Writing inode tables: done            
# 创建日志块                
Creating journal (1024 blocks): done
Writing superblocks and filesystem accounting information: done

```

### 2.2 dumpe2fs
该命令用于查看设备上运行的ext系列文件系统(ext2/3/4)的各项信息。输出中的各项参数信息可以分为两部分，上半部分是超级块（Super Block）中包含的各项参数
信息，下半部分是各个块组（Block Group）的各项参数信息。

1. 1k
```sh

$ dumpe2fs ext4dev 
dumpe2fs 1.44.5 (15-Dec-2018)
# 卷名，因为是用默认的创建的，我们没有指定，所以为空
Filesystem volume name:   <none>
# 上次挂载目录
Last mounted on:          <not available>
# uuid，自动生成的
Filesystem UUID:          475c1dfd-8035-4338-87ab-5eaea27d0f1f
# extx文件系统的魔数
Filesystem magic number:  0xEF53
# fs版本号
Filesystem revision #:    1 (dynamic)
# 特性，
Filesystem features:      ext_attr resize_inode dir_index filetype extent 64bit flex_bg sparse_super large_file huge_file uninit_bg dir_nlink extra_isize
# 标志
Filesystem flags:         signed_directory_hash 
# 默认挂载选项：用户扩展属性，acl
Default mount options:    user_xattr acl
# 状态：干净
Filesystem state:         clean
# fs出错后的处理行为：继续执行，其他状态还有remount-ro(挂载成只读)， panic(崩溃)
Errors behavior:          Continue
# 系统类型
Filesystem OS type:       Linux
# inode数量
Inode count:              16
# 块数
Block count:              120
# 保留的块数
Reserved block count:     6
# 空闲块数
Free blocks:              99
# 空闲inode数量
Free inodes:              5
# 第1个块的序号
First block:              1
# 块大小
Block size:               1024
# 碎片？
Fragment size:            1024
# 组描述符大小
Group descriptor size:    64

# 每组内的块数, 因为块大小是1024，块位图是1个块，
# 所以一个组里的块数就是一个块里比特位数(1024*8=8192)
# 每组的大小就是组块x块大小=8192x1024=8M
Blocks per group:         8192
# 每组内的fragment数
Fragments per group:      8192
# 每组inode数量
Inodes per group:         16
# 每组inode块的数量
Inode blocks per group:   2
# todo: what?
Flex block group size:    16
# fs创建时间
Filesystem created:       Tue Jul 25 09:32:07 2023
# 上次挂载时间
Last mount time:          n/a
# 上次写时间
Last write time:          Tue Jul 25 09:32:07 2023
# 挂载次数
Mount count:              0
# 最大挂载次数，-1表示不限制？
Maximum mount count:      -1
# 最后一次检查的时间
Last checked:             Tue Jul 25 09:32:07 2023
# 检查间隔
Check interval:           0 (<none>)
# todo: ?
Lifetime writes:          18 kB
# 保留块使用户的uid
Reserved blocks uid:      0 (user root)
# 保留块使用户的gid
Reserved blocks gid:      0 (group root)
# 第1个inode的序号。todo: 为啥是11
First inode:              11
# inode大小
Inode size:               128
# 目录哈希算法：md4
Default directory hash:   half_md4
# 哈希种子
Directory Hash Seed:      ddf6d20e-6acc-44ba-9c07-222f05e27190

# 0号组(块号 1-119)。起点是从1号块开始，0号块预留给操作系统存放grub等信息
Group 0: (Blocks 1-119) csum 0xa1d1 [ITABLE_ZEROED]
  # 主超级块在1号块，组描述符在2号块
  Primary superblock at 1, Group descriptors at 2-2
  # 块位图起点在3号块，括号里的+2表示与起始块的offset，下同
  Block bitmap at 3 (+2)
  # inode位图起点在19号块
  Inode bitmap at 19 (+18)
  # inode表在35-36号块，占用2个块。
  # node-size=128b，块大小是1024b，所以一个块能存8个inode，共有16个inode，所以需要2个块来存储
  Inode table at 35-36 (+34)
  # 99个空闲块，5个空闲inode，2个目录，5个未使用的inode
  99 free blocks, 5 free inodes, 2 directories, 5 unused inodes
  # 空闲块号：18, 20-34, 37-119
  Free blocks: 18, 20-34, 37-119
  # 空闲inode号：12-16
  Free inodes: 12-16
```

2. 4k
```sh
$ dumpe2fs ext4dev4k 
...
Inode count:              1024
Block count:              4096
Reserved block count:     204
Free blocks:              2894
Free inodes:              1013
First block:              1
Block size:               1024
Fragment size:            1024
Group descriptor size:    64
# 保留的GDT块
Reserved GDT blocks:      31
Blocks per group:         8192
Fragments per group:      8192
Inodes per group:         1024
Inode blocks per group:   128
Flex block group size:    16
Filesystem created:       Tue Jul 25 10:04:29 2023
Last mount time:          n/a
Last write time:          Tue Jul 25 10:04:29 2023
Mount count:              0
Maximum mount count:      -1
Last checked:             Tue Jul 25 10:04:29 2023
Check interval:           0 (<none>)
Lifetime writes:          51 kB
Reserved blocks uid:      0 (user root)
Reserved blocks gid:      0 (group root)
First inode:              11
Inode size:               128
# 日志inode起点
Journal inode:            8
Default directory hash:   half_md4
Directory Hash Seed:      17e61b4f-b2e3-4cb5-bf3a-b63459e8e4f8
Journal backup:           inode blocks
Journal features:         (none)
Journal size:             1024k
Journal length:           1024
Journal sequence:         0x00000001
Journal start:            0


Group 0: (Blocks 1-4095) csum 0xb4a4 [ITABLE_ZEROED]
  Primary superblock at 1, Group descriptors at 2-2
  Reserved GDT blocks at 3-33
  Block bitmap at 34 (+33)
  Inode bitmap at 50 (+49)
  Inode table at 66-193 (+65)
  2894 free blocks, 1013 free inodes, 2 directories, 1013 unused inodes
  Free blocks: 1202-4095
  Free inodes: 12-1024
```
### 2.3 fsck.ext4
```sh
$ fsck.ext4 ext4dev 
e2fsck 1.44.5 (15-Dec-2018)
ext4dev: clean, 11/16 files, 21/120 blocks
```

### 2.4 通过hexdump查看磁盘数据
```sh
$ hexdump -s 1024 -n 1024 ext4img -C
00000400  10 27 00 00 40 9c 00 00  d0 07 00 00 3f 84 00 00  |.'..@.......?...|
00000410  05 27 00 00 01 00 00 00  00 00 00 00 00 00 00 00  |.'..............|
00000420  00 20 00 00 00 20 00 00  d0 07 00 00 bf c2 ff 64  |. ... .........d|
00000430  bf c2 ff 64 01 00 ff ff  53 ef 01 00 01 00 00 00  |...d....S.......|
00000440  ba c2 ff 64 00 00 00 00  00 00 00 00 01 00 00 00  |...d............|
00000450  00 00 00 00 0b 00 00 00  80 00 00 00 3c 00 00 00  |............<...|
00000460  c6 02 00 00 7b 00 00 00  8f e0 89 81 a7 52 40 fb  |....{........R@.|
00000470  94 17 bc 2c 1e ed 47 dc  00 00 00 00 00 00 00 00  |...,..G.........|
00000480  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```


