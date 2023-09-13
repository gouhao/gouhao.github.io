# 数据结构
代码基于stable-5.10.102

## 简介
我对VFS的理解：  
虚拟文件系统定义一套关于文件读写的通用流程，将与具体文件系统相关的操作抽象成一组函数指针，让各个文件系统自己来定义这些函数。  

熟悉面向对象的同学对这些会比较熟，因为这是面向对象的常用手法，在设计模式里有个模板方法模式就和这个很类似。模板方法模式中父类定义一个算法的基本框架，然后将特定的操作抽象成接口，让子类自己去实现。  

## 文件相关的数据结构
下面所说的文件指的是普通文件和目录，因为从内核来看，这两个是同一个东西，只是类型不一样。  

inode, dentry, file这三个数据结构，这三个与我们平时操作文件最相关。先看一下它们的关系图：
![图1](https://img-blog.csdnimg.cn/a58fddbf21994c8486462d557670ff45.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA6Iuf5rWp,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

每个进程打开一个文件，就会产生一个file对象，存储在进程描述符里。file里保存着dentry的指针，file与dentry是多对一的关系，可以多次打开一个文件。  

dentry是目录项，每都有一个dentry对象，里面主要保存了文件名，inode指针，dentry与inode是多对一的关系，因为一个inode可能有多个文件名，比较我们用link产生一个硬链接的时候（注意：不是软链接），就会生成一个dentry指向一个inode。  

inode代表了一个真正的文件，它保存了一个文件的基础数据，像用户访问权限，用户/组id，ino号等。

### file
```c
struct path {
    // 文件对应的具体文件系统信息
	struct vfsmount *mnt;
    // 文件对应的dentry
	struct dentry *dentry;
} __randomize_layout;


struct file {
	...
    // 里面有dentry和mnt
	struct path		f_path;
    // 指向inode对象
	struct inode		*f_inode;	/* cached value */
    // 文件操作
	const struct file_operations	*f_op;

	...
	fmode_t			f_mode;
    // 读写的当前位置
	loff_t			f_pos;
    ...
	void			*private_data;

    ...
    // 映射的操作
	struct address_space	*f_mapping;
	...
} __randomize_layout
```
file保存在task_struct->files里相关的结构里，它把dentry和进程连接了起来，我们在应用层用的open, write等文件操作函数就会调到f_op里的相应函数。f_pos是当前读写的位置，用lseek可以修改这个位置，如果是以O_APPEND打开的写文件，每次在写的时候都会先把f_pos改成文件大小来实现追加。 

### dentry
```c
sstruct dentry {
    ...
    // 指向父目录
	struct dentry *d_parent;
    // 文件名
	struct qstr d_name;
    // 文件对应的inode
	struct inode *d_inode;

    // 短文件名。如果文件名比较短，上面d_name.name = d_iname
    // 如果文件名比较长，就为d_name.name申请适合的内存
    // DNAME_INLINE_LEN在CONFIG_64BIT打开时为32
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */

	...
    // dentry相关操作
	const struct dentry_operations *d_op;
    // 超级块指针
	struct super_block *d_sb;	/* The root of the dentry tree */
	
    ...

    // 子节点，链入父目录的d_subdirs
	struct list_head d_child;
    // 子节点列表。
	struct list_head d_subdirs;

	union {
        // 链入inode的i_dentry
		struct hlist_node d_alias;	/* inode alias list */
		...
	} d_u;
} __randomize_layout;
```
dentry里主要有文件名，父目录，inode这些信息。它把dentry和inode连接起来，并且由d_parent， d_subdirs，d_child实现了我们平时见到的目录树。

### inode
```c
struct inode {
    // 读写执行的标志，文件类型等都在i_mode里
	umode_t			i_mode;
	unsigned short		i_opflags;
    // 文件主的id
	kuid_t			i_uid;
    // 文件主的组id
	kgid_t			i_gid;

    // 一些控制标志
	unsigned int		i_flags;

    // 访问控制列表相关，selinux会用到
#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
#endif

    // inode的操作函数，具体文件系统实现
	const struct inode_operations	*i_op;

    // 超级块指针
	struct super_block	*i_sb;

    // 映射的操作函数
	struct address_space	*i_mapping;


	// inode节点号
	unsigned long		i_ino;

    ...

    // 文件大小
	loff_t			i_size;
    
    // 访问时间
	struct timespec64	i_atime;
    // 内容修改时间
	struct timespec64	i_mtime;
    // 元数据修改时间。元数据就是inode自己的一些标志，id等等那些东西
	struct timespec64	i_ctime;

	...

    // 占用多少个块
	blkcnt_t		i_blocks;

    ...
} __randomize_layout;
```
inode里存的都是文件的各种元数据，其中通过i_ino可以在磁盘上找到相应的数据块，inode将文件与磁盘连接了起来。  

通过file, dentry, inode这三个数据结构一层一层的连接，就可以把一个逻辑文件和真实的硬盘文件联系起来，当然还有vfsmount, super_block等这些文件系统的信息。

## 文件系统相关的数据结构

### vfsmount
```c
struct vfsmount {
    // 文件系统的根目录。
    // 这个根目录并不是我们平时说的 "/"，我们平时说的"/"目录是针对进程的，
    // 这里说的根目录是针对文件系统，每个文件系统都有自己的根目录，
    // 所谓的挂载就是把具体文件系统的根目录挂在现有文件系统的某个目录上
	struct dentry *mnt_root;

    // 具体文件系统超级块指针
	struct super_block *mnt_sb;

    // 挂载标志
	int mnt_flags;
} __randomize_layout;
```
vfsmount里保存了具体文件系统相关的信息，将dentry和具体文件系统的根目录，超级块连接起来。

```c
struct super_block {
	struct list_head	s_list;
	dev_t			s_dev;		/* search index; _not_ kdev_t */
    // 块大小左移位数？不确定
	unsigned char		s_blocksize_bits;
    // 块大小
	unsigned long		s_blocksize;
    // 最大文件大小 
	loff_t			s_maxbytes;	
    // 具体文件系统指针
	struct file_system_type	*s_type;
    // 超级块操作函数
	const struct super_operations	*s_op;
	const struct dquot_operations	*dq_op;
	const struct quotactl_ops	*s_qcop;
	const struct export_operations *s_export_op;
	unsigned long		s_flags;
	unsigned long		s_iflags;	/* internal SB_I_* flags */
	unsigned long		s_magic;
    // 设备上的根目录
	struct dentry		*s_root;
	struct rw_semaphore	s_umount;
	...
    // 已挂载链表
	struct list_head	s_mounts;	/* list of mounts; _not_ for fs use */
	struct block_device	*s_bdev;
	struct backing_dev_info *s_bdi;
    ...

	// 具体文件系统信息的指针
    // 一般都用这个值来保存特定文件系统的超级块指针
	void			*s_fs_info;

	...
	struct list_head	s_inodes;	/* all inodes */

} __randomize_layout;
```
超级块里保存了文件系统的管理信息，挂载信息，超级块操作连通了具体文件系统和vfs。

```c
struct file_system_type {
    // 文件系统名
	const char *name;
    // 该文件系统的标志
	int fs_flags;
#define FS_REQUIRES_DEV		1  // 需要真实设备
#define FS_BINARY_MOUNTDATA	2
#define FS_HAS_SUBTYPE		4  // 有子类？
#define FS_USERNS_MOUNT		8	/* Can be mounted by userns root */
#define FS_DISALLOW_NOTIFY_PERM	16	/* Disable fanotify permission events */
#define FS_THP_SUPPORT		8192	/* Remove once all fs converted */
#define FS_RENAME_DOES_D_MOVE	32768	/* FS will handle d_move() during rename() internally. */

    // 初始化fs_context的指针（新代码大多用这个）
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
    // 挂载函数，老代码用这个的多，现在推荐用init_fs_context
	struct dentry *(*mount) (struct file_system_type *, int,
		       const char *, void *);
    // 释放超级块的回调
	void (*kill_sb) (struct super_block *);
	struct module *owner;
	struct file_system_type * next;
	...
};
```
每个具体的文件系统都会向系统注册file_system_type结构，这里面主要是挂载的操作，因为只有挂载上才能使用一个文件系统。

```c
// 挂载点
struct mountpoint {
	struct hlist_node m_hash;
	// 挂载目录
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

struct mount {
	struct hlist_node mnt_hash;
    // 父挂载信息
	struct mount *mnt_parent;
    // 挂载点
	struct dentry *mnt_mountpoint;
    // 文件系统指针
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
    ...
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	struct mountpoint *mnt_mp;	/* where is it mounted */
	...
} __randomize_layout;
```
mount里主要是挂载的的相关信息，有挂载点，具体文件系统指针等。