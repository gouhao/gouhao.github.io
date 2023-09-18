# 路径遍历1：主流程与软链接的处理
遍历路径是一个很常用的操作，通过阅读遍历路径的代码可以把dentry，inode， vfsmnt这些数据结构联系起来，可以对文件系统做一个全面的了解。

## 1. struct nameidata
`struct nameidata`是在路径遍历中记录中间路径及最终结果。
```c
// 在遍历路径是保存遍历过程中的数据及结果
struct nameidata {
	// 当前正在处理结点为的路径,里面有dentry和vfsmount
	struct path	path;
	// 当前正在处理节点的文件名
	struct qstr	last;
	// 根目录信息
	struct path	root;
	// inode
	struct inode	*inode; /* path.dentry.d_inode */
	unsigned int	flags;
	unsigned	seq, m_seq, r_seq;
	// 最后文件的类型
	int		last_type;
	// 遍历的深度，有时候遍历会陷入循环，比如软链接
	unsigned	depth;
	int		total_link_count;
	struct saved {
		struct path link;
		struct delayed_call done;
		const char *name;
		unsigned seq;
	} *stack, internal[EMBEDDED_LEVELS];
	// 要找的文件名
	struct filename	*name;
	struct nameidata *saved;
	unsigned	root_seq;
	// 开始查找的目录的fd
	int		dfd;
	kuid_t		dir_uid;
	umode_t		dir_mode;
} __randomize_layout;

// 一般会调set_nameidata来设置nd
static void set_nameidata(struct nameidata *p, int dfd, struct filename *name)
{
	// 进程当前的nd
	struct nameidata *old = current->nameidata;
	p->stack = p->internal;
	// 开始查找的目录
	p->dfd = dfd;
	// 文件名,这个用struct filename包装了一下
	p->name = name;
	// 链接的数量,链接数量不能超过40,如果超过40就算是循环了
	p->total_link_count = old ? old->total_link_count : 0;
	// 保存老值
	p->saved = old;
	// 把新的nd设置到进程里
	current->nameidata = p;
}
```

## 2. path_lookupat
遍历路径的代码大多入口是path_lookupat。
```c
// nd是上层函数传过来的，会设置好要找的文件名，开始的路径，和一些标志等
static int path_lookupat(struct nameidata *nd, unsigned flags, struct path *path)
{
	// 先根据要找的文件路径初始化nd中的数据, 返回值是要找的文件名
	const char *s = path_init(nd, flags);
	int err;

	...

	// 开始遍历
	while (!(err = link_path_walk(s, nd)) &&
	       (s = lookup_last(nd)) != NULL)
		;

	...

	// 如果没有出错就把找到的结果放到path中
	if (!err) {
		*path = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
	}
	// 结束遍历，这个函数要和path_init成对使用，释放一些遍历过程中的数据
	terminate_walk(nd);
	return err;
}
```
上面代码中的主要函数:
path_init将开始要查找的路径设置好，我们平时输文件名的时候有绝对路径和相对路径，也就是以"/"开始和不以"/"开始，在task里有数据结构记录当前进程的工作目录和根目录，所以path_init就根据要找的文件名设置好nd中的相关数据。  
link_path_walk是主要的遍历过程，在这函数里会根据每个目录的名字，找到对应的dentry, inode数据结构，先在内存里找这些数据，如果内存里没有就从磁盘上读。  

## 3. path_init
```c
static const char *path_init(struct nameidata *nd, unsigned flags)
{
	int error;
	// 取出要查找的文件名
	const char *s = nd->name->name;

	...

	nd->flags = flags | LOOKUP_JUMPED;
	nd->depth = 0;

	...

	// 如果标志里明确要从根目录找
	if (flags & LOOKUP_ROOT) {
		// 根目录的dentry
		struct dentry *root = nd->root.dentry;
		// 根目录的inode
		struct inode *inode = root->d_inode;

		// 如果root不是目录类型，则出错
		// d_can_lookup判断dentry类型是不是DCACHE_DIRECTORY_TYPE
		// todo: 什么时候根结点不是目录？
		if (*s && unlikely(!d_can_lookup(root)))
			return ERR_PTR(-ENOTDIR);
        
		// 设置当前目录为根节点
		nd->path = nd->root;
		nd->inode = inode;
		// 普通路径获取引用计数
		path_get(&nd->path);
        	// 返回文件名
		return s;
	}

	// 如果没有LOOKUP_ROOT的标志就得从文件名里判断是要从根目录找还是从当前目录找
	nd->root.mnt = NULL;
	nd->path.mnt = NULL;
	nd->path.dentry = NULL;

	// 如果是以'/'开头的路径，则是绝对路径,就表示从根目录开始找
	// LOOKUP_IN_ROOT是把当前目录当做根目录
	if (*s == '/' && !(flags & LOOKUP_IN_ROOT)) {
		// nd_jump_root会设置nd里相关变量为当前进程根目录的dentry和对应的文件系统
		error = nd_jump_root(nd);
		if (unlikely(error))
			return ERR_PTR(error);
		return s;
	}

	// 这里都是相对路径
	if (nd->dfd == AT_FDCWD) {
		// 设置为当前工作目录的path和inode
		// 这个会设置当前进程工作目录的dentry和对应的文件系统
		// 获取的是current->fs->pwd
		get_fs_pwd(current->fs, &nd->path);
		nd->inode = nd->path.dentry->d_inode;
	} else {
		// 这个路径就是用户指定了相对路径

		// 先找出用户指定路径的文件描述符结构
		struct fd f = fdget_raw(nd->dfd);
		struct dentry *dentry;

		if (!f.file)
			return ERR_PTR(-EBADF);

		// 文件的dentry
		dentry = f.file->f_path.dentry;

		// 指定的开始路径不是目录，则返回
		if (*s && unlikely(!d_can_lookup(dentry))) {
			fdput(f);
			return ERR_PTR(-ENOTDIR);
		}

		// 设置开始目录的path对象和inode为特定文件的
		nd->path = f.file->f_path;
		// 设置开始目录的inode
		path_get(&nd->path);
		nd->inode = nd->path.dentry->d_inode;
		fdput(f);
	}

	...
	return s;
}
```
这个函数主要是指定了遍历时候的起点：根、当前目录、指定目录。

### 3.1 nd_jump_root
```c
static int nd_jump_root(struct nameidata *nd)
{
	...

	// 根fs还没设置
	if (!nd->root.mnt) {
		// set_root会获取当前进程的根文件系统和根dentry,
		// 获取的是current->fs->root
		int error = set_root(nd);
		if (error)
			return error;
	}

	// 先释放原来的path
	path_put(&nd->path);
	// 设置path和inode为根节点的值
	nd->path = nd->root;
	path_get(&nd->path);
	nd->inode = nd->path.dentry->d_inode;

	nd->flags |= LOOKUP_JUMPED;
	return 0;
}
```

## 4. link_path_walk
path_init把nd里开始查找的dentry, inode, 文件系统相关信息设置好之后，就由link_path_walk来遍历路径中的每个节点。

```c
static int link_path_walk(const char *name, struct nameidata *nd)
{
	int depth = 0;
	int err;

	// 初始化默认类型和flags, 默认是根结点,找的是父结点,在下面的遍历中会改
	nd->last_type = LAST_ROOT;
	nd->flags |= LOOKUP_PARENT;
	if (IS_ERR(name))
		return PTR_ERR(name);
    
	// 如果路径以'/'开头，则跳过'/'，所以在路径中间加多个'/'是允许的
	while (*name=='/')
		name++;

	// 如果路径到头了，那直接返回
	if (!*name)
		return 0;

	for(;;) {
		const char *link;
		u64 hash_len;
		int type;

		// map_loopup会检查对当前目录的EXEC权限
		/* 权限校验的一般流程:
			1. 如果是属主, 直接校验对就的权限
			2. 否则,如果有acl, 先校验acl
			3. acl通过后再校验rwe权限
		*/
		err = may_lookup(nd);
		if (err)
			return err;

		/**
		 算出name中以'/'分隔的一个节点的hash值和节点长度。
		 name是整个路径，比如/root/aaa, 由于在前面已经去掉了第一个'/'，
		 所以第一次循环时，这里的name是 root/aaa, 
		 hash_name算出root的哈希值和长度作为返回值，返回值的高32位存长度，
		 低32位存哈希值。
		*/
		hash_len = hash_name(nd->path.dentry, name);

		// 默认是正常结点
		type = LAST_NORM;

		// 这里会判断 '..' 和 '.'的情况
		if (name[0] == '.') switch (hashlen_len(hash_len)) {
			case 2:
				// 2个都是 .
				if (name[1] == '.') {
					type = LAST_DOTDOT;
					nd->flags |= LOOKUP_JUMPED;
				}
				break;
			case 1:
				// 只有一个点是当前目录
				type = LAST_DOT;
		}
		if (likely(type == LAST_NORM)) {
			// 如果是普通的文件名
			struct dentry *parent = nd->path.dentry;
			// 去除跳转标志
			nd->flags &= ~LOOKUP_JUMPED;

			// DCACHE_OP_HASH表示文件系统有自己计算哈希值的方法，则通过
			// 文件系统计算哈希值，如果文件系统支持的话
			if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
				struct qstr this = { { .hash_len = hash_len }, .name = name };
				err = parent->d_op->d_hash(parent, &this);
				if (err < 0)
					return err;
				hash_len = this.hash_len;
				name = this.name;
			}
		}

		// 设置哈希值,名称和类型
		nd->last.hash_len = hash_len;
		nd->last.name = name;
		nd->last_type = type;

		// 字符串前进len个长度
		name += hashlen_len(hash_len);
		// 如果后面没有字符了,跳到ok
		if (!*name)
			goto OK;

		// 走到这儿表示后面还有字符串
		// 跳过路径后面多个 '/'，所以在路径里加多个'/'，也没事
		do {
			name++;
		} while (unlikely(*name == '/'));

		
		if (unlikely(!*name)) { // name是最后一个节点
OK: // 遍历完成
			if (!depth) {
				// depth为0,表示没有软链接,则查找完成了

				// 设置目录的uid和mod
				nd->dir_uid = nd->inode->i_uid;
				nd->dir_mode = nd->inode->i_mode;
				// 去除找父目录的标志
				nd->flags &= ~LOOKUP_PARENT;
				return 0;
			}
			// 如果之前有软链接,则取出保存的未处理完的路径名
			name = nd->stack[--depth].name;
			// 获取nd对应的目录
			link = walk_component(nd, 0);
		} else { 
			// name是中间节点
			link = walk_component(nd, WALK_MORE);
		}

		// link返回的是符号链接的值
		if (unlikely(link)) { 
			// 如果是个符号链接，则取出称号链接的值，继续循环
			if (IS_ERR(link))
				return PTR_ERR(link);
			// 先把以前的name保存到栈里
			nd->stack[depth++].name = name;
			// 因为这个节点是链接,则先处理链接
			name = link;
			continue;
		}

		// 不是个目录,则出错
		if (unlikely(!d_can_lookup(nd->path.dentry))) {
			if (nd->flags & LOOKUP_RCU) {
				if (!try_to_unlazy(nd))
					return -ECHILD;
			}
			return -ENOTDIR;
		}
	}
}
```

## 5. walk_component
```c
static const char *walk_component(struct nameidata *nd, int flags)
{
	struct dentry *dentry;
	struct inode *inode;
	unsigned seq;
	
	// 如果不是正常路径, 则只有需要处理 . 和 ..
	if (unlikely(nd->last_type != LAST_NORM)) { 
		// todo: what?
		if (!(flags & WALK_MORE) && nd->depth)
			put_link(nd);
		
		// 这个函数只处理 '..'，因为'.'不用处理
		return handle_dots(nd, nd->last_type);
	}
	// 在内存里找dentry
	dentry = lookup_fast(nd, &inode, &seq);
	if (IS_ERR(dentry))
		return ERR_CAST(dentry);
	if (unlikely(!dentry)) {
		// 如果在内存里没找到就要去具体的文件系统里找，有可能还要读磁盘，
		// 所以是慢路径
		dentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);
		if (IS_ERR(dentry))
			return ERR_CAST(dentry);
	}
	// todo: 没看懂
	if (!(flags & WALK_MORE) && nd->depth)
		put_link(nd);
	// 把找到的信息设置到nd里，并且有可能会跟踪链接及挂载点
	return step_into(nd, flags, dentry, inode, seq);
}
```

### 5.1 handle_dots
```c
static const char *handle_dots(struct nameidata *nd, int type)
{
	if (type == LAST_DOTDOT) { 
		// '..'就是上层目录
		const char *error = NULL;
		struct dentry *parent;
		struct inode *inode;
		unsigned seq;

		...
		// 返回上一层目录
		parent = follow_dotdot(nd, &inode, &seq);
		if (IS_ERR(parent))
			return ERR_CAST(parent);
		
		if (unlikely(!parent))
			error = step_into(nd, WALK_NOFOLLOW,
					 nd->path.dentry, nd->inode, nd->seq);
		else
			// 设置节点信息到nd里
			error = step_into(nd, WALK_NOFOLLOW,
					 parent, inode, seq);
		...
	}
	return NULL;
}
```

## 6. step_into
```c
static const char *step_into(struct nameidata *nd, int flags,
		     struct dentry *dentry, struct inode *inode, unsigned seq)
{
	struct path path;
	// handle_mounts会判断当前dentry是否是挂载点，如果是的话，则前进到最后一个挂载点里
	int err = handle_mounts(nd, dentry, &path, &inode, &seq);

	if (err < 0)
		return ERR_PTR(err);
	if (likely(!d_is_symlink(path.dentry)) ||
	   ((flags & WALK_TRAILING) && !(nd->flags & LOOKUP_FOLLOW)) ||
	   (flags & WALK_NOFOLLOW)) { 
		   // 如果不是符号链接，走这个分支
		
		if (!(nd->flags & LOOKUP_RCU)) {
			dput(nd->path.dentry);
			if (nd->path.mnt != path.mnt)
				mntput(nd->path.mnt);
		}

		// 这里把相关信息设置后就直接返回
		nd->path = path;
		nd->inode = inode;
		nd->seq = seq;
		return NULL;
	}

	// 走到这儿表示是个符号链接
	if (path.mnt == nd->path.mnt)
		mntget(path.mnt);
	// 走到这里说明是软连接，要跟踪到软链接里, 返回值是链接的字符串
	return pick_link(nd, &path, inode, seq, flags);
}
```

### 6.1 pick_link
```c
static const char *pick_link(struct nameidata *nd, struct path *link,
		     struct inode *inode, unsigned seq, int flags)
{
	struct saved *last;
	const char *res;
	// 判断链接循环数据,防止无限循环,最大层级为40
	int error = reserve_stack(nd, link, seq);

	if (unlikely(error)) {
		if (!(nd->flags & LOOKUP_RCU))
			path_put(link);
		return ERR_PTR(error);
	}
	// 先把last设置成当前路径，如果之前没有跟踪过depth，则depth应该是0
	last = nd->stack + nd->depth++;
	last->link = *link;
	clear_delayed_call(&last->done);
	last->seq = seq;

	if (flags & WALK_TRAILING) {
		// 检查权限
		error = may_follow_link(nd, inode);
		if (unlikely(error))
			return ERR_PTR(error);
	}

	// 如果文件系统不支持软件链接则退出
	if (unlikely(nd->flags & LOOKUP_NO_SYMLINKS) ||
			unlikely(link->mnt->mnt_flags & MNT_NOSYMFOLLOW))
		return ERR_PTR(-ELOOP);

	// 更新访问时间
	if (!(nd->flags & LOOKUP_RCU)) {
		touch_atime(&last->link);
		cond_resched();
	} else if (atime_needs_update(&last->link, inode)) {
		if (!try_to_unlazy(nd))
			return ERR_PTR(-ECHILD);
		touch_atime(&last->link);
	}

	// 调用安全接口
	error = security_inode_follow_link(link->dentry, inode,
					   nd->flags & LOOKUP_RCU);
	if (unlikely(error))
		return ERR_PTR(error);

	res = READ_ONCE(inode->i_link);
	if (!res) {
		const char * (*get)(struct dentry *, struct inode *,
				struct delayed_call *);
		// 获取文件系统的get_line接口
		get = inode->i_op->get_link;

		// 调用具体文件系统的get_link接口，具体文件接口会解析软链接里的路径
		if (nd->flags & LOOKUP_RCU) {
			res = get(NULL, inode, &last->done);
			if (res == ERR_PTR(-ECHILD) && try_to_unlazy(nd))
				res = get(link->dentry, inode, &last->done);
		} else {
			res = get(link->dentry, inode, &last->done);
		}
		if (!res)
			goto all_done;
		if (IS_ERR(res))
			return res;
	}
	
	// 如果最终软链接以'/'开头，则修改nd指向根文件系统
	if (*res == '/') {
		error = nd_jump_root(nd);
		if (unlikely(error))
			return ERR_PTR(error);
		while (unlikely(*++res == '/'))
			;
	}
	if (*res)
		return res;
all_done: // pure jump
	put_link(nd);
	return NULL;
}
```