# Pipe

源码基于stable-5.10.102

## 简介
管道有匿名管道和命名管道之分，在应用层匿名管道用pipe系统调用创建，命名管道用mkfifo创建（或者自己用shell命令创建）。  
匿名管道只能在进程内使用，比如父子进程之间通信；而命名管道会创建一个文件，其它进程只要知道这个文件路径，并有相应的读写权限就可以访问这个管道。  
在内核里只提供了pipe系统调用，并没有mkfifo系统调用。mkfifo是应用层提供的函数接口。

## 文件系统初始化
```c
static struct file_system_type pipe_fs_type = {
	.name		= "pipefs",
	// init_fs_context这种形式的挂载用来代替传统的mount
	.init_fs_context = pipefs_init_fs_context,
	.kill_sb	= kill_anon_super,
};

static int __init init_pipe_fs(void)
{
	// 注册文件系统
	int err = register_filesystem(&pipe_fs_type);

	if (!err) {
		// 注册成功后主动挂载
		pipe_mnt = kern_mount(&pipe_fs_type);
		if (IS_ERR(pipe_mnt)) {
			err = PTR_ERR(pipe_mnt);
			unregister_filesystem(&pipe_fs_type);
		}
	}
	return err;
}

fs_initcall(init_pipe_fs);
```

```c
static int pipefs_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, PIPEFS_MAGIC);
	if (!ctx)
		return -ENOMEM;
	ctx->ops = &pipefs_ops;
	ctx->dops = &pipefs_dentry_operations;
	return 0;
}

struct pseudo_fs_context *init_pseudo(struct fs_context *fc,
					unsigned long magic)
{
	struct pseudo_fs_context *ctx;

	ctx = kzalloc(sizeof(struct pseudo_fs_context), GFP_KERNEL);
	if (likely(ctx)) {
		ctx->magic = magic;
		fc->fs_private = ctx;
		fc->ops = &pseudo_fs_context_ops;

		// SB_NOUSER表示不允许用户层挂载？
		fc->sb_flags |= SB_NOUSER;
		fc->global = true;
	}
	return ctx;
}
```
伪文件系统的挂载主要是在内存里建立文件系统对应的结构，主要是设置super_block的ops和dentry的ops。

## 匿名管道创建
```c
SYSCALL_DEFINE1(pipe, int __user *, fildes)
{
	return do_pipe2(fildes, 0);
}

static int do_pipe2(int __user *fildes, int flags)
{
	struct file *files[2];
	int fd[2];
	int error;

	// 创建2个pipe文件
	error = __do_pipe_flags(fd, files, flags);
	if (!error) {
		// 把两个pipe的文件描述符复制到用户空间的fildes
		if (unlikely(copy_to_user(fildes, fd, sizeof(fd)))) {
			fput(files[0]);
			fput(files[1]);
			put_unused_fd(fd[0]);
			put_unused_fd(fd[1]);
			error = -EFAULT;
		} else {
			// 把这2个进程描述符放到task的文件列表中
			fd_install(fd[0], files[0]);
			fd_install(fd[1], files[1]);
		}
	}
	return error;
}

static int __do_pipe_flags(int *fd, struct file **files, int flags)
{
	int error;
	int fdw, fdr;

	// flags只能是这4个标志，如果是其他标志，则出错
	if (flags & ~(O_CLOEXEC | O_NONBLOCK | O_DIRECT | O_NOTIFICATION_PIPE))
		return -EINVAL;

	error = create_pipe_files(files, flags);
	if (error)
		return error;

	// 在当前进程中获取一个没有使用的fd，来当做 读 fd
	error = get_unused_fd_flags(flags);
	if (error < 0)
		goto err_read_pipe;
	fdr = error;

	// 在当前进程中获取一个没有使用的fd，来当做 写 fd
	error = get_unused_fd_flags(flags);
	if (error < 0)
		goto err_fdr;
	fdw = error;

	// 审计相关
	audit_fd_pair(fdr, fdw);

	fd[0] = fdr;
	fd[1] = fdw;
	return 0;

 err_fdr:
	put_unused_fd(fdr);
 err_read_pipe:
	fput(files[0]);
	fput(files[1]);
	return error;
}
```

```c
int create_pipe_files(struct file **res, int flags)
{
	// 获取一个inode
	struct inode *inode = get_pipe_inode();
	struct file *f;
	int error;

	if (!inode)
		return -ENFILE;

	// todo: O_NOTIFICATION_PIPE是什么？
	if (flags & O_NOTIFICATION_PIPE) {
		error = watch_queue_init(inode->i_pipe);
		if (error) {
			free_pipe_info(inode->i_pipe);
			iput(inode);
			return error;
		}
	}

	// 创建一个伪文件，这里创建文件是 只写 模式
	f = alloc_file_pseudo(inode, pipe_mnt, "",
				O_WRONLY | (flags & (O_NONBLOCK | O_DIRECT)),
				&pipefifo_fops);
	if (IS_ERR(f)) {
		free_pipe_info(inode->i_pipe);
		iput(inode);
		return PTR_ERR(f);
	}

	// 把i_pipe放到文件的私有数据中，后面写要使用
	f->private_data = inode->i_pipe;

	// 把上面的f文件复制一份，复制的模式是 只读
	res[0] = alloc_file_clone(f, O_RDONLY | (flags & O_NONBLOCK),
				  &pipefifo_fops);
	if (IS_ERR(res[0])) {
		put_pipe_info(inode, inode->i_pipe);
		fput(f);
		return PTR_ERR(res[0]);
	}
	res[0]->private_data = inode->i_pipe;

	// 所以 res[0] 是只读，res[1] 是只写，
	// 这也对应用户层的pipe函数返回后，fd[0]是读，fd[1]是写
	res[1] = f;

	// stream_open是清除这些标志：FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE | FMODE_ATOMIC_POS
	// 然后 写入FMODE_STREAM标志
	stream_open(inode, res[0]);
	stream_open(inode, res[1]);
	return 0;
}

static struct inode * get_pipe_inode(void)
{
	// 申请一个inode，调的是通用方法
	struct inode *inode = new_inode_pseudo(pipe_mnt->mnt_sb);
	struct pipe_inode_info *pipe;

	if (!inode)
		goto fail_inode;

	// 获取一个inode号
	// 这个号是假的，只是在系统运行时唯一，因为pipe本身就是临时文件
	inode->i_ino = get_next_ino();

	// 初始化管道信息，这里面初始化的才是管道真正有用的信息
	pipe = alloc_pipe_info();
	if (!pipe)
		goto fail_iput;

	inode->i_pipe = pipe;
	// 设置files默认为2，这个files意思是有多少个struct file使用这个pipe
	pipe->files = 2;
	// 初始化读写者都是1
	pipe->readers = pipe->writers = 1;
	inode->i_fop = &pipefifo_fops;

	// 一些inode其它初始化
	...
}

struct pipe_inode_info *alloc_pipe_info(void)
{
	struct pipe_inode_info *pipe;
	// PIPE_DEF_BUFFERS=16，默认缓冲区16页
	unsigned long pipe_bufs = PIPE_DEF_BUFFERS;
	struct user_struct *user = get_current_user();
	unsigned long user_bufs;

	// pipe最大长度，默认为1048576。可以通过/proc/sys/fs/pipe-max-size修改
	unsigned int max_size = READ_ONCE(pipe_max_size);

	pipe = kzalloc(sizeof(struct pipe_inode_info), GFP_KERNEL_ACCOUNT);
	if (pipe == NULL)
		goto out_free_uid;

	// 默认缓冲区长度如果大于最大长度，则修改缓冲区个数
	// 假设页大小为4K，那1048576就是256页，默认值才16页，所以不会超过；
	// 如果页大小为64K，那1048576刚好是16页。如果使用默认值，是不会超过的
	if (pipe_bufs * PAGE_SIZE > max_size && !capable(CAP_SYS_RESOURCE))
		pipe_bufs = max_size >> PAGE_SHIFT;

	// 统计当前用户已经使用pipe缓冲的数量，把pipe_buf-0加到用户使用量里
	user_bufs = account_pipe_buffers(user, 0, pipe_bufs);

	// 这个函数比较当前用户已经使用pipe缓冲的数量，如果超过了pipe_user_pages_soft，并且是非特权用户，
	// 则减少用户使用的pipe缓冲

	// pipe_user_pages_soft = PIPE_DEF_BUFFERS(16) * INR_OPEN_CUR(1024) = 16384 , 所以最大限制16384个缓冲
	if (too_many_pipe_buffers_soft(user_bufs) && pipe_is_unprivileged_user()) {
		// 重新统计用户使用的pipe数量，PIPE_MIN_DEF_BUFFERS=2，
		// 上面已经把pipe_bufs加在用户使用量里了，这里的PIPE_MIN_DEF_BUFFERS-pipe_bufs是个负数，
		// 所以可以把多余的减去
		user_bufs = account_pipe_buffers(user, pipe_bufs, PIPE_MIN_DEF_BUFFERS);
		// 设置允许使用的缓冲区个数
		pipe_bufs = PIPE_MIN_DEF_BUFFERS;
	}

	// 这里检查硬限制，默认pipe_user_pages_hard为0，表示没有最大硬限制，
	// 用户可以通过/proc/sys/fs/pipe_user_pages_hard来修改
	if (too_many_pipe_buffers_hard(user_bufs) && pipe_is_unprivileged_user())
		// 如果不是特权用户，并且超过了硬限制，则报错
		goto out_revert_acct;

	// 可以看出限制都是对非特权用户，一般都是非root用户

	// 申请pipe_bufs个缓冲区
	pipe->bufs = kcalloc(pipe_bufs, sizeof(struct pipe_buffer),
			     GFP_KERNEL_ACCOUNT);

	if (pipe->bufs) {
		// 初始化各种变量
		init_waitqueue_head(&pipe->rd_wait);
		init_waitqueue_head(&pipe->wr_wait);
		pipe->r_counter = pipe->w_counter = 1;
		pipe->max_usage = pipe_bufs;
		pipe->ring_size = pipe_bufs;
		pipe->nr_accounted = pipe_bufs;
		pipe->user = user;
		mutex_init(&pipe->mutex);
		return pipe;
	}

out_revert_acct:
	(void) account_pipe_buffers(user, pipe_bufs, 0);
	kfree(pipe);
out_free_uid:
	free_uid(user);
	return NULL;
}
```
到此，关于pipe的建就完成了。  
至于alloc_file_pseudo是标准的vfs函数，申请一个dentry，将dentry和inode关联，然后申请一个file，将file与dentry关联。alloc_file_clone直接使用传进去的file的dentry再创建一个文件，两个使用的是同一个dentry。

## 命名管道的打开与关闭
用mkfifo或shell命令创建命名管道时，会有下面类似的命令：
```sh
mknod filename p
```
创建一个filename的文件，它的文件类型是p。p表示文件命令是命名管道，它的文件类型是S_IFIFO。在初始化inode的时候会在init_special_inode中初始化命令管道类型的操作函数表: 
```c
void init_special_inode(struct inode *inode, umode_t mode, dev_t rdev)
{
	inode->i_mode = mode;
	if (S_ISCHR(mode)) {
		inode->i_fop = &def_chr_fops;
		inode->i_rdev = rdev;
	} else if (S_ISBLK(mode)) {
		inode->i_fop = &def_blk_fops;
		inode->i_rdev = rdev;
	} else if (S_ISFIFO(mode))
        // 这里就将文件和管道的操作关联上了
		inode->i_fop = &pipefifo_fops;
	else if (S_ISSOCK(mode))
		;	/* leave it no_open_fops */
	else
		printk(KERN_DEBUG "init_special_inode: bogus i_mode (%o) for"
				  " inode %s:%lu\n", mode, inode->i_sb->s_id,
				  inode->i_ino);
}
```
匿名管道会在调用pipe时自动打开，但是命名管道要在open系统调用里打开，最终会调用到pipefifo_fops的open函数，下面是函数操作表：
```c
const struct file_operations pipefifo_fops = {
	// fifo才会调用fifo_open，普通调用pipe生成的两个fd不调用open
	.open		= fifo_open,
	// 管道不支持seek
	.llseek		= no_llseek,
	.read_iter	= pipe_read,
	.write_iter	= pipe_write,
	.poll		= pipe_poll,
	.unlocked_ioctl	= pipe_ioctl,
	.release	= pipe_release,
	.fasync		= pipe_fasync,
	.splice_write	= iter_file_splice_write,
};

static int fifo_open(struct inode *inode, struct file *filp)
{
	struct pipe_inode_info *pipe;
	/**
	is_pipe表示是否是匿名管道
	匿名管道的inode是通过get_pipe_inode创建的，所以它的超级块是pipefs的超级块，进而也会有PIPEFS_MAGIC标志;
	而命名管道是通过mknod建立的，它是在其它文件系统之上建立了一个inode，所以命令管道的inode的超级块的s_magic，
	是所在文件系统的magic
	**/
	bool is_pipe = inode->i_sb->s_magic == PIPEFS_MAGIC;
	int ret;

	filp->f_version = 0;

	spin_lock(&inode->i_lock);
	if (inode->i_pipe) {// 这个分支是已经创建了pipe的上下文
		pipe = inode->i_pipe;
		// 递增files
		pipe->files++;
		spin_unlock(&inode->i_lock);
	} else { // 这个分支是没有创建pipe上下文
		spin_unlock(&inode->i_lock);
		// 先创建一个pipe结构，和上面匿名管道的相同
		pipe = alloc_pipe_info();
		if (!pipe)
			return -ENOMEM;
		pipe->files = 1;
		spin_lock(&inode->i_lock);
		if (unlikely(inode->i_pipe)) {
			// 这个分支是在处理并发情况。
			// 因为上面的申请pipe内存有可能会阻塞，等到申请成功后，
			// 别人可能已经创建了pipe，所以这里发现已经创建了pipe，则释放
			// 刚才申请的
			inode->i_pipe->files++;
			spin_unlock(&inode->i_lock);
			free_pipe_info(pipe);
			pipe = inode->i_pipe;
		} else {
			// 大多数情况都会走这个分支
			inode->i_pipe = pipe;
			spin_unlock(&inode->i_lock);
		}
	}

	// 把pipe放到file的private_data里
	filp->private_data = pipe;

	__pipe_lock(pipe);
	// 给file设置FMODE_STREAM标志，和匿名管道一样
	stream_open(inode, filp);

	switch (filp->f_mode & (FMODE_READ | FMODE_WRITE)) {
	case FMODE_READ:
		// 以只读模式打开

		// 增加读者计数器
		pipe->r_counter++;

		// 如果以前读者为0，则唤醒等待的写者
		if (pipe->readers++ == 0)
			wake_up_partner(pipe);

		if (!is_pipe && !pipe->writers) { // 如果不是匿名管道，也没有写者
			if ((filp->f_flags & O_NONBLOCK)) {
				// 如果用户要求不阻塞，则直接返回
				filp->f_version = pipe->w_counter;
			} else {
				// 否则等待写者
				// wait_for_partner是等待第二个参数的值改变，才返回
				// 这里因为还没有写者，所以要等有了写者才返回
				if (wait_for_partner(pipe, &pipe->w_counter))
					goto err_rd;
			}
		}
		break;

	case FMODE_WRITE:
	 	// 只写模式
		ret = -ENXIO;
		// 如果不是匿名管道，没有读者，也不阻塞，则直接返回
		if (!is_pipe && (filp->f_flags & O_NONBLOCK) && !pipe->readers)
			goto err;

		// 递增写者统计
		pipe->w_counter++;

		// 递增当前写者计数器
		if (!pipe->writers++)
			// 如果以前写者为0，则唤醒读者
			// wake_up_partner是唤醒在rd_wait队列上等待的进程
			wake_up_partner(pipe);

		// 如果不是匿名管道，而且也没有读者，则等待一个读者
		if (!is_pipe && !pipe->readers) {
			if (wait_for_partner(pipe, &pipe->r_counter))
				goto err_wr;
		}
		break;

	case FMODE_READ | FMODE_WRITE:
		// 读写方式打七

		// 增加读者与写者相关的计数器
		pipe->readers++;
		pipe->writers++;
		pipe->r_counter++;
		pipe->w_counter++;

		// 如果之前，读者或写者为0，则唤醒读写者
		if (pipe->readers == 1 || pipe->writers == 1)
			wake_up_partner(pipe);
		break;

	default:
		// 其它模式返回错误
		ret = -EINVAL;
		goto err;
	}

	/* Ok! */
	__pipe_unlock(pipe);
	return 0;

err_rd:
	if (!--pipe->readers)
		wake_up_interruptible(&pipe->wr_wait);
	ret = -ERESTARTSYS;
	goto err;

err_wr:
	if (!--pipe->writers)
		wake_up_interruptible_all(&pipe->rd_wait);
	ret = -ERESTARTSYS;
	goto err;

err:
	__pipe_unlock(pipe);

	put_pipe_info(inode, pipe);
	return ret;
}

static int wait_for_partner(struct pipe_inode_info *pipe, unsigned int *cnt)
{
	DEFINE_WAIT(rdwait);

	// 记录cnt的值
	int cur = *cnt;

	// 当cnt的值没有变化时，在rd_wait队列上等待
	while (cur == *cnt) {
		prepare_to_wait(&pipe->rd_wait, &rdwait, TASK_INTERRUPTIBLE);
		pipe_unlock(pipe);
		schedule();
		finish_wait(&pipe->rd_wait, &rdwait);
		pipe_lock(pipe);
		// 如果有信号要处理，则退出。
		if (signal_pending(current))
			break;
	}
	// 如果是因为信号返回的，要重启系统调用，否则表示cnt已经变化
	return cur == *cnt ? -ERESTARTSYS : 0;
}

static void wake_up_partner(struct pipe_inode_info *pipe)
{
	// 唤醒rd_wait上等待的进程
	wake_up_interruptible_all(&pipe->rd_wait);
}
```
打开主要有2个任务，一个是创建pipe上下文，第二个是要保证，读者写者都到位。

下面是关闭的代码，调用close最终会调到文件系统的release方法：

```c
static int
pipe_release(struct inode *inode, struct file *file)
{
	struct pipe_inode_info *pipe = file->private_data;

	__pipe_lock(pipe);
	if (file->f_mode & FMODE_READ)
		// 如果是读，则递减读者
		pipe->readers--;
	if (file->f_mode & FMODE_WRITE)
		// 如果是写，则递减写者
		pipe->writers--;
	// 以读写方式打开的，上面两个计数器都会修改

	// 如果读写者的数量不一致，则唤醒所有等待的进程
	if (!pipe->readers != !pipe->writers) {
		wake_up_interruptible_all(&pipe->rd_wait);
		wake_up_interruptible_all(&pipe->wr_wait);
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
		kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
	}
	__pipe_unlock(pipe);

	// 递减pipe，如果没人用了则释放pipe
	put_pipe_info(inode, pipe);
	return 0;
}
```

## pipe的读写
匿名管道和命名管道的读写过程是一致的。
```c
// 读
static ssize_t
pipe_read(struct kiocb *iocb, struct iov_iter *to)
{
	// 要读取数据的长度
	size_t total_len = iov_iter_count(to);
	struct file *filp = iocb->ki_filp;
	struct pipe_inode_info *pipe = filp->private_data;
	bool was_full, wake_next_reader = false;
	ssize_t ret;

	/* Null read succeeds. */
	if (unlikely(total_len == 0))
		return 0;

	ret = 0;
	__pipe_lock(pipe);

	// was_full = head - tail > pipe->max_usage
	was_full = pipe_full(pipe->head, pipe->tail, pipe->max_usage);
	for (;;) {
		unsigned int head = pipe->head;
		unsigned int tail = pipe->tail;
		// ring_size 初始化是pipe_bufs，
		// 减去1,相当于是掩码。比如： 0100 - 1 = 0011
		unsigned int mask = pipe->ring_size - 1;

		// todo: CONFIG_WATCH_QUEUE是个啥？
#ifdef CONFIG_WATCH_QUEUE
		if (pipe->note_loss) {
			struct watch_notification n;

			if (total_len < 8) {
				if (ret == 0)
					ret = -ENOBUFS;
				break;
			}

			n.type = WATCH_TYPE_META;
			n.subtype = WATCH_META_LOSS_NOTIFICATION;
			n.info = watch_sizeof(n);
			if (copy_to_iter(&n, sizeof(n), to) != sizeof(n)) {
				if (ret == 0)
					ret = -EFAULT;
				break;
			}
			ret += sizeof(n);
			total_len -= sizeof(n);
			pipe->note_loss = false;
		}
#endif

		if (!pipe_empty(head, tail)) { // 所有的缓冲区都用了
			// tail指向的缓冲区
			struct pipe_buffer *buf = &pipe->bufs[tail & mask];
			// 缓冲区长度
			size_t chars = buf->len;
			size_t written;
			int error;

			if (chars > total_len) { // 如果要读的长度小于buffer的长度
				// 如果有PIPE_BUF_FLAG_WHOLE这个标志，则出错返回，
				if (buf->flags & PIPE_BUF_FLAG_WHOLE) {
					if (ret == 0)
						ret = -ENOBUFS;
					break;
				}
				// 把长度设为要读取的长度
				chars = total_len;
			}
			// 调用buf->ops->confirm，pipe没有这个函数
			error = pipe_buf_confirm(pipe, buf);
			if (error) {
				if (!ret)
					ret = error;
				break;
			}

			// 向读缓冲区拷数据
			written = copy_page_to_iter(buf->page, buf->offset, chars, to);
			if (unlikely(written < chars)) {
				if (!ret)
					ret = -EFAULT;
				break;
			}
			// 递增已读数据统计
			ret += chars;

			// 增加buf的偏移
			buf->offset += chars;

			// 减少buf的长度
			buf->len -= chars;

			// 如果buf是一个数据包，则把buf清空
			if (buf->flags & PIPE_BUF_FLAG_PACKET) {
				total_len = chars;
				buf->len = 0;
			}

			if (!buf->len) {
				// 可能会释放pipe
				pipe_buf_release(pipe, buf);
				spin_lock_irq(&pipe->rd_wait.lock);
#ifdef CONFIG_WATCH_QUEUE
				if (buf->flags & PIPE_BUF_FLAG_LOSS)
					pipe->note_loss = true;
#endif
				// 增加尾指针
				// 因为head, tail默认都是0，写的时候是从head开始写，
				// 所以读完一个buf，要增加tail
				tail++;
				pipe->tail = tail;
				spin_unlock_irq(&pipe->rd_wait.lock);
			}
			// 从要读的数据中减去已经读的
			total_len -= chars;

			// 如果没有整据，则退出
			if (!total_len)
				break;

			// 判断非空再循环，多此一举！！
			if (!pipe_empty(head, tail))
				continue;
		}

		// 如果没有写者，则退出
		if (!pipe->writers)
			break;
		if (ret)
			break;
		// 如果不阻塞，退出
		if (filp->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		__pipe_unlock(pipe);

		// todo: 已经到最后一个缓冲区了，但是没读到数据。。。
		// 唤醒wr_wait队列的进程
		if (unlikely(was_full))
			wake_up_interruptible_sync_poll(&pipe->wr_wait, EPOLLOUT | EPOLLWRNORM);
		// 向写者发送SIGIO信号，用于POLL
		kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);

		// 在rd_wait等待
		if (wait_event_interruptible_exclusive(pipe->rd_wait, pipe_readable(pipe)) < 0)
			return -ERESTARTSYS;

		// 唤醒之后继续读
		__pipe_lock(pipe);
		was_full = pipe_full(pipe->head, pipe->tail, pipe->max_usage);
		wake_next_reader = true;
	}

	// 如果pipe已经空了，则不再唤醒下一个reader
	if (pipe_empty(pipe->head, pipe->tail))
		wake_next_reader = false;
	__pipe_unlock(pipe);

	// 唤醒写者
	if (was_full)
		wake_up_interruptible_sync_poll(&pipe->wr_wait, EPOLLOUT | EPOLLWRNORM);
	
	// 如果需要唤醒读才
	if (wake_next_reader)
		wake_up_interruptible_sync_poll(&pipe->rd_wait, EPOLLIN | EPOLLRDNORM);
	
	// 发送POLL相关信号
	kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);

	// 设置访问标志
	if (ret > 0)
		file_accessed(filp);
	return ret;
}

// 写
static ssize_t
pipe_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *filp = iocb->ki_filp;
	struct pipe_inode_info *pipe = filp->private_data;
	unsigned int head;
	ssize_t ret = 0;
	// 要写入的数据
	size_t total_len = iov_iter_count(from);
	ssize_t chars;
	bool was_empty = false;
	bool wake_next_writer = false;

	/* Null write succeeds. */
	if (unlikely(total_len == 0))
		return 0;

	__pipe_lock(pipe);

	// 如果没有读者，则向进程发送SIGPIPE，
	// 初始化的时候readers是1，所以只有读者退出的时候会出现这种情况
	if (!pipe->readers) {
		send_sig(SIGPIPE, current, 0);
		ret = -EPIPE;
		goto out;
	}

#ifdef CONFIG_WATCH_QUEUE
	if (pipe->watch_queue) {
		ret = -EXDEV;
		goto out;
	}
#endif

    // 从head指针开始的地方写
	head = pipe->head;
	was_empty = pipe_empty(head, pipe->tail);
    // 先算出少于一页的数据量
	chars = total_len & (PAGE_SIZE-1);
    
    // 如果缓冲区不空，则判断能否把少于一页的数据加到现有缓冲区后面
	if (chars && !was_empty) { // pipe缓冲区不空，说明有些数据还没读走
		unsigned int mask = pipe->ring_size - 1;
        // 取出当前正在写入的buf
		struct pipe_buffer *buf = &pipe->bufs[(head - 1) & mask];
        // 计算出写入点
        // buf->offset是数据开始在页内的偏移，buf->len为当前缓冲区数据长度,
        // 所以两者这和就是可以写入的起点
		int offset = buf->offset + buf->len;

        // PIPE_BUF_FLAG_CAN_MERGE是相对于不是数据包的形式，所以在缓冲区内是可以合并在一页里的，
        // offset + chars 来判断能否把要写入的数据零头写到当前缓冲区
		if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) &&
		    offset + chars <= PAGE_SIZE) {
            // 这个函数调用 buf->ops->confirm，对于普通的页缓冲区这个函数指针为空
			ret = pipe_buf_confirm(pipe, buf);
			if (ret)
				goto out;

            // 从用户空间复制数据到缓冲区
			ret = copy_page_from_iter(buf->page, offset, chars, from);

            // 复制出错，则返回
			if (unlikely(ret < chars)) {
				ret = -EFAULT;
				goto out;
			}

            // 累加buf的长度
			buf->len += ret;

            // 如果已经复制完了，则直接退出
			if (!iov_iter_count(from))
				goto out;
		}
	}

	for (;;) {

        // 检查还有没有读者
		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		head = pipe->head;
		if (!pipe_full(head, pipe->tail, pipe->max_usage)) { // 缓冲区没有满，说明可以写入
			unsigned int mask = pipe->ring_size - 1;
			struct pipe_buffer *buf = &pipe->bufs[head & mask];
			struct page *page = pipe->tmp_page;
			int copied;

            // 如果pipe->tmp_page为空，则申请一页
            // 在上面的read中，如果读者读完了一页，tmp_page为空时，会把那一页缓存在tmp_page中
            // 所以这里会重用读完的页
			if (!page) {
				page = alloc_page(GFP_HIGHUSER | __GFP_ACCOUNT);
				if (unlikely(!page)) {
					ret = ret ? : -ENOMEM;
					break;
				}
				pipe->tmp_page = page;
			}

			spin_lock_irq(&pipe->rd_wait.lock);

            // 因为加锁可能会睡眠，而被调度出去，所以这里重新取head指针，
            // 然后再检查队列是否已经满了
			head = pipe->head;
			if (pipe_full(head, pipe->tail, pipe->max_usage)) {
				spin_unlock_irq(&pipe->rd_wait.lock);
				continue;
			}

			pipe->head = head + 1;
			spin_unlock_irq(&pipe->rd_wait.lock);

			// 把刚申请的临时页放到bufs中
			buf = &pipe->bufs[head & mask];
			buf->page = page;
			buf->ops = &anon_pipe_buf_ops;
			buf->offset = 0;
			buf->len = 0;
            // is_packetized是以O_DIRECT打开的文件，
            // 使用pipe生成的管道不会有这个标志，只有用命令管道，才可能设置这个标志
			if (is_packetized(filp))
				buf->flags = PIPE_BUF_FLAG_PACKET;
			else
                // todo: PIPE_BUF_FLAG_CAN_MERGE表示缓冲区可以合并？
				buf->flags = PIPE_BUF_FLAG_CAN_MERGE;

            // 置空tmp_page
			pipe->tmp_page = NULL;

            // 向用户层的数据复制到buf中，在这个函数里会递减from->count的数量
			copied = copy_page_from_iter(page, 0, PAGE_SIZE, from);

            // 如果复制的数据量少于一页大小，但是from中还有数据，那肯定有问题，直接跳出循环
			if (unlikely(copied < PAGE_SIZE && iov_iter_count(from))) {
                // ret是已经复制的数据量，ret为0，表示是第一次就复制失败了
				if (!ret)
					ret = -EFAULT;
				break;
			}
            // 累加已经复制的数据
			ret += copied;
            // 重置offset
			buf->offset = 0;
            // 将buf的长度设为本次复制的数据量
			buf->len = copied;
            // 如果已经没有需要写的数据，则退出循环
			if (!iov_iter_count(from))
				break;
		}

		if (!pipe_full(head, pipe->tail, pipe->max_usage))
			continue;

		// 走到这儿，就是缓冲区已经满了

        // 如果读标志为不阻塞，则返回EAGAIN
		if (filp->f_flags & O_NONBLOCK) {
			if (!ret)
				ret = -EAGAIN;
			break;
		}

        // 如果有信号要处理，则先处理信号，再重启系统调用
		if (signal_pending(current)) {
			if (!ret)
				ret = -ERESTARTSYS;
			break;
		}

		__pipe_unlock(pipe);

        // 唤醒读者
		if (was_empty)
			wake_up_interruptible_sync_poll(&pipe->rd_wait, EPOLLIN | EPOLLRDNORM);

        // 发送POLL_IN
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);

        // 在wr_wait上等待，等待结束的条件是pipe可以写入
		wait_event_interruptible_exclusive(pipe->wr_wait, pipe_writable(pipe));

        // 被唤醒之后重新加锁
		__pipe_lock(pipe);
		was_empty = pipe_empty(pipe->head, pipe->tail);

        // 是否要唤醒下一个写者，走到这儿，因为有可写的空间了，所以先把它置为true
		wake_next_writer = true;
	}
out:

    // 如果缓冲区满了，则不再唤醒写者
	if (pipe_full(pipe->head, pipe->tail, pipe->max_usage))
		wake_next_writer = false;
	__pipe_unlock(pipe);

	// 发送POLLIN
	if (was_empty || pipe->poll_usage)
		wake_up_interruptible_sync_poll(&pipe->rd_wait, EPOLLIN | EPOLLRDNORM);
	kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);

    // 如果需要唤醒下一个写者，则唤醒在wr_wait等待的进程
	if (wake_next_writer)
		wake_up_interruptible_sync_poll(&pipe->wr_wait, EPOLLOUT | EPOLLWRNORM);

    // 更新文件的访问时间
	if (ret > 0 && sb_start_write_trylock(file_inode(filp)->i_sb)) {
		int err = file_update_time(filp);
		if (err)
			ret = err;
		sb_end_write(file_inode(filp)->i_sb);
	}
	return ret;
}
```

## pipe的释放
```c
static void put_pipe_info(struct inode *inode, struct pipe_inode_info *pipe)
{
	int kill = 0;

	spin_lock(&inode->i_lock);
	// 递减files的数量，如果为0，则在下面要释放
	if (!--pipe->files) {
		inode->i_pipe = NULL;
		kill = 1;
	}
	spin_unlock(&inode->i_lock);

	if (kill)
		free_pipe_info(pipe);
}

void free_pipe_info(struct pipe_inode_info *pipe)
{
	int i;

#ifdef CONFIG_WATCH_QUEUE
	if (pipe->watch_queue) {
		watch_queue_clear(pipe->watch_queue);
		put_watch_queue(pipe->watch_queue);
	}
#endif

	// 减少用户使用pipe缓冲区的数量，减少的数量是当前pipe的缓冲区数量
	(void) account_pipe_buffers(pipe->user, pipe->nr_accounted, 0);
	// 递减user引用
	free_uid(pipe->user);

	// 遍历pipe中的缓冲区，调用每个缓冲区的release方法
	for (i = 0; i < pipe->ring_size; i++) {
		struct pipe_buffer *buf = pipe->bufs + i;
		if (buf->ops)
			pipe_buf_release(pipe, buf);
	}
	// 如果有临时页，则释放页
	if (pipe->tmp_page)
		__free_page(pipe->tmp_page);
	
	// 释放bufs和pipe数据结构
	kfree(pipe->bufs);
	kfree(pipe);
}

// pipe_buf_release会直接调用buf->ops->release方法
// pipe默认是匿名页，匿名页对应的release是anon_pipe_buf_release
static void anon_pipe_buf_release(struct pipe_inode_info *pipe,
				  struct pipe_buffer *buf)
{
	struct page *page = buf->page;

	// 页的数量为1表示没有人使用这个页了，因为一递减就是0,
	// 如果pipe没有临时页的话，把这一页当做临时页
	if (page_count(page) == 1 && !pipe->tmp_page)
		pipe->tmp_page = page;
	else
		// 递减page的引用计数，如果使用量为0，则会释放
		put_page(page);
}
```