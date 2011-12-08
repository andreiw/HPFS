/*
  Host Profile Overlay FS
  Copyright (C) 2011 Andrei Warkentin <andreiw@vmware.com>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags --libs` -lulockmgr hpfs.c -o hpfs

  Using: ./hpfs -o allow_root ~/ -o nonempty
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse.h>
#include <ulockmgr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <dirent.h>
#include <sys/types.h>
#include <pwd.h>

struct hp_priv {
	int fd;
};

static int saved_home_fd = -1;

static int hp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	res = fstatat(priv->fd,
		      path, stbuf, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_fgetattr(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi)
{
	int res;

	(void) path;

	res = fstat(fi->fh, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_access(const char *path, int mask)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	res = faccessat(priv->fd, path, mask, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	res = readlinkat(priv->fd, path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

struct hp_dirp {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static int hp_opendir(const char *path, struct fuse_file_info *fi)
{
	int res;
	int fd;
	struct hp_dirp *d = malloc(sizeof(struct hp_dirp));
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (d == NULL)
		return -ENOMEM;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	
	fd = openat(priv->fd, path, O_RDONLY | O_DIRECTORY);
	if (fd == -1) {
		res = -errno;
		free(d);
		return res;
	}

	d->dp = fdopendir(fd);
	if (d->dp == NULL) {
		res = -errno;
		close(fd);
		free(d);
		return res;
	}
	d->offset = 0;
	d->entry = NULL;

	fi->fh = (unsigned long) d;
	return 0;
}

static inline struct hp_dirp *get_dirp(struct fuse_file_info *fi)
{
	return (struct hp_dirp *) (uintptr_t) fi->fh;
}

static int hp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	struct hp_dirp *d = get_dirp(fi);

	(void) path;
	if (offset != d->offset) {
		seekdir(d->dp, offset);
		d->entry = NULL;
		d->offset = offset;
	}
	while (1) {
		struct stat st;
		off_t nextoff;

		if (!d->entry) {
			d->entry = readdir(d->dp);
			if (!d->entry)
				break;
		}

		memset(&st, 0, sizeof(st));
		st.st_ino = d->entry->d_ino;
		st.st_mode = d->entry->d_type << 12;
		nextoff = telldir(d->dp);
		if (filler(buf, d->entry->d_name, &st, nextoff))
			break;

		d->entry = NULL;
		d->offset = nextoff;
	}

	return 0;
}

static int hp_releasedir(const char *path, struct fuse_file_info *fi)
{
	int fd;
	struct hp_dirp *d = get_dirp(fi);
	(void) path;

	fd = dirfd(d->dp);
	closedir(d->dp);
	close(fd);
	free(d);
	return 0;
}

static void *hp_init(struct fuse_conn_info *conn)
{
	struct hp_priv *priv;

	priv = malloc(sizeof(*priv));
	if (!priv)
		return NULL;

	priv->fd = saved_home_fd;
	return priv;
}

static void hp_destroy(void *data)
{
	struct hp_priv *priv = data;
	if (!priv)
		return;

	free(priv);
}

static int hp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	if (S_ISFIFO(mode))
		res = mkfifoat(priv->fd, path, mode);
	else
		res = mknodat(priv->fd, path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_mkdir(const char *path, mode_t mode)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	res = mkdirat(priv->fd, path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_unlink(const char *path)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	res = unlinkat(priv->fd, path, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_rmdir(const char *path)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	res = unlinkat(priv->fd, path, AT_REMOVEDIR);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_symlink(const char *from, const char *to)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*from == '/')
		from++;

	if (!*from)
		from = ".";

	if (*to == '/')
		to++;

	if (!*to)
		to = ".";

	res = symlinkat(from, priv->fd, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_rename(const char *from, const char *to)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*from == '/')
		from++;

	if (!*from)
		from = ".";

	if (*to == '/')
		to++;

	if (!*to)
		to = ".";

	res = renameat(priv->fd, from,
		       priv->fd, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_link(const char *from, const char *to)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*from == '/')
		from++;

	if (!*from)
		from = ".";

	if (*to == '/')
		to++;

	if (!*to)
		to = ".";

	res = linkat(priv->fd, from,
		     priv->fd, to, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_chmod(const char *path, mode_t mode)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	res = fchmodat(priv->fd, path, mode, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	res = fchownat(priv->fd, path, uid, gid, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_truncate(const char *path, off_t size)
{
	int res;
	int fd;

	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	fd = openat(priv->fd, path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = ftruncate(fd, size);
	if (res == -1) {
		res = -errno;
		close(fd);
		return res;
	}

	close(fd);
	return 0;
}

static int hp_ftruncate(const char *path, off_t size,
			 struct fuse_file_info *fi)
{
	int res;

	(void) path;

	res = ftruncate(fi->fh, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	res = utimensat(priv->fd, path, ts, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	fd = openat(priv->fd, path, fi->flags, mode);
	if (fd == -1)
		return -errno;

	fi->fh = fd;
	return 0;
}

static int hp_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";

	fd = openat(priv->fd, path, fi->flags);
	if (fd == -1)
		return -errno;

	fi->fh = fd;
	return 0;
}

static int hp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int res;

	(void) path;
	res = pread(fi->fh, buf, size, offset);
	if (res == -1)
		res = -errno;

	return res;
}

static int hp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res;

	(void) path;
	res = pwrite(fi->fh, buf, size, offset);
	if (res == -1)
		res = -errno;

	return res;
}

static int hp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	struct fuse_context *context = fuse_get_context();
	struct hp_priv *priv = context->private_data;

	if (!priv)
		return -ENXIO;

	res = fstatvfs(priv->fd, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_flush(const char *path, struct fuse_file_info *fi)
{
	int res;

	(void) path;
	/* This is called from every close on an open file, so call the
	   close on the underlying filesystem.	But since flush may be
	   called multiple times for an open file, this must not really
	   close the file.  This is important if used on a network
	   filesystem like NFS which flush the data/metadata on close() */
	res = close(dup(fi->fh));
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	close(fi->fh);

	return 0;
}

static int hp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	int res;
	(void) path;

#ifndef HAVE_FDATASYNC
	(void) isdatasync;
#else
	if (isdatasync)
		res = fdatasync(fi->fh);
	else
#endif
		res = fsync(fi->fh);
	if (res == -1)
		return -errno;

	return 0;
}

#if 0
#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int hp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int hp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int hp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int hp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */
#endif

static int hp_lock(const char *path, struct fuse_file_info *fi, int cmd,
		    struct flock *lock)
{
	(void) path;

	return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
			   sizeof(fi->lock_owner));
}

static struct fuse_operations hp_oper = {
	.getattr	= hp_getattr,
	.fgetattr	= hp_fgetattr,
	.access		= hp_access,
	.readlink	= hp_readlink,
	.opendir	= hp_opendir,
	.readdir	= hp_readdir,
	.releasedir	= hp_releasedir,
	.init		= hp_init,
	.destroy	= hp_destroy,
	.mknod		= hp_mknod,
	.mkdir		= hp_mkdir,
	.symlink	= hp_symlink,
	.unlink		= hp_unlink,
	.rmdir		= hp_rmdir,
	.rename		= hp_rename,
	.link		= hp_link,
	.chmod		= hp_chmod,
	.chown		= hp_chown,
	.truncate	= hp_truncate,
	.ftruncate	= hp_ftruncate,
	.utimens	= hp_utimens,
	.create		= hp_create,
	.open		= hp_open,
	.read		= hp_read,
	.write		= hp_write,
	.statfs		= hp_statfs,
	.flush		= hp_flush,
	.release	= hp_release,
	.fsync		= hp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= hp_setxattr,
	.getxattr	= hp_getxattr,
	.listxattr	= hp_listxattr,
	.removexattr	= hp_removexattr,
#endif
	.lock		= hp_lock,

	.flag_nullpath_ok = 1,
};

int main(int argc, char *argv[])
{
	struct passwd *passwd;
	DIR *dir;

	passwd = getpwuid(getuid());
	if (!passwd)
		return -errno;

	dir = opendir(passwd->pw_dir);
	if (!dir)
		return -errno;
	saved_home_fd = dirfd(dir);
	if (saved_home_fd == -1)
		return -errno;

	umask(0);
	return fuse_main(argc, argv, &hp_oper, NULL);
}
