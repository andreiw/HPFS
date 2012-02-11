/*
  Host Profile Overlay FS
  Copyright (C) 2011 Andrei Warkentin <andreiw@vmware.com>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags --libs` -lulockmgr hpfs.c -o hpfs

  Using: ./hpfs ~/ $redir -o nonempty,allow_root
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
#include <syslog.h>
#include <fuse_opt.h>

struct hp_priv {
	int fd;
	int redir_fd;
} priv = {
	-1,
	-1
};

static int hp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	res = fstatat(fd, path, stbuf, AT_SYMLINK_NOFOLLOW);
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
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	res = faccessat(fd, path, mask, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	res = readlinkat(fd, path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

struct hp_dirp {
	DIR *dp;
	DIR *rdp;
	struct dirent *entry;
	off_t offset;
#define ROOT_DIR  1
#define REDIR_DIR 2
	int flags;
};

static int hp_opendir(const char *path, struct fuse_file_info *fi)
{
	int res;
	int dup_fd;
	int fd = priv.fd;
	struct hp_dirp *d = malloc(sizeof(struct hp_dirp));
	memset(d, 0, sizeof(*d));

	if (d == NULL)
		return -ENOMEM;

	if (*path == '/')
		path++;

	if (!*path) {
		path = ".";
		d->flags |= ROOT_DIR;

		dup_fd = dup(priv.redir_fd);
		if (dup_fd == -1) {
			res = -errno;
			free(d);
			return res;
		}
		d->rdp = fdopendir(dup_fd);
		if (!d->rdp) {
			res = -errno;
			close(dup_fd);
			free(d);
			return res;
		}
	} else if(*path == '.')
		fd = priv.redir_fd;
	
	fd = openat(fd, path, O_RDONLY | O_DIRECTORY);
	if (fd == -1) {
		syslog(LOG_ERR, "openat for %s failed\n", path);
		res = -errno;
		if (d->rdp)
			closedir(d->rdp);
		free(d);
		return res;
	}

	d->dp = fdopendir(fd);
	if (d->dp == NULL) {
		res = -errno;
		if (d->rdp)
			closedir(d->rdp);
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
	DIR *dp = d->dp;

	(void) path;
	if (offset != d->offset) {
		if (d->offset != 0) {
			syslog(LOG_ERR, "readdir() to non-consecutive offsets unsupported\n");
			return -EINVAL;
		}

		seekdir(d->dp, 0);
		d->entry = NULL;
		d->offset = 0;
	}
	while (1) {
		struct stat st;
		off_t nextoff;

		if (!d->entry) {
			d->entry = readdir(dp);
			if (!d->entry) {
				if (!(d->flags & ROOT_DIR) ||
					d->flags & REDIR_DIR)
					break;

				d->flags |= REDIR_DIR;
				dp = d->rdp;
				seekdir(dp, 0);
				continue;
			}
		}

		nextoff = telldir(dp);
		if (d->flags == ROOT_DIR &&
		    d->entry->d_name[0] == '.') {
			d->entry = NULL;
			continue;
		}

		memset(&st, 0, sizeof(st));
		st.st_ino = d->entry->d_ino;
		st.st_mode = d->entry->d_type << 12;
		if (filler(buf, d->entry->d_name, &st, nextoff))
			break;

		d->entry = NULL;
		d->offset = nextoff;
	}

	return 0;
}

static int hp_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct hp_dirp *d = get_dirp(fi);
	(void) path;

	closedir(d->dp);
	if (d->rdp)
		closedir(d->rdp);
	free(d);
	return 0;
}

static int hp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	if (S_ISFIFO(mode))
		res = mkfifoat(fd, path, mode);
	else
		res = mknodat(fd, path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_mkdir(const char *path, mode_t mode)
{
	int res;
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	res = mkdirat(fd, path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_unlink(const char *path)
{
	int res;
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	res = unlinkat(fd, path, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_rmdir(const char *path)
{
	int res;
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	res = unlinkat(fd, path, AT_REMOVEDIR);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_symlink(const char *from, const char *to)
{
	int res;
	int fd = priv.fd;

	if (*to == '/')
		to++;

	if (!*to)
		to = ".";
	else if(*to == '.')
		fd = priv.redir_fd;

	res = symlinkat(from, fd, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_rename(const char *from, const char *to)
{
	int res;
	int fd_from = priv.fd;
	int fd_to = priv.fd;

	if (*from == '/')
		from++;

	if (!*from)
		from = ".";
	else if (*from == '.')
		fd_from = priv.redir_fd;

	if (*to == '/')
		to++;

	if (!*to)
		to = ".";
	else if (*to == '.')
		fd_to = priv.redir_fd;

	res = renameat(fd_from, from,
		       fd_to, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_link(const char *from, const char *to)
{
	int res;
	int fd_from = priv.fd;
	int fd_to = priv.fd;

	if (*from == '/')
		from++;

	if (!*from)
		from = ".";
	else if (*from == '.')
		fd_from = priv.redir_fd;

	if (*to == '/')
		to++;

	if (!*to)
		to = ".";
	else if (*to == '.')
		fd_to = priv.redir_fd;

	res = linkat(fd_from, from,
		     fd_to, to, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_chmod(const char *path, mode_t mode)
{
	int res;
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	res = fchmodat(fd, path, mode, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	res = fchownat(fd, path, uid, gid, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_truncate(const char *path, off_t size)
{
	int res;
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	fd = openat(fd, path, O_WRONLY);
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
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	res = utimensat(fd, path, ts, 0);
	if (res == -1)
		return -errno;

	return 0;
}

static int hp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	fd = openat(fd, path, fi->flags, mode);
	if (fd == -1)
		return -errno;

	fi->fh = fd;
	return 0;
}

static int hp_open(const char *path, struct fuse_file_info *fi)
{
	int fd = priv.fd;

	if (*path == '/')
		path++;

	if (!*path)
		path = ".";
	else if(*path == '.')
		fd = priv.redir_fd;

	fd = openat(fd, path, fi->flags);
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

	res = fstatvfs(priv.fd, stbuf);
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

/*
 * No *at() variants available, so not implementable, yet.
 */

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
	DIR *dir;
	int i, res;
	char *error;
	struct passwd *passwd;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

	for(i = 0; i < argc; i++) {
		if (i == 2) {
			dir = opendir(argv[i]);
			if (!dir) {
				res = -errno;
				error = "dot redirect path invalid";
				goto err;
			}
			priv.redir_fd = dirfd(dir);
			if (priv.redir_fd == -1) {
				res = -errno;
			        error = "couldn't get fd for dot redirect path";
				goto err;
			}
		} else
			fuse_opt_add_arg(&args, argv[i]);
	}

	if (priv.redir_fd == -1) {
		error = "dot redirect path not passed";
		res = EINVAL;
		goto err;
	}

	passwd = getpwuid(getuid());
	if (!passwd) {
		res = -errno;
		error = "you don't exist, go away";
		goto err;
	}

	dir = opendir(passwd->pw_dir);
	if (!dir) {
		res = -errno;
		error = "you don't have a home directory";
		goto err;
	}
	priv.fd = dirfd(dir);
	if (priv.fd == -1) {
		res = -errno;
		error = "couldn't get fd for home directory";
		goto err;
	}

	openlog(argv[0], 0, LOG_USER);

	umask(0);
	return fuse_main(args.argc, args.argv, &hp_oper, NULL);
err:
	fprintf(stderr, "%s: %d\n", error, res);
	syslog(LOG_ERR, "%s: %d\n", error, res);
	return res;
}
