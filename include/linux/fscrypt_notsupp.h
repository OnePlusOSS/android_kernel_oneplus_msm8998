/*
 * fscrypt_notsupp.h
 *
 * This stubs out the fscrypt functions for filesystems configured without
 * encryption support.
 */

#ifndef _LINUX_FSCRYPT_NOTSUPP_H
#define _LINUX_FSCRYPT_NOTSUPP_H

#include <linux/fscrypt_common.h>

/* crypto.c */
static inline struct fscrypt_ctx *fscrypt_get_ctx(const struct inode *inode,
						  gfp_t gfp_flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void fscrypt_release_ctx(struct fscrypt_ctx *ctx)
{
	return;
}

static inline struct page *fscrypt_encrypt_page(const struct inode *inode,
						struct page *page,
						unsigned int len,
						unsigned int offs,
						u64 lblk_num, gfp_t gfp_flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int fscrypt_decrypt_page(const struct inode *inode,
				       struct page *page,
				       unsigned int len, unsigned int offs,
				       u64 lblk_num)
{
	return -EOPNOTSUPP;
}


static inline void fscrypt_restore_control_page(struct page *page)
{
	return;
}

static inline void fscrypt_set_d_op(struct dentry *dentry)
{
	return;
}

static inline void fscrypt_set_encrypted_dentry(struct dentry *dentry)
{
	return;
}

/* policy.c */
static inline int fscrypt_ioctl_set_policy(struct file *filp,
					   const void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_ioctl_get_policy(struct file *filp, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_has_permitted_context(struct inode *parent,
						struct inode *child)
{
	return 0;
}

static inline int fscrypt_inherit_context(struct inode *parent,
					  struct inode *child,
					  void *fs_data, bool preload)
{
	return -EOPNOTSUPP;
}

/* keyinfo.c */
static inline int fscrypt_get_encryption_info(struct inode *inode)
{
	return -EOPNOTSUPP;
}

static inline void fscrypt_put_encryption_info(struct inode *inode,
					       struct fscrypt_info *ci)
{
	return;
}

 /* fname.c */
static inline int fscrypt_setup_filename(struct inode *dir,
					 const struct qstr *iname,
					 int lookup, struct fscrypt_name *fname)
{
	if (dir->i_sb->s_cop->is_encrypted(dir))
		return -EOPNOTSUPP;

	memset(fname, 0, sizeof(struct fscrypt_name));
	fname->usr_fname = iname;
	fname->disk_name.name = (unsigned char *)iname->name;
	fname->disk_name.len = iname->len;
	return 0;
}

static inline void fscrypt_free_filename(struct fscrypt_name *fname)
{
	return;
}

static inline u32 fscrypt_fname_encrypted_size(const struct inode *inode,
					       u32 ilen)
{
	/* never happens */
	WARN_ON(1);
	return 0;
}

static inline int fscrypt_fname_alloc_buffer(const struct inode *inode,
					     u32 ilen,
					     struct fscrypt_str *crypto_str)
{
	return -EOPNOTSUPP;
}

static inline void fscrypt_fname_free_buffer(struct fscrypt_str *crypto_str)
{
	return;
}

static inline int fscrypt_fname_disk_to_usr(struct inode *inode,
					    u32 hash, u32 minor_hash,
					    const struct fscrypt_str *iname,
					    struct fscrypt_str *oname)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_fname_usr_to_disk(struct inode *inode,
					    const struct qstr *iname,
					    struct fscrypt_str *oname)
{
	return -EOPNOTSUPP;
}

static inline bool fscrypt_match_name(const struct fscrypt_name *fname,
				      const u8 *de_name, u32 de_name_len)
{
	/* Encryption support disabled; use standard comparison */
	if (de_name_len != fname->disk_name.len)
		return false;
	return !memcmp(de_name, fname->disk_name.name, fname->disk_name.len);
}

/* bio.c */
static inline void fscrypt_decrypt_bio_pages(struct fscrypt_ctx *ctx,
					     struct bio *bio)
{
	return;
}

static inline void fscrypt_pullback_bio_page(struct page **page, bool restore)
{
	return;
}

static inline int fscrypt_zeroout_range(const struct inode *inode, pgoff_t lblk,
					sector_t pblk, unsigned int len)
{
	return -EOPNOTSUPP;
}

#endif	/* _LINUX_FSCRYPT_NOTSUPP_H */
