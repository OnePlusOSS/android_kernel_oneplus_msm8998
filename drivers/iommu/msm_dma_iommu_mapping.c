// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/dma-buf.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/rbtree.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/barrier.h>

/**
 * struct msm_iommu_map - represents a mapping of an ion buffer to an iommu
 * @lnode - List node to exist in the buffer's list of iommu mappings.
 * @dev - Device this is mapped to. Used as key.
 * @sgl - The scatterlist for this mapping.
 * @nents - Number of entries in sgl.
 * @dir - The direction for the unmap.
 * @meta - Backpointer to the meta this guy belongs to.
 * @ref - For reference counting this mapping.
 *
 * Represents a mapping of one dma_buf buffer to a particular device and address
 * range. There may exist other mappings of this buffer in different devices.
 * All mappings have the same cacheability and security.
 */
struct msm_iommu_map {
	struct list_head lnode;
	struct device *dev;
	struct scatterlist sgl;
	unsigned int nents;
	enum dma_data_direction dir;
	struct msm_iommu_meta *meta;
	struct kref ref;
};

struct msm_iommu_meta {
	struct rb_node node;
	struct list_head maps;
	struct kref ref;
	struct mutex map_lock;
	rwlock_t lock;
	void *buffer;
};

static struct rb_root iommu_root;
static DEFINE_RWLOCK(rb_tree_lock);

static void msm_iommu_meta_add(struct msm_iommu_meta *meta)
{
	struct rb_root *root = &iommu_root;
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct msm_iommu_meta *entry;

	write_lock(&rb_tree_lock);
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, typeof(*entry), node);
		if (meta->buffer < entry->buffer)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	rb_link_node(&meta->node, parent, p);
	rb_insert_color(&meta->node, root);
	write_unlock(&rb_tree_lock);
}

static struct msm_iommu_meta *msm_iommu_meta_lookup_get(void *buffer)
{
	struct rb_root *root = &iommu_root;
	struct rb_node **p = &root->rb_node;
	struct msm_iommu_meta *entry;

	read_lock(&rb_tree_lock);
	while (*p) {
		entry = rb_entry(*p, typeof(*entry), node);
		if (buffer < entry->buffer) {
			p = &(*p)->rb_left;
		} else if (buffer > entry->buffer) {
			p = &(*p)->rb_right;
		} else {
			kref_get(&entry->ref);
			read_unlock(&rb_tree_lock);
			return entry;
		}
	}
	read_unlock(&rb_tree_lock);

	return NULL;
}

static void msm_iommu_add(struct msm_iommu_meta *meta,
			  struct msm_iommu_map *map)
{
	write_lock(&meta->lock);
	list_add(&map->lnode, &meta->maps);
	write_unlock(&meta->lock);
}

static struct msm_iommu_map *msm_iommu_lookup_get(struct msm_iommu_meta *meta,
						  struct device *dev)
{
	struct msm_iommu_map *entry;

	read_lock(&meta->lock);
	list_for_each_entry(entry, &meta->maps, lnode) {
		if (entry->dev == dev) {
			kref_get(&entry->ref);
			read_unlock(&meta->lock);
			return entry;
		}
	}
	read_unlock(&meta->lock);

	return NULL;
}

static void msm_iommu_meta_destroy(struct kref *kref)
{
	struct msm_iommu_meta *meta = container_of(kref, typeof(*meta), ref);
	struct rb_root *root = &iommu_root;

	write_lock(&rb_tree_lock);
	rb_erase(&meta->node, root);
	write_unlock(&rb_tree_lock);

	kfree(meta);
}

static void msm_iommu_map_destroy(struct kref *kref)
{
	struct msm_iommu_map *map = container_of(kref, typeof(*map), ref);
	struct msm_iommu_meta *meta = map->meta;

	write_lock(&meta->lock);
	list_del(&map->lnode);
	write_unlock(&meta->lock);

	mutex_lock(&meta->map_lock);
	dma_unmap_sg(map->dev, &map->sgl, map->nents, map->dir);
	mutex_unlock(&meta->map_lock);

	kfree(map);
}

static void msm_iommu_map_destroy_noop(struct kref *kref)
{
	/* For when we need to unmap on our own terms */
}

static struct msm_iommu_meta *msm_iommu_meta_create(struct dma_buf *dma_buf)
{
	struct msm_iommu_meta *meta;

	meta = kmalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return NULL;

	meta->buffer = dma_buf->priv;
	kref_init(&meta->ref);
	mutex_init(&meta->map_lock);
	rwlock_init(&meta->lock);
	INIT_LIST_HEAD(&meta->maps);
	msm_iommu_meta_add(meta);

	return meta;
}

static int __msm_dma_map_sg(struct device *dev, struct scatterlist *sg,
			    int nents, enum dma_data_direction dir,
			    struct dma_buf *dma_buf, struct dma_attrs *attrs)
{
	bool late_unmap = !dma_get_attr(DMA_ATTR_NO_DELAYED_UNMAP, attrs);
	bool extra_meta_ref_taken = false;
	struct msm_iommu_meta *meta;
	struct msm_iommu_map *map;
	int ret;

	meta = msm_iommu_meta_lookup_get(dma_buf->priv);
	if (!meta) {
		meta = msm_iommu_meta_create(dma_buf);
		if (!meta)
			return -ENOMEM;

		if (late_unmap) {
			kref_get(&meta->ref);
			extra_meta_ref_taken = true;
		}
	}

	map = msm_iommu_lookup_get(meta, dev);
	if (map) {
		sg->dma_address = map->sgl.dma_address;
		sg->dma_length = map->sgl.dma_length;

		/*
		 * Ensure all outstanding changes for coherent buffers are
		 * applied to the cache before any DMA occurs.
		 */
		if (is_device_dma_coherent(dev))
			dmb(ish);
	} else {
		map = kmalloc(sizeof(*map), GFP_KERNEL);
		if (!map) {
			ret = -ENOMEM;
			goto release_meta;
		}

		mutex_lock(&meta->map_lock);
		ret = dma_map_sg_attrs(dev, sg, nents, dir, attrs);
		mutex_unlock(&meta->map_lock);
		if (ret != nents) {
			kfree(map);
			goto release_meta;
		}

		kref_init(&map->ref);
		if (late_unmap)
			kref_get(&map->ref);

		map->meta = meta;
		map->sgl.dma_address = sg->dma_address;
		map->sgl.dma_length = sg->dma_length;
		map->dev = dev;
		map->nents = nents;
		map->sgl.page_link = sg->page_link;
		map->sgl.offset = sg->offset;
		map->sgl.length = sg->length;
		INIT_LIST_HEAD(&map->lnode);
		msm_iommu_add(meta, map);
	}

	return nents;

release_meta:
	if (extra_meta_ref_taken)
		kref_put(&meta->ref, msm_iommu_meta_destroy);
	kref_put(&meta->ref, msm_iommu_meta_destroy);
	return ret;
}

/*
 * We are not taking a reference to the dma_buf here. It is expected that
 * clients hold reference to the dma_buf until they are done with mapping and
 * unmapping.
 */
int msm_dma_map_sg_attrs(struct device *dev, struct scatterlist *sg, int nents,
			 enum dma_data_direction dir, struct dma_buf *dma_buf,
			 struct dma_attrs *attrs)
{
	if (IS_ERR_OR_NULL(dev)) {
		pr_err("%s: dev pointer is invalid\n", __func__);
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(sg)) {
		pr_err("%s: sg table pointer is invalid\n", __func__);
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(dma_buf)) {
		pr_err("%s: dma_buf pointer is invalid\n", __func__);
		return -EINVAL;
	}

	return __msm_dma_map_sg(dev, sg, nents, dir, dma_buf, attrs);
}
EXPORT_SYMBOL(msm_dma_map_sg_attrs);

void msm_dma_unmap_sg(struct device *dev, struct scatterlist *sgl, int nents,
		      enum dma_data_direction dir, struct dma_buf *dma_buf)
{
	struct msm_iommu_meta *meta;
	struct msm_iommu_map *map;

	meta = msm_iommu_meta_lookup_get(dma_buf->priv);
	if (!meta)
		return;

	map = msm_iommu_lookup_get(meta, dev);
	if (!map) {
		kref_put(&meta->ref, msm_iommu_meta_destroy);
		return;
	}

	/*
	 * Save direction for later use when we actually unmap. Not used right
	 * now but in the future if we go to coherent mapping API we might want
	 * to call the appropriate API when client asks to unmap.
	 */
	map->dir = dir;

	/* Do an extra put to undo msm_iommu_lookup_get */
	kref_put(&map->ref, msm_iommu_map_destroy);
	kref_put(&map->ref, msm_iommu_map_destroy);

	/* Do an extra put to undo msm_iommu_meta_lookup_get */
	kref_put(&meta->ref, msm_iommu_meta_destroy);
	kref_put(&meta->ref, msm_iommu_meta_destroy);
}
EXPORT_SYMBOL(msm_dma_unmap_sg);

static void msm_dma_unmap_list(struct list_head *unmap_list)
{
	struct msm_iommu_map *map, *map_next;
	struct msm_iommu_meta *meta;
	LIST_HEAD(kfree_list);

	while (!list_empty(unmap_list)) {
		meta = list_first_entry(unmap_list, typeof(*map), lnode)->meta;
		mutex_lock(&meta->map_lock);
		list_for_each_entry_safe(map, map_next, unmap_list, lnode) {
			if (map->meta != meta)
				break;
			dma_unmap_sg(map->dev, &map->sgl, map->nents, map->dir);
			list_move_tail(&map->lnode, &kfree_list);
		}
		mutex_unlock(&meta->map_lock);
	}

	list_for_each_entry_safe(map, map_next, &kfree_list, lnode)
		kfree(map);
}

int msm_dma_unmap_all_for_dev(struct device *dev)
{
	struct msm_iommu_map *map, *map_next;
	struct rb_root *root = &iommu_root;
	struct msm_iommu_meta *meta;
	struct rb_node *meta_node;
	LIST_HEAD(unmap_list);
	int ret = 0;

	read_lock(&rb_tree_lock);
	meta_node = rb_first(root);
	while (meta_node) {
		meta = rb_entry(meta_node, typeof(*meta), node);
		write_lock(&meta->lock);
		list_for_each_entry_safe(map, map_next, &meta->maps, lnode) {
			if (map->dev != dev)
				continue;

			/* Do the actual unmapping outside of the locks */
			if (kref_put(&map->ref, msm_iommu_map_destroy_noop))
				list_move_tail(&map->lnode, &unmap_list);
			else
				ret = -EINVAL;
		}
		write_unlock(&meta->lock);
		meta_node = rb_next(meta_node);
	}
	read_unlock(&rb_tree_lock);

	msm_dma_unmap_list(&unmap_list);

	return ret;
}
EXPORT_SYMBOL(msm_dma_unmap_all_for_dev);

/* Only to be called by ION code when a buffer is freed */
void msm_dma_buf_freed(void *buffer)
{
	struct msm_iommu_map *map, *map_next;
	struct msm_iommu_meta *meta;
	LIST_HEAD(unmap_list);

	meta = msm_iommu_meta_lookup_get(buffer);
	if (!meta)
		return;

	write_lock(&meta->lock);
	list_for_each_entry_safe(map, map_next, &meta->maps, lnode) {
		/* Do the actual unmapping outside of the lock */
		if (kref_put(&map->ref, msm_iommu_map_destroy_noop))
			list_move_tail(&map->lnode, &unmap_list);
	}
	write_unlock(&meta->lock);

	msm_dma_unmap_list(&unmap_list);

	/* Do an extra put to undo msm_iommu_meta_lookup_get */
	kref_put(&meta->ref, msm_iommu_meta_destroy);
	kref_put(&meta->ref, msm_iommu_meta_destroy);
}
