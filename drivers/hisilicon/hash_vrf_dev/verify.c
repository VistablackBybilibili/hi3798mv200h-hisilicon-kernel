/******************************************************************************
 *    COPYRIGHT (C) 2013 Hisilicon
 *    All rights reserved.
 * ***
 *    Create by wangjian 2016-04
 *
******************************************************************************/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <asm/sizes.h>
#include <linux/reboot.h>
#include <linux/suspend.h>
#include <linux/delay.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/syscalls.h>
#include <linux/dma-mapping.h>
#include <asm/setup.h>


#define VERBLOCK_SIZE        0x200
#define HASG_LEN             32
#define HAS_PART             "shatable"
#define VERIFY_BLOCK_NAME    "verify-block"
#define VERIFY_BLOCK_COUNT   1
#define TOUSY

extern unsigned char g_swpk_iv[16];
extern int drv_fs_verify_decrypt(unsigned int buf_address, unsigned int length, unsigned char *swpk_iv, unsigned int swpk_iv_length);
extern int pdm_get_hashtable(u32 *phyaddr, u32 *size);
extern char *PDM_VmapByPhyaddr(u8 *phy_addr, u32 size);
extern int drv_fs_verify_init(void);

/******************************************************************************/

struct verify_block_device {
	int idx;
	char hhfile_name[64];
	char blkdev_name[64];
	char blkname[32];
	char verify_tmp[HASG_LEN];
	char hash_tmp[HASG_LEN];
	char blkdev_num;

	struct gendisk *gd;
	spinlock_t queue_lock;
	struct request_queue *queue;
	struct mutex dev_mutex;

	struct request_queue *rq;
	struct workqueue_struct *wq;
	struct work_struct work;

	struct file *blkdev_file;
	unsigned char      *blkdev_hash;
	unsigned int hash_length;

	void      *dma_vaddr;
	dma_addr_t dma_paddr;

	int refcnt;
};


static int vblk_dev_major = 0;
static struct verify_block_device verify_block_devices[VERIFY_BLOCK_COUNT];
/******************************************************************************/

#ifndef MODULE
static int part_find_num(char *name)
{
	char * b = NULL;
	char * tmp = NULL;
	char * blkdevparts = NULL;
	char buffer[256];
	int num = 0;

	blkdevparts = strstr(boot_command_line, "mtdparts");
	memset(buffer,0,sizeof(buffer));
	memcpy(buffer,blkdevparts,sizeof(buffer));
	b = strim(buffer);
	while (b) {
		tmp = strsep(&b, ",");
		if (!tmp)
			continue;
		if(strstr(tmp,name))
			break;
		num++;
	}
	return num ;
}
/******************************************************************************/
// vmxfy=rootfs:hastable

static int __init early_verify_paramter(char *p)
{
	int i;
	char * b = NULL;
	char * tmp_buf = NULL;
	char buffer[128];
	memset(buffer,0,sizeof(buffer));
	memcpy(buffer,p,sizeof(buffer));
	b = strim(buffer);

	for (i = 0; i < VERIFY_BLOCK_COUNT ; i++) {
		tmp_buf = strsep(&b, ":,");
		if(!tmp_buf)
			continue ;
		verify_block_devices[i].blkdev_num = part_find_num(tmp_buf);
		sprintf(verify_block_devices[i].blkdev_name,"/dev/romblock%d",verify_block_devices[i].blkdev_num);
		sprintf(verify_block_devices[i].blkname,"%s",tmp_buf);
		tmp_buf = strsep(&b, ":,");
		if(!tmp_buf)
			continue ;
		sprintf(verify_block_devices[i].hhfile_name,"%s",tmp_buf);
	}
	return 0;
}
early_param("vmxfy", early_verify_paramter);
#endif
/******************************************************************************/

static int vblk_dev_open(struct block_device *bdev, fmode_t mode)
{
	int ret;
	loff_t size;
	u32 devnum;
	struct file *blkdev_file = NULL;
	struct block_device *src_bdev = NULL;
	struct verify_block_device *vbdev = bdev->bd_disk->private_data;

	mutex_lock(&vbdev->dev_mutex);
	if (vbdev->refcnt > 0)
		goto out_done;

	drv_fs_verify_init();

	devnum = 0xf000000 | vbdev->blkdev_num;
	sys_unlink(vbdev->blkdev_name);
	sys_mknod(vbdev->blkdev_name, S_IFBLK|0600, new_encode_dev(devnum));

	blkdev_file = filp_open(vbdev->blkdev_name, O_RDONLY | O_LARGEFILE, 0600);
	if (IS_ERR(blkdev_file)) {
		pr_err("can't open block device '%s'.\n", vbdev->blkdev_name);
		ret = -ENODEV;
		goto out_unlock;
	}

	if (!(blkdev_file->f_mode & FMODE_READ)) {
		filp_close(blkdev_file, NULL);
		pr_err("block device '%s' is not readable.\n", vbdev->blkdev_name);
		ret = -EPERM;
		goto out_unlock;
	}
	vbdev->blkdev_file = blkdev_file;
	src_bdev = blkdev_file->private_data;
	size = i_size_read(blkdev_file->f_mapping->host) >> 9;
	set_capacity(vbdev->gd, size);

out_done:
	vbdev->refcnt++;
	mutex_unlock(&vbdev->dev_mutex);
	return 0;

out_unlock:
	mutex_unlock(&vbdev->dev_mutex);
	return ret;
}
/******************************************************************************/

static void vblk_dev_release(struct gendisk *gd, fmode_t mode)
{
	struct verify_block_device *vbdev = gd->private_data;

	mutex_lock(&vbdev->dev_mutex);
	vbdev->refcnt--;
	if (vbdev->refcnt == 0) {
		filp_close(vbdev->blkdev_file, NULL);
	}
	mutex_unlock(&vbdev->dev_mutex);
}
/******************************************************************************/

static int vblk_dev_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	geo->heads = 1;
	geo->cylinders = 1;
	geo->sectors = get_capacity(bdev->bd_disk);
	geo->start = 0;
	return 0;
}
/******************************************************************************/

static const struct block_device_operations vblk_dev_ops = {
	.owner = THIS_MODULE,
	.open = vblk_dev_open,
	.release = vblk_dev_release,
	.getgeo = vblk_dev_getgeo,
};
/******************************************************************************/

static void vblk_dev_request(struct request_queue *rq)
{
	struct verify_block_device *vbdev = NULL;
	struct request *req = NULL;

	vbdev = rq->queuedata;

	if (!vbdev)
		while ((req = blk_fetch_request(rq)) != NULL)
			__blk_end_request_all(req, -ENODEV);
	else
		queue_work(vbdev->wq, &vbdev->work);
}
/******************************************************************************/

static char string_to_num(char a)
{
	return (a>0x60)?(a-0x57):(a-0x30);
}
/******************************************************************************/

static char __maybe_unused compose_num(char a,char b)
{
	a = string_to_num(a) ;
	b = string_to_num(b) ;
	return ((0xf0 & (a<<4))| (0x0f & b));
}
/******************************************************************************/
bool verify_key_right(struct verify_block_device *vbdev  ,unsigned char *hash ,u64 off)
{
	int i;
	memcpy(vbdev->verify_tmp,  vbdev->blkdev_hash + (off<<5), HASG_LEN);
	if(memcmp(vbdev->verify_tmp,hash,HASG_LEN)) {
		pr_err("tmp=  ");
		for(i=0;i<HASG_LEN;i++)
			pr_err("%.2x",vbdev->verify_tmp[i]);
		pr_err("\nhash= ");
		for(i=0;i<HASG_LEN;i++)
			pr_err("%.2x",hash[i]);
		pr_err("\n");
		return false ;
	} else {
		return true ;
	}
}
/******************************************************************************/

static int sha256_string(char *buf,unsigned char *hash)
{
	int ret;
	struct crypto_hash *tfm = NULL;
	struct hash_desc desc;
	struct scatterlist sg;
	tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		pr_err("Failed to load transform for sha256 \n");
		return -1;
	}
	desc.tfm = tfm;
	desc.flags = 0;
	ret = crypto_hash_init(&desc);
	if (ret) {
		pr_err("hash init fail.\n");
		return -1;
	}
	sg_init_one(&sg, buf, VERBLOCK_SIZE);
	crypto_hash_digest(&desc, &sg, VERBLOCK_SIZE, hash);
	crypto_free_hash(tfm);

	return 0;
}
/******************************************************************************/

static int vblk_read(struct verify_block_device *vbdev, char *buffer,
		     sector_t sec, int len)
{
	int i;
	char *buffer_tmp =  buffer;
	char buffer_swpk[VERBLOCK_SIZE];
	unsigned char *swpk_iv = NULL;
	u64 pos = sec << 9;
	kernel_read(vbdev->blkdev_file, pos, buffer, len);
	if(len == 0)
		return 0;

	if (sec == 0)
		swpk_iv = g_swpk_iv;
	else {
		kernel_read(vbdev->blkdev_file, (sec-1) << 9, buffer_swpk, VERBLOCK_SIZE);
		swpk_iv = buffer_swpk + VERBLOCK_SIZE -16;
	}

	for(i=0; i<(len>>9); i++) {
		memcpy(vbdev->dma_vaddr, buffer_tmp, VERBLOCK_SIZE);
		if(0 != drv_fs_verify_decrypt(vbdev->dma_paddr, VERBLOCK_SIZE, swpk_iv, 16)) {
			pr_err("decrypt_block error %d , system reboot ... !\n", i);
			kernel_restart(NULL);
			return -1;
		}

		memcpy(buffer_swpk, buffer_tmp, VERBLOCK_SIZE);
		swpk_iv = buffer_swpk + VERBLOCK_SIZE -16;
		memcpy(buffer_tmp, vbdev->dma_vaddr, VERBLOCK_SIZE);

		buffer_tmp += VERBLOCK_SIZE;

	}

	buffer_tmp =  buffer;
	for(i=0; i<(len>>9); i++) {
		sha256_string(buffer_tmp, vbdev->hash_tmp);
		buffer_tmp += VERBLOCK_SIZE;
		if(false == verify_key_right(vbdev,vbdev->hash_tmp,(sec + i))) {
			pr_err("verify key error , system reboot ... !\n");
			kernel_restart(NULL);
			return -1;
		}
	}

	return 0;
}
/******************************************************************************/

static int do_verify_block_request(struct verify_block_device *vbdev,
				   struct request *req)
{
	int len, ret;
	sector_t sec;

	if (req->cmd_type != REQ_TYPE_FS)
		return -EIO;

	if (blk_rq_pos(req) + blk_rq_cur_sectors(req) >
	    get_capacity(req->rq_disk))
		return -EIO;

	if (rq_data_dir(req) != READ)
		return -ENOSYS;

	sec = blk_rq_pos(req);
	len = blk_rq_cur_bytes(req);

	mutex_lock(&vbdev->dev_mutex);
	ret = vblk_read(vbdev, bio_data(req->bio), sec, len);
	mutex_unlock(&vbdev->dev_mutex);

	return ret;
}
/******************************************************************************/

static void vblk_dev_do_work(struct work_struct *work)
{
	struct verify_block_device *vbdev =
		container_of(work, struct verify_block_device, work);
	struct request_queue *rq = vbdev->rq;
	struct request *req = NULL;
	int res;

	spin_lock_irq(rq->queue_lock);

	req = blk_fetch_request(rq);
	while (req) {
		spin_unlock_irq(rq->queue_lock);
		res = do_verify_block_request(vbdev, req);
		spin_lock_irq(rq->queue_lock);
		if (!__blk_end_request_cur(req, res))
			req = blk_fetch_request(rq);
	}

	spin_unlock_irq(rq->queue_lock);
}
/******************************************************************************/

int vblk_dev_create(struct verify_block_device *vbdev, int idx)
{
	int ret;
	struct gendisk *gd = NULL;
	u32 hash_addr, hash_length;

	mutex_init(&vbdev->dev_mutex);

	gd = alloc_disk(1);
	if (!gd) {
		pr_err("alloc_disk failed");
		return -ENODEV;
	}

	gd->fops = &vblk_dev_ops;
	gd->major = vblk_dev_major;
	gd->first_minor = idx;
	gd->private_data = vbdev;

	set_capacity(gd, VERBLOCK_SIZE);

	snprintf(gd->disk_name, sizeof(gd->disk_name), "verify_%s", vbdev->blkname);
	vbdev->gd = gd;

	spin_lock_init(&vbdev->queue_lock);
	vbdev->rq = blk_init_queue(vblk_dev_request, &vbdev->queue_lock);
	if (!vbdev->rq) {
		pr_err("blk_init_queue failed.\n");
		ret = -ENODEV;
		goto out_put_disk;
	}

	vbdev->rq->queuedata = vbdev;
	vbdev->gd->queue = vbdev->rq;

	vbdev->wq = alloc_workqueue("%s", 0, 0, gd->disk_name);
	if (!vbdev->wq) {
		pr_err("alloc_workqueue failed.\n");
		ret = -ENOMEM;
		goto out_free_queue;
	}
	INIT_WORK(&vbdev->work, vblk_dev_do_work);

	vbdev->dma_vaddr = dma_alloc_coherent(NULL, PAGE_SIZE,
		&vbdev->dma_paddr, GFP_KERNEL);
	if (!vbdev->dma_vaddr) {
		printk(KERN_ERR "dma_alloc_coherent fail.\n");
		ret = -ENOMEM;
		goto out_free_queue;
	}

	pdm_get_hashtable(&hash_addr, &hash_length);
	vbdev->blkdev_hash = PDM_VmapByPhyaddr((u8 *)hash_addr, hash_length);
	vbdev->hash_length = hash_length;

	add_disk(vbdev->gd);

	pr_info("created verify block %s from %s\n",
		gd->disk_name, vbdev->blkdev_name);

	return 0;

out_free_queue:
	blk_cleanup_queue(vbdev->rq);
out_put_disk:
	put_disk(vbdev->gd);

	vbdev->gd = NULL;

	return ret;
}
/******************************************************************************/

static void verify_block_remove_all(void)
{
	int i;

	for (i = 0; i < VERIFY_BLOCK_COUNT; i++) {
		struct verify_block_device *vbdev = &verify_block_devices[i];

		if (!vbdev->blkdev_name)
			break;

		destroy_workqueue(vbdev->wq);

		del_gendisk(vbdev->gd);
		blk_cleanup_queue(vbdev->rq);

		pr_info("%s released\n", vbdev->gd->disk_name);

		put_disk(vbdev->gd);
		vfree(vbdev->blkdev_name);
	}
}
/******************************************************************************/

static int __init vblk_device_init(void)
{
	int i, ret;

	vblk_dev_major = register_blkdev(0, VERIFY_BLOCK_NAME);
	if (vblk_dev_major < 0)
		return -ENODEV;

	for (i = 0; i < VERIFY_BLOCK_COUNT; i++) {
		struct verify_block_device *vbdev = &verify_block_devices[i];

		if (0 == strlen(vbdev->blkdev_name))
			break;

		ret = vblk_dev_create(vbdev, i);
		if (ret) {
			pr_err("can't create '%s' verify block, err=%d\n",
			       vbdev->blkdev_name, ret);
			goto err_uncreate;
		}
	}

	return 0;

err_uncreate:
	unregister_blkdev(vblk_dev_major, VERIFY_BLOCK_NAME);
	verify_block_remove_all();

	return ret;
}
/******************************************************************************/

static void __exit vblk_device_exit(void)
{
	verify_block_remove_all();
	unregister_blkdev(vblk_dev_major, VERIFY_BLOCK_NAME);
}
/******************************************************************************/

module_init(vblk_device_init);
module_exit(vblk_device_exit);
MODULE_LICENSE("GPL");
