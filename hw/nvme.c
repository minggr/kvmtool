#include "kvm/nvme.h"
#include "kvm/disk-image.h"
#include "kvm/mutex.h"
#include "kvm/util.h"
#include "kvm/kvm.h"
#include "kvm/kvm-cpu.h"
#include "kvm/irq.h"
#include "kvm/pci.h"
#include "kvm/threadpool.h"
#include "kvm/ioeventfd.h"
#include "kvm/guest_compat.h"
#include "kvm/strbuf.h"
#include "kvm/sglist.h"
#include "kvm/iovec.h"

#include "kvm/virtio-pci-dev.h"
#include "kvm/virtio-pci.h"

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/types.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <linux/byteorder.h>
#include <assert.h>

#define PCI_VENDOR_ID_IBM                0x1014
#define PCI_VENDOR_ID_INTEL              0x8086
#define PCI_CLASS_STORAGE_EXPRESS        0x010802

#define CTRL_TO_DEV(n)	container_of(n, struct nvme_dev, ctrl)
#define CTRL_TO_KVM(n)	CTRL_TO_DEV(n)->kvm
typedef uint64_t dma_addr_t;
typedef uint64_t hwaddr;

static inline void pci_dma_read(struct kvm *kvm, dma_addr_t addr,
                               void *buf, dma_addr_t len)
{                   
	struct iovec iov[1];

	iov[0].iov_base = buf;
	iov[0].iov_len = len;

	memcpy_toiovec(iov, guest_flat_to_host(kvm, addr), len);
}

static inline void pci_dma_write(struct kvm *kvm, dma_addr_t addr,
                               void *buf, dma_addr_t len)
{                   
	struct iovec iov[1];

	iov[0].iov_base = buf;
	iov[0].iov_len = len;

	memcpy_fromiovec(guest_flat_to_host(kvm, addr), iov, len);
}

struct nvme_pci {
	struct pci_device_header pci_hdr;
	struct device_header	dev_hdr;
	void			*dev;
	struct kvm		*kvm;

	u8			status;
	u8			isr;
	u32			features;

	u8			legacy_irq_line;

	/* MSI-X */
	u16			config_vector;
	u32			config_gsi;
	u32			vq_vector[VIRTIO_PCI_MAX_VQ];
	u32			gsis[VIRTIO_PCI_MAX_VQ];
	u64			msix_pba;
	struct msix_table	msix_table[VIRTIO_PCI_MAX_VQ + VIRTIO_PCI_MAX_CONFIG];
};

struct nvme_dev_req {
	struct nvme_dev			*ndev;
	//struct iovec			iov[VIRTIO_BLK_QUEUE_SIZE];
	u16				out, in, head;
	struct kvm			*kvm;
};

struct nvme_dev {
	struct mutex			mutex;

	struct list_head		list;

	struct nvme_pci			pci;
	NvmeCtrl			ctrl;

	//struct nvme_config		blk_config;
	struct disk_image		*disk;
	u32				features;

	//struct nvme_dev_req		reqs[VIRTIO_BLK_QUEUE_SIZE];

	struct kvm			*kvm;
};

static LIST_HEAD(ndevs);

static void nvme_process_sq(void *opaque);

static void *nvme_sq_thread(void *arg)
{
	NvmeSQueue *sq = arg;
	u64 data;
	int r;

	kvm__set_thread_name("nvme-sq");

	while (1) {
		r = read(sq->io_efd, &data, sizeof(u64));
		if (r < 0)
			continue;
		// Only support 1 SQ now
		nvme_process_sq(sq);
	}

	pthread_exit(NULL);
	return NULL;
}

static int nvme_check_sqid(NvmeCtrl *n, uint16_t sqid)
{
    return sqid < n->num_queues && n->sq[sqid] != NULL ? 0 : -1;
}

static int nvme_check_cqid(NvmeCtrl *n, uint16_t cqid)
{
    return cqid < n->num_queues && n->cq[cqid] != NULL ? 0 : -1;
}

static void nvme_inc_cq_tail(NvmeCQueue *cq)
{
    cq->tail++;
    if (cq->tail >= cq->size) {
        cq->tail = 0;
        cq->phase = !cq->phase;
    }
}

static void nvme_inc_sq_head(NvmeSQueue *sq)
{
    sq->head = (sq->head + 1) % sq->size;
}

static uint8_t nvme_cq_full(NvmeCQueue *cq)
{
    return (cq->tail + 1) % cq->size == cq->head;
}

static uint8_t nvme_sq_empty(NvmeSQueue *sq)
{
    return sq->head == sq->tail;
}

static void nvme_isr_notify(NvmeCtrl *n, NvmeCQueue *cq)
{
#if 0
    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            msix_notify(&(n->parent_obj), cq->vector);
        } else {
            qemu_irq_pulse(n->parent_obj.irq[0]);
        }
    }
#else
	struct nvme_dev *ndev = CTRL_TO_DEV(n);
	kvm__irq_trigger(ndev->kvm, ndev->pci.legacy_irq_line);
#endif
}

static uint16_t nvme_map_prp(sglist *sg, uint64_t prp1, uint64_t prp2,
    uint32_t len, NvmeCtrl *n)
{
    uint64_t trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;

    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    sglist_init(sg, num_prps, CTRL_TO_KVM(n));
    sglist_add(sg, prp1, trans_len);
    len -= trans_len;
    if (len) {
        if (!prp2) {
            goto unmap;
        }
        if (len > n->page_size) {
            uint64_t prp_list[n->max_prp_ents];
            uint32_t nents, prp_trans;
            int i = 0;

            nents = (len + n->page_size - 1) >> n->page_bits;
            prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
            pci_dma_read(CTRL_TO_KVM(n), prp2, (void *)prp_list, prp_trans);
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == n->max_prp_ents - 1 && len > n->page_size) {
                    if (!prp_ent || prp_ent & (n->page_size - 1)) {
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
                    pci_dma_read(CTRL_TO_KVM(n), prp_ent, (void *)prp_list,
                        prp_trans);
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (!prp_ent || prp_ent & (n->page_size - 1)) {
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                sglist_add(sg, prp_ent, trans_len);
                len -= trans_len;
                i++;
            }
        } else {
            if (prp2 & (n->page_size - 1)) {
                goto unmap;
            }
            sglist_add(sg, prp2, len);
        }
    }
    return NVME_SUCCESS;

 unmap:
    sglist_destroy(sg);
    return NVME_INVALID_FIELD | NVME_DNR;
}

static uint16_t nvme_dma_read_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2)
{
    sglist sg;

    if (nvme_map_prp(&sg, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }   
    if (sglist_read(ptr, len, &sg)) {
        sglist_destroy(&sg);
        return NVME_INVALID_FIELD | NVME_DNR;
    }   
    return NVME_SUCCESS;
}

static void nvme_post_cqes(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeCtrl *n = cq->ctrl;
    NvmeRequest *req, *tmp;

    list_for_each_entry_safe(req, tmp, &cq->req_list, entry) {
        NvmeSQueue *sq;
        hwaddr addr;

        if (nvme_cq_full(cq)) {
            break;
        }

        sq = req->sq;
        req->cqe.status = cpu_to_le16((req->status << 1) | cq->phase);
        req->cqe.sq_id = cpu_to_le16(sq->sqid);
        req->cqe.sq_head = cpu_to_le16(sq->head);
        addr = cq->dma_addr + cq->tail * n->cqe_size;
        nvme_inc_cq_tail(cq);
        pci_dma_write(CTRL_TO_KVM(n), addr, (void *)&req->cqe,
            sizeof(req->cqe));
        list_move_tail(&req->entry, &sq->req_list);
    }
    nvme_isr_notify(n, cq);
}

static void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req)
{
    assert(cq->cqid == req->sq->cqid);
    list_move_tail(&req->entry, &cq->req_list);
    //qemu_mod_timer(cq->timer, qemu_get_clock_ns(vm_clock) + 500);
    nvme_post_cqes(cq);
}

static void nvme_io_complete(void *opaque, long len)
{
    NvmeRequest *req = opaque;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    if (len < 0) {
        req->status = NVME_INTERNAL_DEV_ERROR;
    } else {
        req->status = NVME_SUCCESS;
    }   

    sglist_destroy(&req->sg);
    nvme_enqueue_req_completion(cq, req);
}

#if 0
static void nvme_rw_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    //bdrv_acct_done(n->conf.bs, &req->acct);
    if (!ret) {
        req->status = NVME_SUCCESS;
    } else {
        req->status = NVME_INTERNAL_DEV_ERROR;
    }

    //qemu_sglist_destroy(&req->sg);
    nvme_enqueue_req_completion(cq, req);
}
#endif

static uint16_t nvme_rw(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint32_t nlb  = le32_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint64_t prp1 = le64_to_cpu(rw->prp1);
    uint64_t prp2 = le64_to_cpu(rw->prp2);

    uint8_t lba_index  = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    uint64_t data_size = nlb << data_shift;
    uint64_t aio_slba  = slba << (data_shift - BDRV_SECTOR_BITS);
    int is_write = rw->opcode == NVME_CMD_WRITE ? 1 : 0;

    if ((slba + nlb) > ns->id_ns.nsze) {
        return NVME_LBA_RANGE | NVME_DNR;
    }
    if (nvme_map_prp(&req->sg, prp1, prp2, data_size, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    assert((nlb << data_shift) == req->sg.size);

    if (is_write)
        disk_image__write(CTRL_TO_DEV(n)->disk, aio_slba, req->sg.iov, req->sg.nsg, req);
    else
        disk_image__write(CTRL_TO_DEV(n)->disk, aio_slba, req->sg.iov, req->sg.nsg, req);

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    switch (cmd->opcode) {
    case NVME_CMD_FLUSH:
        return NVME_SUCCESS;
    case NVME_CMD_WRITE:
    case NVME_CMD_READ:
        return nvme_rw(n, ns, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_free_sq(NvmeSQueue *sq, NvmeCtrl *n)
{
    n->sq[sq->sqid] = NULL;
    //qemu_del_timer(sq->timer);
    //qemu_free_timer(sq->timer);
    free(sq->io_req);
    if (sq->sqid) {
        free(sq);
    }
}

static uint16_t nvme_del_sq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeRequest *req, *tmp;
    NvmeSQueue *sq;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);

    if (!qid || nvme_check_sqid(n, qid)) {
        return NVME_INVALID_QID | NVME_DNR;
    }

    sq = n->sq[qid];
    while (!list_empty(&sq->out_req_list)) {
        req = list_first_entry(&sq->out_req_list, NvmeRequest, entry);
        //assert(req->aiocb);
        //bdrv_aio_cancel(req->aiocb);
    }
    if (!nvme_check_cqid(n, sq->cqid)) {
        cq = n->cq[sq->cqid];
        list_del(&sq->entry);

        nvme_post_cqes(cq);
        list_for_each_entry_safe(req, tmp, &cq->req_list, entry) {
            if (req->sq == sq) {
                list_move_tail(&req->entry, &sq->req_list);
            }
        }
    }

    nvme_free_sq(sq, n);
    return NVME_SUCCESS;
}

static void nvme_init_sq(NvmeSQueue *sq, NvmeCtrl *n, uint64_t dma_addr,
    uint16_t sqid, uint16_t cqid, uint16_t size)
{
    u32 i;
    NvmeCQueue *cq;

    sq->ctrl = n;
    sq->dma_addr = dma_addr;
    sq->sqid = sqid;
    sq->size = size;
    sq->cqid = cqid;
    sq->head = sq->tail = 0;
    sq->io_req = malloc(sq->size * sizeof(*sq->io_req));

    INIT_LIST_HEAD(&sq->req_list);
    INIT_LIST_HEAD(&sq->out_req_list);
    for (i = 0; i < sq->size; i++) {
        sq->io_req[i].sq = sq;
        list_add_tail(&sq->io_req[i].entry, &sq->req_list);
    }
    //sq->timer = qemu_new_timer_ns(vm_clock, nvme_process_sq, sq);

    assert(n->cq[cqid]);
    cq = n->cq[cqid];
    list_add_tail(&sq->entry, &cq->sq_list);
    n->sq[sqid] = sq;

    sq->io_efd = eventfd(0, 0);
    if (sq->io_efd < 0)
        assert(0);
        //return -errno;

    if (pthread_create(&sq->io_thread, NULL, nvme_sq_thread, sq))
        assert(0);
        //return -errno;
}

static uint16_t nvme_create_sq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeSQueue *sq;
    NvmeCreateSq *c = (NvmeCreateSq *)cmd;

    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t sqid = le16_to_cpu(c->sqid);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->sq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    if (!cqid || nvme_check_cqid(n, cqid)) {
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (!sqid || (sqid && !nvme_check_sqid(n, sqid))) {
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (!qsize || qsize > NVME_CAP_MQES(n->bar.cap)) {
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (!prp1 || prp1 & (n->page_size - 1)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!(NVME_SQ_FLAGS_PC(qflags))) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    sq = malloc(sizeof(*sq));
    nvme_init_sq(sq, n, prp1, sqid, cqid, qsize + 1);
    return NVME_SUCCESS;
}

static void nvme_free_cq(NvmeCQueue *cq, NvmeCtrl *n)
{
    n->cq[cq->cqid] = NULL;
    //qemu_del_timer(cq->timer);
    //qemu_free_timer(cq->timer);
    //msix_vector_unuse(&n->parent_obj, cq->vector);
    if (cq->cqid) {
        free(cq);
    }
}

static uint16_t nvme_del_cq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);

    if (!qid || nvme_check_cqid(n, qid)) {
        return NVME_INVALID_CQID | NVME_DNR;
    }

    cq = n->cq[qid];
    if (!list_empty(&cq->sq_list)) {
        return NVME_INVALID_QUEUE_DEL;
    }
    nvme_free_cq(cq, n);
    return NVME_SUCCESS;
}

static void nvme_init_cq(NvmeCQueue *cq, NvmeCtrl *n, uint64_t dma_addr,
    uint16_t cqid, uint16_t vector, uint16_t size, uint16_t irq_enabled)
{
    cq->ctrl = n;
    cq->cqid = cqid;
    cq->size = size;
    cq->dma_addr = dma_addr;
    cq->phase = 1;
    cq->irq_enabled = irq_enabled;
    cq->vector = vector;
    cq->head = cq->tail = 0;
    INIT_LIST_HEAD(&cq->req_list);
    INIT_LIST_HEAD(&cq->sq_list);
    //msix_vector_use(&n->parent_obj, cq->vector);
    n->cq[cqid] = cq;
    //cq->timer = qemu_new_timer_ns(vm_clock, nvme_post_cqes, cq);
}

static uint16_t nvme_create_cq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeCQueue *cq;
    NvmeCreateCq *c = (NvmeCreateCq *)cmd;
    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t vector = le16_to_cpu(c->irq_vector);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->cq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    if (!cqid || (cqid && !nvme_check_cqid(n, cqid))) {
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (!qsize || qsize > NVME_CAP_MQES(n->bar.cap)) {
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (vector > n->num_queues) {
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (!(NVME_CQ_FLAGS_PC(qflags))) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    cq = malloc(sizeof(*cq));
    nvme_init_cq(cq, n, prp1, cqid, vector, qsize + 1,
        NVME_CQ_FLAGS_IEN(qflags));
    return NVME_SUCCESS;
}

static uint16_t nvme_identify(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t cns  = le32_to_cpu(c->cns);
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint64_t prp2 = le64_to_cpu(c->prp2);

    if (cns) {
        return nvme_dma_read_prp(n, (uint8_t *)&n->id_ctrl, sizeof(n->id_ctrl),
            prp1, prp2);
    }
    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    return nvme_dma_read_prp(n, (uint8_t *)&ns->id_ns, sizeof(ns->id_ns),
        prp1, prp2);
}

static uint16_t nvme_get_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);

    switch (dw10) {
    case NVME_NUMBER_OF_QUEUES:
        req->cqe.result = cpu_to_le32(n->num_queues);
        break;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static uint16_t nvme_set_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);

    switch (dw10) {
    case NVME_NUMBER_OF_QUEUES:
        req->cqe.result = cpu_to_le32(n->num_queues);
        break;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static uint16_t nvme_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_DELETE_SQ:
        return nvme_del_sq(n, cmd);
    case NVME_ADM_CMD_CREATE_SQ:
        return nvme_create_sq(n, cmd);
    case NVME_ADM_CMD_DELETE_CQ:
        return nvme_del_cq(n, cmd);
    case NVME_ADM_CMD_CREATE_CQ:
        return nvme_create_cq(n, cmd);
    case NVME_ADM_CMD_IDENTIFY:
        return nvme_identify(n, cmd);
    case NVME_ADM_CMD_SET_FEATURES:
        return nvme_set_feature(n, cmd, req);
    case NVME_ADM_CMD_GET_FEATURES:
        return nvme_get_feature(n, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_process_sq(void *opaque)
{
    NvmeSQueue *sq = opaque;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    uint16_t status;
    hwaddr addr;
    NvmeCmd cmd;
    NvmeRequest *req;

    while (!(nvme_sq_empty(sq) || list_empty(&sq->req_list))) {
        addr = sq->dma_addr + sq->head * n->sqe_size;
        pci_dma_read(CTRL_TO_KVM(n), addr, (void *)&cmd, sizeof(cmd));
        nvme_inc_sq_head(sq);

        req = list_first_entry(&sq->req_list, NvmeRequest, entry);
        list_move(&req->entry, &sq->out_req_list);
        memset(&req->cqe, 0, sizeof(req->cqe));
        req->cqe.cid = cmd.cid;

        status = sq->sqid ? nvme_io_cmd(n, &cmd, req) :
            nvme_admin_cmd(n, &cmd, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion(cq, req);
        }
    }
}

static void nvme_clear_ctrl(NvmeCtrl *n)
{
    u32 i;

    for (i = 0; i < n->num_queues; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i < n->num_queues; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n);
        }
    }

    //bdrv_flush(n->conf.bs);
    n->bar.cc = 0;
}

static int nvme_start_ctrl(NvmeCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (n->cq[0] || n->sq[0] || !n->bar.asq || !n->bar.acq ||
            n->bar.asq & (page_size - 1) || n->bar.acq & (page_size - 1) ||
            NVME_CC_MPS(n->bar.cc) < NVME_CAP_MPSMIN(n->bar.cap) ||
            NVME_CC_MPS(n->bar.cc) > NVME_CAP_MPSMAX(n->bar.cap) ||
            NVME_CC_IOCQES(n->bar.cc) < NVME_CTRL_CQES_MIN(n->id_ctrl.cqes) ||
            NVME_CC_IOCQES(n->bar.cc) > NVME_CTRL_CQES_MAX(n->id_ctrl.cqes) ||
            NVME_CC_IOSQES(n->bar.cc) < NVME_CTRL_SQES_MIN(n->id_ctrl.sqes) ||
            NVME_CC_IOSQES(n->bar.cc) > NVME_CTRL_SQES_MAX(n->id_ctrl.sqes) ||
            !NVME_AQA_ASQS(n->bar.aqa) || NVME_AQA_ASQS(n->bar.aqa) > 4095 ||
            !NVME_AQA_ACQS(n->bar.aqa) || NVME_AQA_ACQS(n->bar.aqa) > 4095) {
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = page_size;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
    n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);
    nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0,
        NVME_AQA_ACQS(n->bar.aqa) + 1, 1);
    nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0,
        NVME_AQA_ASQS(n->bar.aqa) + 1); 

    return 0;
}

static void nvme_write_bar(NvmeCtrl *n, u32 offset, uint64_t data,
    unsigned size)
{
    switch (offset) {
    case 0xc:
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        break;
    case 0x10:
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        break;
    case 0x14:
        if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
            n->bar.cc = data;
            if (nvme_start_ctrl(n)) {
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                n->bar.csts = NVME_CSTS_READY;
            }   
        } else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
            nvme_clear_ctrl(n);
            n->bar.csts &= ~NVME_CSTS_READY;
        }   
        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
                nvme_clear_ctrl(n);
                n->bar.cc = data;
                n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(n->bar.cc)) {
                n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;
                n->bar.cc = data;
        }   
        break;
    case 0x24:
        n->bar.aqa = data & 0xffffffff;
        break;
    case 0x28:
        n->bar.asq = data;
        break;
    case 0x2c:
        n->bar.asq |= data << 32; 
        break;
    case 0x30:
        n->bar.acq = data;
        break;
    case 0x34:
        n->bar.acq |= data << 32; 
        break;
    default:
        break;
    }   
}

static void nvme_mmio_read(struct nvme_dev *ndev, u8 *data, u32 offset, unsigned size)
{
	NvmeCtrl *n = &ndev->ctrl; 
	uint8_t *ptr = (uint8_t *)&n->bar;

	if (offset < sizeof(n->bar))
		memcpy(data, ptr + offset, size);
}

static int nvme_notify_sq(NvmeSQueue *sq)
{
	u64 data = 1;
	int r;

	r = write(sq->io_efd, &data, sizeof(data));
	if (r < 0)
		return r;

	return 0;
}


static void nvme_process_db(NvmeCtrl *n, uint32_t addr, uint64_t val)
{
    uint32_t qid;

    if (addr & ((1 << 2) - 1)) {
        return;
    }

    if (((addr - 0x1000) >> 2) & 1) {
        uint16_t new_head = val & 0xffff;
        int start_sqs;
        NvmeCQueue *cq;

        qid = (addr - (0x1000 + (1 << 2))) >> 3;
        if (nvme_check_cqid(n, qid)) {
            return;
        }

        cq = n->cq[qid];
        if (new_head >= cq->size) {
            return;
        }

        start_sqs = nvme_cq_full(cq) ? 1 : 0;
        cq->head = new_head;
        if (start_sqs) {
            NvmeSQueue *sq;
            list_for_each_entry(sq, &cq->sq_list, entry) {
                //qemu_mod_timer(sq->timer, qemu_get_clock_ns(vm_clock) + 500);
                nvme_notify_sq(sq);
            }
            //qemu_mod_timer(cq->timer, qemu_get_clock_ns(vm_clock) + 500);
        }

        if (cq->tail != cq->head) {
            nvme_isr_notify(n, cq);
        }
    } else {
        uint16_t new_tail = val & 0xffff;
        NvmeSQueue *sq;

        qid = (addr - 0x1000) >> 3;
        if (nvme_check_sqid(n, qid)) {
            return;
        }

        sq = n->sq[qid];
        if (new_tail >= sq->size) {
            return;
        }

        sq->tail = new_tail;
        //qemu_mod_timer(sq->timer, qemu_get_clock_ns(vm_clock) + 500);
        nvme_notify_sq(sq);
    }
}

static void nvme_mmio_write(struct nvme_dev *ndev, u8 *data, u32 offset, unsigned size)
{   
	NvmeCtrl *n = &ndev->ctrl; 
	uint64_t value = *(uint64_t *)data;

	if (offset < sizeof(n->bar))
		nvme_write_bar(n, offset, value, size);
	else if (offset >= 0x1000)
		nvme_process_db(n, offset, value);
}

static void nvme_pci__io_mmio_callback(struct kvm_cpu *vcpu,
					 u64 addr, u8 *data, u32 len,
					 u8 is_write, void *ptr)
{
	struct nvme_dev *ndev = ptr;
	struct nvme_pci *vpci = &ndev->pci;
	u32 base_addr;

	base_addr = pci__bar_address(&vpci->pci_hdr, 0);

	if (!is_write)
		nvme_mmio_read(ndev, data, addr - base_addr, len);
	else
		nvme_mmio_write(ndev, data, addr - base_addr, len);
}

static int nvme_pci__bar_activate(struct kvm *kvm,
				    struct pci_device_header *pci_hdr,
				    int bar_num, void *data)
{
	struct nvme_dev *vdev = data;
	u32 bar_addr, bar_size;
	int r = -EINVAL;

	assert(bar_num == 0);

	bar_addr = pci__bar_address(pci_hdr, bar_num);
	bar_size = pci__bar_size(pci_hdr, bar_num);

	r =  kvm__register_mmio(kvm, bar_addr, bar_size, false,
					nvme_pci__io_mmio_callback, vdev);
	return r;
}

static int nvme_pci__bar_deactivate(struct kvm *kvm,
				      struct pci_device_header *pci_hdr,
				      int bar_num, void *data)
{
	u32 bar_addr;
	bool success;
	int r = -EINVAL;

	assert(bar_num == 0);

	bar_addr = pci__bar_address(pci_hdr, bar_num);

	success = kvm__deregister_mmio(kvm, bar_addr);
	/* kvm__deregister_mmio fails when the region is not found. */
	r = (success ? 0 : -ENOENT);

	return r;
}

#if 1
static int nvme_pci__init(struct kvm *kvm, void *dev, struct nvme_dev *ndev)
{
	struct nvme_pci *vpci = &ndev->pci;
	int device_id = 0x5845;
	//int subsys_id = VIRTIO_ID_BLOCK;
	int class = PCI_CLASS_STORAGE_EXPRESS;
	//int subsys_id = VIRTIO_ID_BLOCK;
	u32 mmio_addr;
	//u32 msix_io_block;
	//u16 port_addr;
	int r;

	vpci->kvm = kvm;
	vpci->dev = dev;

	BUILD_BUG_ON(!is_power_of_two(PCI_IO_SIZE));

	//port_addr = pci_get_io_port_block(PCI_IO_SIZE);
	#define MMIO_SIZE PCI_IO_SIZE*32
	mmio_addr = pci_get_mmio_block(MMIO_SIZE);
	//msix_io_block = pci_get_mmio_block(PCI_IO_SIZE * 2);

	vpci->pci_hdr = (struct pci_device_header) {
		.vendor_id		= cpu_to_le16(PCI_VENDOR_ID_REDHAT_QUMRANET),
		.device_id		= cpu_to_le16(device_id),
		.command		= PCI_COMMAND_IO | PCI_COMMAND_MEMORY,
		.header_type		= PCI_HEADER_TYPE_NORMAL,
		.revision_id		= 0,
		.class[0]		= class & 0xff,
		.class[1]		= (class >> 8) & 0xff,
		.class[2]		= (class >> 16) & 0xff,
		//.subsys_vendor_id	= cpu_to_le16(PCI_SUBSYSTEM_VENDOR_ID_REDHAT_QUMRANET),
		//.subsys_id		= cpu_to_le16(subsys_id),
		.status			= cpu_to_le16(PCI_STATUS_CAP_LIST),
		.capabilities		= (void *)&vpci->pci_hdr.msix - (void *)&vpci->pci_hdr,
#if 0
		.bar[0]			= cpu_to_le32(port_addr
							| PCI_BASE_ADDRESS_SPACE_IO),
		.bar[1]			= cpu_to_le32(mmio_addr
							| PCI_BASE_ADDRESS_SPACE_MEMORY),
		.bar[2]			= cpu_to_le32(msix_io_block
							| PCI_BASE_ADDRESS_SPACE_MEMORY),
		.bar_size[0]		= cpu_to_le32(PCI_IO_SIZE),
		.bar_size[1]		= cpu_to_le32(PCI_IO_SIZE),
		.bar_size[2]		= cpu_to_le32(PCI_IO_SIZE*2),
#else
		.bar[0]			= cpu_to_le32(mmio_addr
							| PCI_BASE_ADDRESS_SPACE_MEMORY),
		.bar_size[0]		= cpu_to_le32(MMIO_SIZE),
#endif
	};

	r = pci__register_bar_regions(kvm, &vpci->pci_hdr,
				      nvme_pci__bar_activate,
				      nvme_pci__bar_deactivate, ndev);
	//r = pci__register_bar_regions(kvm, &vpci->pci_hdr,
	//			      virtio_pci__bar_activate,
	//			      virtio_pci__bar_deactivate, vdev);
	if (r < 0)
		return r;

	vpci->dev_hdr = (struct device_header) {
		.bus_type		= DEVICE_BUS_PCI,
		.data			= &vpci->pci_hdr,
	};

#if 0
	vpci->pci_hdr.msix.cap = PCI_CAP_ID_MSIX;
	vpci->pci_hdr.msix.next = 0;
	/*
	 * We at most have VIRTIO_PCI_MAX_VQ entries for virt queue,
	 * VIRTIO_PCI_MAX_CONFIG entries for config.
	 *
	 * To quote the PCI spec:
	 *
	 * System software reads this field to determine the
	 * MSI-X Table Size N, which is encoded as N-1.
	 * For example, a returned value of "00000000011"
	 * indicates a table size of 4.
	 */
	vpci->pci_hdr.msix.ctrl = cpu_to_le16(VIRTIO_PCI_MAX_VQ + VIRTIO_PCI_MAX_CONFIG - 1);

	/* Both table and PBA are mapped to the same BAR (2) */
	vpci->pci_hdr.msix.table_offset = cpu_to_le32(2);
	vpci->pci_hdr.msix.pba_offset = cpu_to_le32(2 | PCI_IO_SIZE);
	vpci->config_vector = 0;

	if (irq__can_signal_msi(kvm))
		vpci->features |= VIRTIO_PCI_F_SIGNAL_MSI;
#endif

	vpci->legacy_irq_line = pci__assign_irq(&vpci->pci_hdr);

	r = device__register(&vpci->dev_hdr);
	if (r < 0)
		return r;

	return 0;
}

#else
static int nvme_pci__init(struct kvm *kvm, void *dev, struct nvme_dev *ndev)
{
	struct nvme_pci *vpci = &ndev->pci;
	u32 mmio_addr;
	int r;

	vpci->kvm = kvm;
	vpci->dev = dev;

	BUILD_BUG_ON(!is_power_of_two(PCI_IO_SIZE));

	mmio_addr = pci_get_mmio_block(PCI_IO_SIZE);

	vpci->pci_hdr.vendor_id = cpu_to_le16(PCI_VENDOR_ID_IBM);
	vpci->pci_hdr.device_id = cpu_to_le16(0x5845);
	vpci->pci_hdr.command = PCI_COMMAND_MEMORY;
	vpci->pci_hdr.header_type = PCI_HEADER_TYPE_NORMAL;
	vpci->pci_hdr.revision_id = 0;
	vpci->pci_hdr.class[0] = PCI_CLASS_STORAGE_EXPRESS & 0xff;
	vpci->pci_hdr.class[1] = (PCI_CLASS_STORAGE_EXPRESS >> 8) & 0xff;
	vpci->pci_hdr.class[2] = (PCI_CLASS_STORAGE_EXPRESS >> 16) & 0xff;
	vpci->pci_hdr.bar[0] = cpu_to_le32(mmio_addr | PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64);
	vpci->pci_hdr.bar_size[0] = cpu_to_le32(PCI_IO_SIZE);
	vpci->pci_hdr.irq_pin = 1;

	vpci->pci_hdr.msix.cap = PCI_CAP_ID_MSIX;
	vpci->pci_hdr.msix.next = 0;
	vpci->pci_hdr.magic = 0x1234;

	r = pci__register_bar_regions(kvm, &vpci->pci_hdr,
				      nvme_pci__bar_activate,
				      nvme_pci__bar_deactivate, ndev);
	if (r < 0)
		return r;

	vpci->dev_hdr = (struct device_header) {
		.bus_type		= DEVICE_BUS_PCI,
		.data			= &vpci->pci_hdr,
	};

	vpci->legacy_irq_line = pci__assign_irq(&vpci->pci_hdr);

	r = device__register(&vpci->dev_hdr);
	if (r < 0)
		return r;

	return 0;
}
#endif

static int nvme_ctrl__init(struct nvme_dev *ndev)
{
    NvmeCtrl *n = &ndev->ctrl;
    NvmeIdCtrl *id = &n->id_ctrl;

    uint32_t i;
    int64_t bs_size;

/* TODO
    if (!(n->conf.bs)) {
        return -1;
    }

    bs_size =  bdrv_getlength(n->conf.bs);
    if (bs_size <= 0) {
        return -1;
    }

    blkconf_serial(&n->conf, &n->serial);
    if (!n->serial) {
        return -1;
    }
*/

    n->num_namespaces = 1;
    n->num_queues = 64;
    n->reg_size = 1 << qemu_fls(0x1004 + 2 * (n->num_queues + 1) * 4);
    //TODO
    bs_size = ndev->disk->size;
    n->ns_size = bs_size / (uint64_t)n->num_namespaces;

    n->namespaces = malloc(sizeof(*n->namespaces)*n->num_namespaces);
    n->sq = malloc(sizeof(*n->sq)*n->num_queues);
    n->cq = malloc(sizeof(*n->cq)*n->num_queues);

    //TODO
    id->vid = cpu_to_le16(PCI_VENDOR_ID_INTEL);
    //id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    //id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));
    strpadcpy((char *)id->mn, sizeof(id->mn), "KVMTool NVMe Ctrl", ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), "1.0", ' ');
    //strpadcpy((char *)id->sn, sizeof(id->sn), n->serial, ' ');
    strpadcpy((char *)id->sn, sizeof(id->sn), "123456", ' ');
    id->rab = 6;
    id->ieee[0] = 0x00;
    id->ieee[1] = 0x02;
    id->ieee[2] = 0xb3;
    id->oacs = cpu_to_le16(0);
    id->frmw = 7 << 1;
    id->lpa = 1 << 0;
    id->sqes = (0x6 << 4) | 0x6;
    id->cqes = (0x4 << 4) | 0x4;
    id->nn = cpu_to_le32(n->num_namespaces);
    id->psd[0].mp = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, 0x7ff);
    NVME_CAP_SET_CQR(n->bar.cap, 1); 
    NVME_CAP_SET_AMS(n->bar.cap, 1); 
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_CSS(n->bar.cap, 1); 

    n->bar.vs = 0x00010001;
    n->bar.intmc = n->bar.intms = 0;

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        NvmeIdNs *id_ns = &ns->id_ns;
        id_ns->nsfeat = 0;
        id_ns->nlbaf = 0;
        id_ns->flbas = 0;
        id_ns->mc = 0;
        id_ns->dpc = 0;
        id_ns->dps = 0;
        id_ns->lbaf[0].ds = BDRV_SECTOR_BITS;
        id_ns->ncap  = id_ns->nuse = id_ns->nsze =
            cpu_to_le64(n->ns_size >>
                id_ns->lbaf[NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas)].ds);
    }

    return 0;
}

static int nvme__init_one(struct kvm *kvm, struct disk_image *disk)
{
	struct nvme_dev *ndev;
	int r;

	if (!disk)
		return -EINVAL;

	ndev = calloc(1, sizeof(struct nvme_dev));
	if (ndev == NULL)
		return -ENOMEM;

	*ndev = (struct nvme_dev) {
		.disk			= disk,
		.kvm			= kvm,
	};

	list_add_tail(&ndev->list, &ndevs);

	nvme_ctrl__init(ndev);

	r = nvme_pci__init(kvm, ndev->pci.dev, ndev);
	if (r < 0)
		return r;

	disk_image__set_callback(ndev->disk, nvme_io_complete);

	return 0;
}

static int nvme__exit_one(struct kvm *kvm, struct nvme_dev *ndev)
{
	list_del(&ndev->list);
	free(ndev);

	return 0;
}

int nvme__init(struct kvm *kvm)
{
	int i, r = 0;

	for (i = 0; i < kvm->nr_disks; i++) {
		if (!kvm->disks[i]->nvme)
			continue;
		r = nvme__init_one(kvm, kvm->disks[i]);
		if (r < 0)
			goto cleanup;
	}

	return 0;
cleanup:
	nvme__exit(kvm);
	return r;
}
dev_init(nvme__init);

int nvme__exit(struct kvm *kvm)
{
	while (!list_empty(&ndevs)) {
		struct nvme_dev *ndev;

		ndev = list_first_entry(&ndevs, struct nvme_dev, list);
		nvme__exit_one(kvm, ndev);
	}

	return 0;
}
dev_exit(nvme__exit);
