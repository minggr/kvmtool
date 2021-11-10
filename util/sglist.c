#include "kvm/kvm.h"
#include "kvm/sglist.h"

void sglist_init(sglist *sg, int alloc_hint, struct kvm *kvm)
{
	sg->iov = malloc(alloc_hint * sizeof(struct iovec));
	sg->nsg = 0;
	sg->nalloc = alloc_hint;
	sg->size = 0;
	sg->kvm = kvm;
}

void sglist_add(sglist *sg, uint64_t base, uint64_t len)
{
	if (sg->nsg == sg->nalloc) {
		sg->nalloc = 2 * sg->nalloc + 1;
		sg->iov = realloc(sg->iov, sg->nalloc * sizeof(struct iovec));
	}
	sg->iov[sg->nsg].iov_base = guest_flat_to_host(sg->kvm, base);
	sg->iov[sg->nsg].iov_len = len;
	sg->size += len;
	++sg->nsg;
}

void sglist_destroy(sglist *sg)
{
	free(sg->iov);
	memset(sg, 0, sizeof(*sg));
}

uint64_t sglist_read(uint8_t *ptr, int32_t len, sglist *sg)
{
	uint64_t resid;
	int sg_cur_index;

	resid = sg->size;
	sg_cur_index = 0;
	len = MIN(len, resid);

	while (len > 0) {
        	struct iovec iov = sg->iov[sg_cur_index++];
        	int32_t xfer = MIN(len, iov.iov_len);
		memcpy(iov.iov_base, ptr, xfer);
        	ptr += xfer;
        	len -= xfer;
        	resid -= xfer;       
	}

	return resid;
}
