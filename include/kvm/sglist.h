#ifndef KVM_UTIL_SGLIST_H_
#define KVM_UTIL_SGLIST_H_

struct iov;
struct kvm;

typedef struct sglist {
	struct iovec *iov;
	int nsg;
	int nalloc;
	size_t size;
	struct kvm *kvm;
} sglist;

void sglist_init(sglist *sg, int alloc_hint, struct kvm *kvm);
void sglist_add(sglist *sg, uint64_t base, uint64_t len);
void sglist_destroy(sglist *sg);
uint64_t sglist_read(uint8_t *ptr, int32_t len, sglist *sg);

#endif
