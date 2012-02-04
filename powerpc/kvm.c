/*
 * PPC64 (SPAPR) platform support
 *
 * Copyright 2011 Matt Evans <matt@ozlabs.org>, IBM Corporation.
 *
 * Portions of FDT setup borrowed from QEMU, copyright 2010 David Gibson, IBM
 * Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include "kvm/kvm.h"
#include "kvm/util.h"
#include "libfdt.h"
#include "cpu_info.h"

#include <linux/kvm.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <asm/unistd.h>
#include <errno.h>

#include <linux/byteorder.h>

#define HPT_ORDER 24

#define HUGETLBFS_PATH "/var/lib/hugetlbfs/global/pagesize-16MB/"

static char kern_cmdline[2048];

struct kvm_ext kvm_req_ext[] = {
	{ 0, 0 }
};

static uint32_t mfpvr(void)
{
	uint32_t r;
	asm volatile ("mfpvr %0" : "=r"(r));
	return r;
}

bool kvm__arch_cpu_supports_vm(void)
{
	return true;
}

void kvm__init_ram(struct kvm *kvm)
{
	u64	phys_start, phys_size;
	void	*host_mem;

	phys_start = 0;
	phys_size  = kvm->ram_size;
	host_mem   = kvm->ram_start;

	/*
	 * We put MMIO at PPC_MMIO_START, high up.  Make sure that this doesn't
	 * crash into the end of RAM -- on PPC64 at least, this is so high
	 * (63TB!) that this is unlikely.
	 */
	if (phys_size >= PPC_MMIO_START)
		die("Too much memory (%lld, what a nice problem): "
		    "overlaps MMIO!\n",
		    phys_size);

	kvm__register_mem(kvm, phys_start, phys_size, host_mem);
}

void kvm__arch_set_cmdline(char *cmdline, bool video)
{
	/* We don't need anything unusual in here. */
}

/* Architecture-specific KVM init */
void kvm__arch_init(struct kvm *kvm, const char *hugetlbfs_path, u64 ram_size)
{
	int cap_ppc_rma;
	unsigned long hpt;

	kvm->ram_size		= ram_size;

	/*
	 * Currently, HV-mode PPC64 SPAPR requires that we map from hugetlfs.
	 * Allow a 'default' option to assist.
	 * PR-mode does not require this.
	 */
	if (hugetlbfs_path) {
		if (!strcmp(hugetlbfs_path, "default"))
			hugetlbfs_path = HUGETLBFS_PATH;
		kvm->ram_start = mmap_hugetlbfs(hugetlbfs_path, kvm->ram_size);
	} else {
		kvm->ram_start = mmap(0, kvm->ram_size, PROT_READ | PROT_WRITE,
				      MAP_ANON | MAP_PRIVATE,
				      -1, 0);
	}
	if (kvm->ram_start == MAP_FAILED)
		die("Couldn't map %lld bytes for RAM (%d)\n",
		    kvm->ram_size, errno);

	/* FDT goes at top of memory, RTAS just below */
	kvm->fdt_gra = kvm->ram_size - FDT_MAX_SIZE;
	/* FIXME: Not all PPC systems have RTAS */
	kvm->rtas_gra = kvm->fdt_gra - RTAS_MAX_SIZE;
	madvise(kvm->ram_start, kvm->ram_size, MADV_MERGEABLE);

	/* FIXME:  SPAPR-PR specific; allocate a guest HPT. */
	if (posix_memalign((void **)&hpt, (1<<HPT_ORDER), (1<<HPT_ORDER)))
		die("Can't allocate %d bytes for HPT\n", (1<<HPT_ORDER));

	kvm->sdr1 = ((hpt + 0x3ffffULL) & ~0x3ffffULL) | (HPT_ORDER-18);

	kvm->pvr = mfpvr();

	/* FIXME: This is book3s-specific */
	cap_ppc_rma = ioctl(kvm->sys_fd, KVM_CHECK_EXTENSION, KVM_CAP_PPC_RMA);
	if (cap_ppc_rma == 2)
		die("Need contiguous RMA allocation on this hardware, "
		    "which is not yet supported.");
}

void kvm__arch_delete_ram(struct kvm *kvm)
{
	munmap(kvm->ram_start, kvm->ram_size);
}

void kvm__irq_line(struct kvm *kvm, int irq, int level)
{
	fprintf(stderr, "irq_line(%d, %d)\n", irq, level);
}

void kvm__irq_trigger(struct kvm *kvm, int irq)
{
	kvm__irq_line(kvm, irq, 1);
	kvm__irq_line(kvm, irq, 0);
}

int load_flat_binary(struct kvm *kvm, int fd_kernel, int fd_initrd, const char *kernel_cmdline)
{
	void *p;
	void *k_start;
	void *i_start;
	int nr;

	if (lseek(fd_kernel, 0, SEEK_SET) < 0)
		die_perror("lseek");

	p = k_start = guest_flat_to_host(kvm, KERNEL_LOAD_ADDR);

	while ((nr = read(fd_kernel, p, 65536)) > 0)
		p += nr;

	pr_info("Loaded kernel to 0x%x (%ld bytes)", KERNEL_LOAD_ADDR, p-k_start);

	if (fd_initrd != -1) {
		if (lseek(fd_initrd, 0, SEEK_SET) < 0)
			die_perror("lseek");

		if (p-k_start > INITRD_LOAD_ADDR)
			die("Kernel overlaps initrd!");

		/* Round up kernel size to 8byte alignment, and load initrd right after. */
		i_start = p = guest_flat_to_host(kvm, INITRD_LOAD_ADDR);

		while (((nr = read(fd_initrd, p, 65536)) > 0) &&
		       p < (kvm->ram_start + kvm->ram_size))
			p += nr;

		if (p >= (kvm->ram_start + kvm->ram_size))
			die("initrd too big to contain in guest RAM.\n");

		pr_info("Loaded initrd to 0x%x (%ld bytes)",
			INITRD_LOAD_ADDR, p-i_start);
		kvm->initrd_gra = INITRD_LOAD_ADDR;
		kvm->initrd_size = p-i_start;
	} else {
		kvm->initrd_size = 0;
	}
	strncpy(kern_cmdline, kernel_cmdline, 2048);
	kern_cmdline[2047] = '\0';

	return true;
}

bool load_bzimage(struct kvm *kvm, int fd_kernel,
		  int fd_initrd, const char *kernel_cmdline, u16 vidmode)
{
	/* We don't support bzImages. */
	return false;
}

#define SMT_THREADS 4

/*
 * Set up the FDT for the kernel: This function is currently fairly SPAPR-heavy,
 * and whilst most PPC targets will require CPU/memory nodes, others like RTAS
 * should eventually be added separately.
 */
static void setup_fdt(struct kvm *kvm)
{
	uint64_t 	mem_reg_property[] = { 0, cpu_to_be64(kvm->ram_size) };
	int 		smp_cpus = kvm->nrcpus;
	char 		hypertas_prop_kvm[] = "hcall-pft\0hcall-term\0"
		"hcall-dabr\0hcall-interrupt\0hcall-tce\0hcall-vio\0"
		"hcall-splpar\0hcall-bulk";
	int 		i, j;
	char 		cpu_name[30];
	u8		staging_fdt[FDT_MAX_SIZE];
	struct cpu_info *cpu_info = find_cpu_info(kvm->pvr);

	/* Generate an appropriate DT at kvm->fdt_gra */
	void *fdt_dest = guest_flat_to_host(kvm, kvm->fdt_gra);
	void *fdt = staging_fdt;

	_FDT(fdt_create(fdt, FDT_MAX_SIZE));
	_FDT(fdt_finish_reservemap(fdt));

	_FDT(fdt_begin_node(fdt, ""));

	_FDT(fdt_property_string(fdt, "device_type", "chrp"));
	_FDT(fdt_property_string(fdt, "model", "IBM pSeries (kvmtool)"));
	_FDT(fdt_property_cell(fdt, "#address-cells", 0x2));
	_FDT(fdt_property_cell(fdt, "#size-cells", 0x2));

	/* /chosen */
	_FDT(fdt_begin_node(fdt, "chosen"));
	/* cmdline */
	_FDT(fdt_property_string(fdt, "bootargs", kern_cmdline));
	/* Initrd */
	if (kvm->initrd_size != 0) {
		uint32_t ird_st_prop = cpu_to_be32(kvm->initrd_gra);
		uint32_t ird_end_prop = cpu_to_be32(kvm->initrd_gra +
						    kvm->initrd_size);
		_FDT(fdt_property(fdt, "linux,initrd-start",
				   &ird_st_prop, sizeof(ird_st_prop)));
		_FDT(fdt_property(fdt, "linux,initrd-end",
				   &ird_end_prop, sizeof(ird_end_prop)));
	}
	_FDT(fdt_end_node(fdt));

	/*
	 * Memory: We don't alloc. a separate RMA yet.  If we ever need to
	 * (CAP_PPC_RMA == 2) then have one memory node for 0->RMAsize, and
	 * another RMAsize->endOfMem.
	 */
	_FDT(fdt_begin_node(fdt, "memory@0"));
	_FDT(fdt_property_string(fdt, "device_type", "memory"));
	_FDT(fdt_property(fdt, "reg", mem_reg_property,
			  sizeof(mem_reg_property)));
	_FDT(fdt_end_node(fdt));

	/* CPUs */
	_FDT(fdt_begin_node(fdt, "cpus"));
	_FDT(fdt_property_cell(fdt, "#address-cells", 0x1));
	_FDT(fdt_property_cell(fdt, "#size-cells", 0x0));

	for (i = 0; i < smp_cpus; i += SMT_THREADS) {
		int32_t pft_size_prop[] = { 0, HPT_ORDER };
		uint32_t servers_prop[SMT_THREADS];
		uint32_t gservers_prop[SMT_THREADS * 2];
		int threads = (smp_cpus - i) >= SMT_THREADS ? SMT_THREADS :
			smp_cpus - i;

		sprintf(cpu_name, "PowerPC,%s@%d", cpu_info->name, i);
		_FDT(fdt_begin_node(fdt, cpu_name));
		sprintf(cpu_name, "PowerPC,%s", cpu_info->name);
		_FDT(fdt_property_string(fdt, "name", cpu_name));
		_FDT(fdt_property_string(fdt, "device_type", "cpu"));

		_FDT(fdt_property_cell(fdt, "reg", i));
		_FDT(fdt_property_cell(fdt, "cpu-version", kvm->pvr));

		_FDT(fdt_property_cell(fdt, "dcache-block-size", cpu_info->d_bsize));
		_FDT(fdt_property_cell(fdt, "icache-block-size", cpu_info->i_bsize));

		_FDT(fdt_property_cell(fdt, "timebase-frequency", cpu_info->tb_freq));
		/* Lies, but safeish lies! */
		_FDT(fdt_property_cell(fdt, "clock-frequency", 0xddbab200));

		if (cpu_info->slb_size)
			_FDT(fdt_property_cell(fdt, "ibm,slb-size", cpu_info->slb_size));
		/*
		 * HPT size is hardwired; KVM currently fixes it at 16MB but the
		 * moment that changes we'll need to read it out of the kernel.
		 */
		_FDT(fdt_property(fdt, "ibm,pft-size", pft_size_prop,
				  sizeof(pft_size_prop)));

		_FDT(fdt_property_string(fdt, "status", "okay"));
		_FDT(fdt_property(fdt, "64-bit", NULL, 0));
		/* A server for each thread in this core */
		for (j = 0; j < SMT_THREADS; j++) {
			servers_prop[j] = cpu_to_be32(i+j);
			/*
			 * Hack borrowed from QEMU, direct the group queues back
			 * to cpu 0:
			 */
			gservers_prop[j*2] = cpu_to_be32(i+j);
			gservers_prop[j*2 + 1] = 0;
		}
		_FDT(fdt_property(fdt, "ibm,ppc-interrupt-server#s",
				   servers_prop, threads * sizeof(uint32_t)));
		_FDT(fdt_property(fdt, "ibm,ppc-interrupt-gserver#s",
				  gservers_prop,
				  threads * 2 * sizeof(uint32_t)));
		if (cpu_info->page_sizes_prop)
			_FDT(fdt_property(fdt, "ibm,segment-page-sizes",
					  cpu_info->page_sizes_prop,
					  cpu_info->page_sizes_prop_len));
		if (cpu_info->segment_sizes_prop)
			_FDT(fdt_property(fdt, "ibm,processor-segment-sizes",
					  cpu_info->segment_sizes_prop,
					  cpu_info->segment_sizes_prop_len));
		/* VSX / DFP options: */
		if (cpu_info->flags & CPUINFO_FLAG_VMX)
			_FDT(fdt_property_cell(fdt, "ibm,vmx",
					       (cpu_info->flags &
						CPUINFO_FLAG_VSX) ? 2 : 1));
		if (cpu_info->flags & CPUINFO_FLAG_DFP)
			_FDT(fdt_property_cell(fdt, "ibm,dfp", 0x1));
		_FDT(fdt_end_node(fdt));
	}
	_FDT(fdt_end_node(fdt));

	/* Finalise: */
	_FDT(fdt_end_node(fdt)); /* Root node */
	_FDT(fdt_finish(fdt));

	_FDT(fdt_open_into(fdt, fdt_dest, FDT_MAX_SIZE));
	_FDT(fdt_add_mem_rsv(fdt_dest, kvm->rtas_gra, kvm->rtas_size));
	_FDT(fdt_pack(fdt_dest));
}

/**
 * kvm__arch_setup_firmware
 */
int kvm__arch_setup_firmware(struct kvm *kvm)
{
	/* Load RTAS */

	/* Load SLOF */

	/* Init FDT */
	setup_fdt(kvm);

	return 0;
}

int kvm__arch_free_firmware(struct kvm *kvm)
{
	return 0;
}