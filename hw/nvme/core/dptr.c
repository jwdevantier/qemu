/*
 * QEMU NVM Express — shared data-path helpers (PRP/SGL mapping)
 *
 * Core PRP and SGL mapping code shared by the production (`vnvme`) and test
 * (`nvme`) devices. This code is in the QEMU security boundary.
 *
 * Data buffers are mapped eagerly into host memory (see NvmeMap): each data
 * pointer fragment becomes either a direct mapping (guest RAM, CMB, PMR —
 * all of which are RAM memory regions and thus mappable with
 * dma_memory_map()) or, for memory that cannot be mapped (e.g. MMIO of
 * another device), a bounce buffer — if the device class allows bouncing at
 * all (NvmeBaseClass::bounce); otherwise the command is failed with a Data
 * Transfer Error. No per-device address operation hooks are involved.
 *
 * Copyright (c) 2012, Intel Corporation
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/nvme/core/nvme.h"
#include "hw/nvme/trace.h"

/* ------------------------------------------------------------------ */
/* Mapping primitives                                                  */
/* ------------------------------------------------------------------ */

/*
 * NvmeTxDirection and DMADirection encode the same direction with the
 * same values; go through a conversion anyway to keep the types apart.
 */
static inline DMADirection nvme_dma_dir(NvmeMap *map)
{
    return map->dir == NVME_TX_DIRECTION_FROM_DEVICE ?
        DMA_DIRECTION_FROM_DEVICE : DMA_DIRECTION_TO_DEVICE;
}

void nvme_map_init(NvmeMap *map, NvmeTxDirection dir)
{
    assert(!map->frag && !map->iov.niov); /* must nvme_map_unmap() first */

    memset(map, 0x0, sizeof(*map));
    map->dir = dir;
    qemu_iovec_init(&map->iov, 0);
}

void nvme_map_unmap(NvmeCtrlBase *n, NvmeMap *map)
{
    AddressSpace *as = pci_get_address_space(PCI_DEVICE(n));
    DMADirection dir = nvme_dma_dir(map);
    int i;

    for (i = 0; i < map->nfrag; i++) {
        if (map->frag[i].bounce) {
            if (map->dir == NVME_TX_DIRECTION_FROM_DEVICE) {
                /* the device wrote into the bounce buffer; flush it back */
                address_space_write(as, map->frag[i].addr,
                                    MEMTXATTRS_UNSPECIFIED,
                                    map->frag[i].ptr, map->frag[i].len);
            }

            g_free(map->frag[i].ptr);
        } else {
            dma_memory_unmap(as, map->frag[i].ptr, map->frag[i].len, dir,
                             map->frag[i].len);
        }
    }

    g_free(map->frag);
    qemu_iovec_destroy(&map->iov);
    memset(map, 0x0, sizeof(*map));
}

static uint16_t nvme_map_append(NvmeMap *map, void *ptr, size_t len,
                                hwaddr addr, bool bounce)
{
    if (map->iov.niov >= IOV_MAX) {
        NVME_GUEST_ERR(pci_nvme_ub_too_many_mappings,
                       "number of mappings exceed 1024");
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    map->frag = g_renew(typeof(*map->frag), map->frag, map->nfrag + 1);
    map->frag[map->nfrag] = (typeof(*map->frag)) {
        .ptr    = ptr,
        .len    = len,
        .addr   = addr,
        .bounce = bounce,
    };
    map->nfrag++;

    qemu_iovec_add(&map->iov, ptr, len);

    return NVME_SUCCESS;
}

/*
 * Map the guest range [addr, addr+len) into host memory and append the
 * resulting fragment(s) to `map`. Guest RAM, CMB and PMR map directly;
 * non-mappable memory is bounced (if permitted by the device class).
 *
 * On error, the caller is responsible for releasing any partial mapping
 * (nvme_map_unmap()).
 */
uint16_t nvme_map_range(NvmeCtrlBase *n, NvmeMap *map, hwaddr addr, size_t len)
{
    NvmeBaseClass *bc = NVME_BASE_GET_CLASS(n);
    AddressSpace *as = pci_get_address_space(PCI_DEVICE(n));
    const MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    bool is_write = map->dir == NVME_TX_DIRECTION_FROM_DEVICE;
    DMADirection dir = nvme_dma_dir(map);
    uint16_t status;

    if (!len) {
        return NVME_SUCCESS;
    }

    trace_pci_nvme_map_addr(addr, len);

    if (nvme_addr_is_iomem(n, addr)) {
        return NVME_DATA_TRAS_ERROR;
    }

    if (UINT64_MAX - addr < len) {
        return NVME_DATA_TRAS_ERROR;
    }

    while (len) {
        hwaddr xlat;
        MemoryRegion *mr;
        void *ptr;
        hwaddr clen = len;

        mr = address_space_translate(as, addr, &xlat, &clen, is_write, attrs);

        if (unlikely(!clen)) {
            return NVME_DATA_TRAS_ERROR;
        }

        if (memory_access_is_direct(mr, is_write, attrs)) {
            hwaddr mlen = len;

            /*
             * dma_memory_map() extends the mapping through as much
             * contiguous memory as possible, so pass the whole
             * remaining length and let it clamp.
             */
            ptr = dma_memory_map(as, addr, &mlen, dir, attrs);
            if (!ptr) {
                trace_pci_nvme_err_addr_read(addr);
                return NVME_DATA_TRAS_ERROR;
            }

            status = nvme_map_append(map, ptr, mlen, 0, false);
            if (status) {
                dma_memory_unmap(as, ptr, mlen, dir, mlen);
                return status;
            }

            clen = mlen;
        } else {
            if (!bc->bounce) {
                /*
                 * Hardened device: do not put device-internal or
                 * otherwise non-mappable memory on the data path.
                 */
                trace_pci_nvme_err_addr_read(addr);
                return NVME_DATA_TRAS_ERROR;
            }

            ptr = g_malloc(clen);

            if (map->dir == NVME_TX_DIRECTION_TO_DEVICE) {
                /* fill the bounce buffer with what the guest provided */
                if (address_space_read(as, addr, attrs, ptr, clen) !=
                    MEMTX_OK) {
                    g_free(ptr);
                    trace_pci_nvme_err_addr_read(addr);
                    return NVME_DATA_TRAS_ERROR;
                }
            }

            status = nvme_map_append(map, ptr, clen, addr, true);
            if (status) {
                g_free(ptr);
                return status;
            }
        }

        addr += clen;
        len -= clen;
    }

    return NVME_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* PRP mapping                                                         */
/* ------------------------------------------------------------------ */

static uint16_t nvme_map_prp(NvmeCtrlBase *n, NvmeMap *map, uint64_t prp1,
                             uint64_t prp2, uint32_t len)
{
    AddressSpace *as = pci_get_address_space(PCI_DEVICE(n));
    const MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;
    uint16_t status;

    trace_pci_nvme_map_prp(trans_len, len, prp1, prp2, num_prps);

    status = nvme_map_range(n, map, prp1, trans_len);
    if (status) {
        return status;
    }

    len -= trans_len;
    if (len) {
        if (len > n->page_size) {
            g_autofree uint64_t *prp_list = g_new(uint64_t, n->max_prp_ents);
            uint32_t nents, prp_trans;
            int i = 0;

            /*
             * The first PRP list entry, pointed to by PRP2 may contain offset.
             * Hence, we need to calculate the number of entries in based on
             * that offset.
             */
            nents = (n->page_size - (prp2 & (n->page_size - 1))) >> 3;
            prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
            if (dma_memory_read(as, prp2, (void *)prp_list, prp_trans,
                                attrs)) {
                trace_pci_nvme_err_addr_read(prp2);
                return NVME_DATA_TRAS_ERROR;
            }
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == nents - 1 && len > n->page_size) {
                    if (unlikely(prp_ent & (n->page_size - 1))) {
                        trace_pci_nvme_err_invalid_prplist_ent(prp_ent);
                        return NVME_INVALID_PRP_OFFSET | NVME_DNR;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    nents = MIN(nents, n->max_prp_ents);
                    prp_trans = nents * sizeof(uint64_t);
                    if (dma_memory_read(as, prp_ent, (void *)prp_list,
                                        prp_trans, attrs)) {
                        trace_pci_nvme_err_addr_read(prp_ent);
                        return NVME_DATA_TRAS_ERROR;
                    }
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (unlikely(prp_ent & (n->page_size - 1))) {
                    trace_pci_nvme_err_invalid_prplist_ent(prp_ent);
                    return NVME_INVALID_PRP_OFFSET | NVME_DNR;
                }

                trans_len = MIN(len, n->page_size);
                status = nvme_map_range(n, map, prp_ent, trans_len);
                if (status) {
                    return status;
                }

                len -= trans_len;
                i++;
            }
        } else {
            if (unlikely(prp2 & (n->page_size - 1))) {
                trace_pci_nvme_err_invalid_prp2_align(prp2);
                return NVME_INVALID_PRP_OFFSET | NVME_DNR;
            }
            status = nvme_map_range(n, map, prp2, len);
            if (status) {
                return status;
            }
        }
    }

    return NVME_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* SGL mapping                                                         */
/* ------------------------------------------------------------------ */

/*
 * Map 'nsgld' data descriptors from 'segment'. The function will subtract the
 * number of bytes mapped in len.
 */
static uint16_t nvme_map_sgl_data(NvmeCtrlBase *n, NvmeMap *map,
                                  NvmeSglDescriptor *segment, uint64_t nsgld,
                                  size_t *len, NvmeCmd *cmd)
{
    dma_addr_t addr, trans_len;
    uint32_t dlen;
    uint16_t status;

    for (int i = 0; i < nsgld; i++) {
        uint8_t type = NVME_SGL_TYPE(segment[i].type);

        switch (type) {
        case NVME_SGL_DESCR_TYPE_DATA_BLOCK:
            break;
        case NVME_SGL_DESCR_TYPE_SEGMENT:
        case NVME_SGL_DESCR_TYPE_LAST_SEGMENT:
            return NVME_INVALID_NUM_SGL_DESCRS | NVME_DNR;
        default:
            return NVME_SGL_DESCR_TYPE_INVALID | NVME_DNR;
        }

        dlen = le32_to_cpu(segment[i].len);

        if (!dlen) {
            continue;
        }

        if (*len == 0) {
            uint32_t sgls = le32_to_cpu(n->id_ctrl.sgls);
            if (sgls & NVME_CTRL_SGLS_EXCESS_LENGTH) {
                break;
            }

            trace_pci_nvme_err_invalid_sgl_excess_length(dlen);
            return NVME_DATA_SGL_LEN_INVALID | NVME_DNR;
        }

        trans_len = MIN(*len, dlen);

        addr = le64_to_cpu(segment[i].addr);

        if (UINT64_MAX - addr < dlen) {
            return NVME_DATA_SGL_LEN_INVALID | NVME_DNR;
        }

        status = nvme_map_range(n, map, addr, trans_len);
        if (status) {
            return status;
        }

        *len -= trans_len;
    }

    return NVME_SUCCESS;
}

/*
 * Map the SGL `sgl` into `map`, which must have been initialized by the
 * caller (nvme_map_init()). On error, releasing any partial mapping is
 * the caller's responsibility.
 */
uint16_t nvme_map_sgl(NvmeCtrlBase *n, NvmeMap *map, NvmeSglDescriptor sgl,
                      size_t len, NvmeCmd *cmd)
{
#define SEG_CHUNK_SIZE 256

    AddressSpace *as = pci_get_address_space(PCI_DEVICE(n));
    const MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    QEMU_UNINITIALIZED NvmeSglDescriptor segment[SEG_CHUNK_SIZE];
    NvmeSglDescriptor *sgld, *last_sgld;
    uint64_t nsgld;
    uint32_t seg_len;
    uint16_t status;
    hwaddr addr;

    sgld = &sgl;
    addr = le64_to_cpu(sgl.addr);

    trace_pci_nvme_map_sgl(NVME_SGL_TYPE(sgl.type), len);

    if (NVME_SGL_TYPE(sgl.type) == NVME_SGL_DESCR_TYPE_DATA_BLOCK) {
        status = nvme_map_sgl_data(n, map, sgld, 1, &len, cmd);
        if (status) {
            return status;
        }
        goto out;
    }

    for (;;) {
        size_t prev_len = len;

        switch (NVME_SGL_TYPE(sgld->type)) {
        case NVME_SGL_DESCR_TYPE_SEGMENT:
        case NVME_SGL_DESCR_TYPE_LAST_SEGMENT:
            break;
        default:
            return NVME_INVALID_SGL_SEG_DESCR | NVME_DNR;
        }

        seg_len = le32_to_cpu(sgld->len);

        if (!seg_len || seg_len & 0xf) {
            return NVME_INVALID_SGL_SEG_DESCR | NVME_DNR;
        }

        if (UINT64_MAX - addr < seg_len) {
            return NVME_DATA_SGL_LEN_INVALID | NVME_DNR;
        }

        nsgld = seg_len / sizeof(NvmeSglDescriptor);

        while (nsgld > SEG_CHUNK_SIZE) {
            if (dma_memory_read(as, addr, segment, sizeof(segment), attrs)) {
                trace_pci_nvme_err_addr_read(addr);
                return NVME_DATA_TRAS_ERROR;
            }

            status = nvme_map_sgl_data(n, map, segment, SEG_CHUNK_SIZE,
                                       &len, cmd);
            if (status) {
                return status;
            }

            nsgld -= SEG_CHUNK_SIZE;
            addr += SEG_CHUNK_SIZE * sizeof(NvmeSglDescriptor);
        }

        if (dma_memory_read(as, addr, segment, nsgld *
                            sizeof(NvmeSglDescriptor), attrs)) {
            trace_pci_nvme_err_addr_read(addr);
            return NVME_DATA_TRAS_ERROR;
        }

        last_sgld = &segment[nsgld - 1];

        if (NVME_SGL_TYPE(last_sgld->type) == NVME_SGL_DESCR_TYPE_DATA_BLOCK) {
            status = nvme_map_sgl_data(n, map, segment, nsgld, &len, cmd);
            if (status) {
                return status;
            }
            goto out;
        }

        if (NVME_SGL_TYPE(sgld->type) == NVME_SGL_DESCR_TYPE_LAST_SEGMENT) {
            return NVME_INVALID_SGL_SEG_DESCR | NVME_DNR;
        }

        sgld = last_sgld;
        addr = le64_to_cpu(sgld->addr);

        status = nvme_map_sgl_data(n, map, segment, nsgld - 1, &len, cmd);
        if (status) {
            return status;
        }

        if (len == prev_len) {
            return NVME_INVALID_SGL_SEG_DESCR | NVME_DNR;
        }
    }

out:
    if (len) {
        return NVME_DATA_SGL_LEN_INVALID | NVME_DNR;
    }

    return NVME_SUCCESS;
}

/*
 * Map the data pointer of `cmd` (PRP or SGL, `len` bytes) into host
 * memory. The mapping is owned by the caller and must be released with
 * nvme_map_unmap().
 */
uint16_t nvme_map_dptr(NvmeCtrlBase *n, NvmeMap *map, size_t len,
                       NvmeCmd *cmd, NvmeTxDirection dir)
{
    uint64_t prp1, prp2;
    uint16_t status;

    nvme_map_init(map, dir);

    switch (NVME_CMD_FLAGS_PSDT(cmd->flags)) {
    case NVME_PSDT_PRP:
        prp1 = le64_to_cpu(cmd->dptr.prp1);
        prp2 = le64_to_cpu(cmd->dptr.prp2);
        status = nvme_map_prp(n, map, prp1, prp2, len);
        break;
    case NVME_PSDT_SGL_MPTR_CONTIGUOUS:
    case NVME_PSDT_SGL_MPTR_SGL:
        status = nvme_map_sgl(n, map, cmd->dptr.sgl, len, cmd);
        break;
    default:
        status = NVME_INVALID_FIELD;
        break;
    }

    if (status) {
        nvme_map_unmap(n, map);
    }

    return status;
}
