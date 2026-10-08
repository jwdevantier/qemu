/*
 * QEMU NVM Express — shared data-path helpers (PRP/SGL mapping)
 *
 * Core PRP and SGL mapping code, shared by the NVMe device models.
 * This code is in the QEMU security boundary.
 *
 * CMB/PMR address handling is NOT in core — the test device provides
 * CMB/PMR-aware implementations (nvme_map_addr/addr_read/
 * addr_write/is_dma_addr, test/ctrl.c) which this code calls
 * directly. The test device is the only device model using the core
 * at this point; dispatch through a QOM base class arrives with the
 * production device.
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
/* PRP mapping                                                         */
/* ------------------------------------------------------------------ */

static uint16_t nvme_map_prp(NvmeCtrlBase *n, NvmeSg *sg, uint64_t prp1,
                             uint64_t prp2, uint32_t len)
{
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;
    uint16_t status;
    int ret;

    trace_pci_nvme_map_prp(trans_len, len, prp1, prp2, num_prps);

    nvme_sg_init(n, sg, nvme_is_dma_addr(n, prp1));

    status = nvme_map_addr(n, sg, prp1, trans_len);
    if (status) {
        goto unmap;
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
            ret = nvme_addr_read(n, prp2, (void *)prp_list, prp_trans);
            if (ret) {
                trace_pci_nvme_err_addr_read(prp2);
                status = NVME_DATA_TRAS_ERROR;
                goto unmap;
            }
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == nents - 1 && len > n->page_size) {
                    if (unlikely(prp_ent & (n->page_size - 1))) {
                        trace_pci_nvme_err_invalid_prplist_ent(prp_ent);
                        status = NVME_INVALID_PRP_OFFSET | NVME_DNR;
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    nents = MIN(nents, n->max_prp_ents);
                    prp_trans = nents * sizeof(uint64_t);
                    ret = nvme_addr_read(n, prp_ent, (void *)prp_list,
                                         prp_trans);
                    if (ret) {
                        trace_pci_nvme_err_addr_read(prp_ent);
                        status = NVME_DATA_TRAS_ERROR;
                        goto unmap;
                    }
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (unlikely(prp_ent & (n->page_size - 1))) {
                    trace_pci_nvme_err_invalid_prplist_ent(prp_ent);
                    status = NVME_INVALID_PRP_OFFSET | NVME_DNR;
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                status = nvme_map_addr(n, sg, prp_ent, trans_len);
                if (status) {
                    goto unmap;
                }

                len -= trans_len;
                i++;
            }
        } else {
            if (unlikely(prp2 & (n->page_size - 1))) {
                trace_pci_nvme_err_invalid_prp2_align(prp2);
                status = NVME_INVALID_PRP_OFFSET | NVME_DNR;
                goto unmap;
            }
            status = nvme_map_addr(n, sg, prp2, len);
            if (status) {
                goto unmap;
            }
        }
    }

    return NVME_SUCCESS;

unmap:
    nvme_sg_unmap(sg);
    return status;
}

/* ------------------------------------------------------------------ */
/* SGL mapping                                                         */
/* ------------------------------------------------------------------ */

/*
 * Map 'nsgld' data descriptors from 'segment'. The function will subtract the
 * number of bytes mapped in len.
 */
static uint16_t nvme_map_sgl_data(NvmeCtrlBase *n, NvmeSg *sg,
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

        status = nvme_map_addr(n, sg, addr, trans_len);
        if (status) {
            return status;
        }

        *len -= trans_len;
    }

    return NVME_SUCCESS;
}

uint16_t nvme_map_sgl(NvmeCtrlBase *n, NvmeSg *sg, NvmeSglDescriptor sgl,
                     size_t len, NvmeCmd *cmd)
{
#define SEG_CHUNK_SIZE 256

    QEMU_UNINITIALIZED NvmeSglDescriptor segment[SEG_CHUNK_SIZE];
    NvmeSglDescriptor *sgld, *last_sgld;
    uint64_t nsgld;
    uint32_t seg_len;
    uint16_t status;
    hwaddr addr;
    int ret;

    sgld = &sgl;
    addr = le64_to_cpu(sgl.addr);

    trace_pci_nvme_map_sgl(NVME_SGL_TYPE(sgl.type), len);

    nvme_sg_init(n, sg, nvme_is_dma_addr(n, addr));

    if (NVME_SGL_TYPE(sgl.type) == NVME_SGL_DESCR_TYPE_DATA_BLOCK) {
        status = nvme_map_sgl_data(n, sg, sgld, 1, &len, cmd);
        if (status) {
            goto unmap;
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
            if (nvme_addr_read(n, addr, segment, sizeof(segment))) {
                trace_pci_nvme_err_addr_read(addr);
                status = NVME_DATA_TRAS_ERROR;
                goto unmap;
            }

            status = nvme_map_sgl_data(n, sg, segment, SEG_CHUNK_SIZE,
                                       &len, cmd);
            if (status) {
                goto unmap;
            }

            nsgld -= SEG_CHUNK_SIZE;
            addr += SEG_CHUNK_SIZE * sizeof(NvmeSglDescriptor);
        }

        ret = nvme_addr_read(n, addr, segment, nsgld *
                             sizeof(NvmeSglDescriptor));
        if (ret) {
            trace_pci_nvme_err_addr_read(addr);
            status = NVME_DATA_TRAS_ERROR;
            goto unmap;
        }

        last_sgld = &segment[nsgld - 1];

        if (NVME_SGL_TYPE(last_sgld->type) == NVME_SGL_DESCR_TYPE_DATA_BLOCK) {
            status = nvme_map_sgl_data(n, sg, segment, nsgld, &len, cmd);
            if (status) {
                goto unmap;
            }
            goto out;
        }

        if (NVME_SGL_TYPE(sgld->type) == NVME_SGL_DESCR_TYPE_LAST_SEGMENT) {
            status = NVME_INVALID_SGL_SEG_DESCR | NVME_DNR;
            goto unmap;
        }

        sgld = last_sgld;
        addr = le64_to_cpu(sgld->addr);

        status = nvme_map_sgl_data(n, sg, segment, nsgld - 1, &len, cmd);
        if (status) {
            goto unmap;
        }

        if (len == prev_len) {
            status = NVME_INVALID_SGL_SEG_DESCR | NVME_DNR;
            goto unmap;
        }
    }

out:
    if (len) {
        status = NVME_DATA_SGL_LEN_INVALID | NVME_DNR;
        goto unmap;
    }

    return NVME_SUCCESS;

unmap:
    nvme_sg_unmap(sg);
    return status;
}

uint16_t nvme_map_dptr(NvmeCtrlBase *n, NvmeSg *sg, size_t len, NvmeCmd *cmd)
{
    uint64_t prp1, prp2;

    switch (NVME_CMD_FLAGS_PSDT(cmd->flags)) {
    case NVME_PSDT_PRP:
        prp1 = le64_to_cpu(cmd->dptr.prp1);
        prp2 = le64_to_cpu(cmd->dptr.prp2);
        return nvme_map_prp(n, sg, prp1, prp2, len);
    case NVME_PSDT_SGL_MPTR_CONTIGUOUS:
    case NVME_PSDT_SGL_MPTR_SGL:
        return nvme_map_sgl(n, sg, cmd->dptr.sgl, len, cmd);
    default:
        return NVME_INVALID_FIELD;
    }
}
