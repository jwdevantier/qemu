/*
 * QEMU NVM Express — shared DMA transfer helpers
 *
 * Core transfer functions (controller-buffer ↔ guest DMA and direct block
 * I/O) for the NVMe device models. This
 * code is in the QEMU security boundary.
 *
 * Copyright (c) 2012, Intel Corporation
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include "qemu/osdep.h"
#include "system/dma.h"
#include "system/block-backend.h"
#include "hw/pci/pci.h"
#include "hw/nvme/core/nvme.h"
#include "hw/nvme/trace.h"

uint16_t nvme_tx(NvmeCtrl *n, NvmeSg *sg, void *ptr, uint32_t len,
                 NvmeTxDirection dir)
{
    assert(sg->flags & NVME_SG_ALLOC);

    if (sg->flags & NVME_SG_DMA) {
        const MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;

        if (dir == NVME_TX_DIRECTION_TO_DEVICE) {
            dma_buf_write(ptr, len, NULL, &sg->qsg, attrs);
        } else {
            dma_buf_read(ptr, len, NULL, &sg->qsg, attrs);
        }
    } else {
        if (dir == NVME_TX_DIRECTION_TO_DEVICE) {
            qemu_iovec_to_buf(&sg->iov, 0, ptr, len);
        } else {
            qemu_iovec_from_buf(&sg->iov, 0, ptr, len);
        }
    }

    return NVME_SUCCESS;
}

uint16_t nvme_c2h(NvmeCtrl *n, void *ptr, size_t len, uint32_t hostlen,
                  NvmeRequest *req)
{
    uint16_t status;

    status = nvme_map_dptr(n, &req->sg, hostlen, &req->cmd);
    if (status) {
        return status;
    }

    return nvme_tx(n, &req->sg, ptr, len, NVME_TX_DIRECTION_FROM_DEVICE);
}

uint16_t nvme_h2c(NvmeCtrl *n, void *ptr, uint32_t len, NvmeRequest *req)
{
    uint16_t status;

    status = nvme_map_dptr(n, &req->sg, len, &req->cmd);
    if (status) {
        return status;
    }

    return nvme_tx(n, &req->sg, ptr, len, NVME_TX_DIRECTION_TO_DEVICE);
}

void nvme_blk_read(BlockBackend *blk, int64_t offset, uint32_t align,
                   BlockCompletionFunc *cb, NvmeRequest *req)
{
    assert(req->sg.flags & NVME_SG_ALLOC);

    if (req->sg.flags & NVME_SG_DMA) {
        req->aiocb = dma_blk_read(blk, &req->sg.qsg, offset, align, cb, req);
    } else {
        req->aiocb = blk_aio_preadv(blk, offset, &req->sg.iov, 0, cb, req);
    }
}

void nvme_blk_write(BlockBackend *blk, int64_t offset, uint32_t align,
                    BlockCompletionFunc *cb, NvmeRequest *req)
{
    assert(req->sg.flags & NVME_SG_ALLOC);

    if (req->sg.flags & NVME_SG_DMA) {
        req->aiocb = dma_blk_write(blk, &req->sg.qsg, offset, align, cb, req);
    } else {
        req->aiocb = blk_aio_pwritev(blk, offset, &req->sg.iov, 0, cb, req);
    }
}
