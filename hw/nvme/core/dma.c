/*
 * QEMU NVM Express — shared DMA transfer helpers
 *
 * Core transfer functions (controller-buffer ↔ guest DMA and direct block
 * I/O) shared by the production (`vnvme`) and test (`nvme`) devices. This
 * code is in the QEMU security boundary.
 *
 * All transfers operate on eagerly mapped host buffers (NvmeMap) or views
 * carved out of them (NvmeRequest::iov); there is no scatter/gather
 * indirection left, so the block layer path is a plain blk_aio_preadv/
 * pwritev.
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

/*
 * Note that the transfer length may exceed the size of the mapping
 * (`hostlen` on the c2h path): short host buffers are tolerated and
 * the remaining bytes are simply left as-is.
 */
uint16_t nvme_tx(QEMUIOVector *iov, void *ptr, uint32_t len,
                 NvmeTxDirection dir)
{
    if (dir == NVME_TX_DIRECTION_TO_DEVICE) {
        qemu_iovec_to_buf(iov, 0, ptr, len);
    } else {
        qemu_iovec_from_buf(iov, 0, ptr, len);
    }

    return NVME_SUCCESS;
}

uint16_t nvme_c2h(NvmeCtrlBase *n, void *ptr, size_t len, uint32_t hostlen,
                  NvmeRequest *req)
{
    uint16_t status;

    /*
     * Map the host buffer, not the payload size: mapping `len` could
     * make nvme_map_prp() misinterpret PRP2 as a page pointer instead
     * of a PRP List pointer when the payload spans more than one but
     * less than two pages and the host buffer is larger.
     */
    status = nvme_map_dptr(n, &req->map, hostlen, &req->cmd,
                           NVME_TX_DIRECTION_FROM_DEVICE);
    if (status) {
        return status;
    }

    nvme_map_wrap(&req->map, &req->iov);

    return nvme_tx(&req->iov, ptr, len, NVME_TX_DIRECTION_FROM_DEVICE);
}

uint16_t nvme_h2c(NvmeCtrlBase *n, void *ptr, uint32_t len, NvmeRequest *req)
{
    uint16_t status;

    status = nvme_map_dptr(n, &req->map, len, &req->cmd,
                           NVME_TX_DIRECTION_TO_DEVICE);
    if (status) {
        return status;
    }

    nvme_map_wrap(&req->map, &req->iov);

    return nvme_tx(&req->iov, ptr, len, NVME_TX_DIRECTION_TO_DEVICE);
}

void nvme_blk_read(BlockBackend *blk, int64_t offset,
                   BlockCompletionFunc *cb, NvmeRequest *req)
{
    assert(req->iov.niov);

    req->aiocb = blk_aio_preadv(blk, offset, &req->iov, 0, cb, req);
}

void nvme_blk_write(BlockBackend *blk, int64_t offset,
                    BlockCompletionFunc *cb, NvmeRequest *req)
{
    assert(req->iov.niov);

    req->aiocb = blk_aio_pwritev(blk, offset, &req->iov, 0, cb, req);
}
