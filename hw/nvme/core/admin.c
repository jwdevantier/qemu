/*
 * QEMU NVM Express generic admin command semantics (core)
 *
 * The admin command dispatcher installed as the NvmeBaseClass
 * admin_cmd default (see core/base.c), along with the generic
 * payloads it owns: the Abort Command and the Asynchronous Event
 * Request; a device model extends or restricts the set through the
 * admin_cmd_custom class hook.
 *
 * This code is covered by the QEMU security policy.
 *
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include "qemu/osdep.h"
#include "system/block-backend.h"
#include "hw/nvme/trace.h"
#include "hw/nvme/core/nvme.h"

/*
 * Abort Command (NVM Express 1.4 Section 5.1): find the command on
 * the given submission queue and either cancel the block operation
 * in flight, or, for a command on the Admin Submission Queue that
 * has no counterpart in the block layer (i.e. an outstanding
 * Asynchronous Event Request), retract it from the AER array.
 */
uint16_t nvme_abort(NvmeCtrlBase *n, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(req->cmd.cdw10);
    uint16_t sqid = dw10 & 0xffff;
    uint16_t cid = (dw10 >> 16) & 0xffff;
    NvmeSQueue *sq;
    NvmeRequest *r, *next;
    int i;

    req->cqe.result = cpu_to_le32(1);

    if (nvme_check_sqid(n, sqid)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    sq = n->sq[sqid];

    if (sqid == 0) {
        for (i = 0; i < n->outstanding_aers; i++) {
            NvmeRequest *areq = n->aer_reqs[i];

            if (nvme_cid(areq) == cid) {
                memmove(n->aer_reqs + i, n->aer_reqs + i + 1,
                        (n->outstanding_aers - i - 1) *
                        sizeof(NvmeRequest *));
                n->outstanding_aers--;

                areq->status = NVME_CMD_ABORT_REQ;
                req->cqe.result = cpu_to_le32(0);
                nvme_enqueue_req_completion(&n->admin_cq, areq);

                return NVME_SUCCESS;
            }
        }
    }

    QTAILQ_FOREACH_SAFE(r, &sq->out_req_list, entry, next) {
        if (nvme_cid(r) == cid) {
            if (r->aiocb) {
                r->status = NVME_CMD_ABORT_REQ;
                blk_aio_cancel_async(r->aiocb);
            }
            /* the command was aborted (or is abortable): result 0 */
            req->cqe.result = cpu_to_le32(0);
            break;
        }
    }

    return NVME_SUCCESS;
}

/*
 * Asynchronous Event Request (NVM Express 1.4 Section 5.2): park the
 * request; it completes when the device model enqueues an event.
 */
uint16_t nvme_aer(NvmeCtrlBase *n, NvmeRequest *req)
{
    NvmeBaseClass *bc = NVME_BASE_GET_CLASS(n);

    trace_pci_nvme_aer(nvme_cid(req));

    if (n->outstanding_aers > n->params.aerl) {
        trace_pci_nvme_aer_aerl_exceeded();
        return NVME_AER_LIMIT_EXCEEDED | NVME_DNR;
    }

    n->aer_reqs[n->outstanding_aers] = req;
    n->outstanding_aers++;

    if (!QTAILQ_EMPTY(&n->aer_queue) && bc->process_aers) {
        bc->process_aers(n);
    }

    return NVME_NO_COMPLETE;
}

/*
 * Admin sub-dispatch of the command set defined by the base class
 * defaults: queue creation/deletion, abort, AER and the shadow
 * doorbell buffer configuration. Called either from the
 * admin_cmd default (below) or directly from a device-override of
 * admin_cmd that chains generic commands here.
 */
uint16_t nvme_admin_default(NvmeCtrlBase *n, NvmeRequest *req)
{
    NvmeBaseClass *bc = NVME_BASE_GET_CLASS(n);

    switch (req->cmd.opcode) {
    case NVME_ADM_CMD_DELETE_SQ:
        return nvme_del_sq(n, req);
    case NVME_ADM_CMD_CREATE_SQ:
        return nvme_create_sq(n, req);
    case NVME_ADM_CMD_DELETE_CQ:
        return nvme_del_cq(n, req);
    case NVME_ADM_CMD_CREATE_CQ:
        return nvme_create_cq(n, req);
    case NVME_ADM_CMD_ABORT:
        return nvme_abort(n, req);
    case NVME_ADM_CMD_ASYNC_EV_REQ:
        return nvme_aer(n, req);
    case NVME_ADM_CMD_DBBUF_CONFIG:
        return nvme_dbbuf_config(n, req);
    default:
        break;
    }

    return bc->admin_cmd_custom(n, req);
}

/*
 * Base-class admin_cmd default: the admin commands are PRP-only and
 * must not be fused on NVMe over PCIe; anything outside the generic
 * set is delegated to the device's admin_cmd_custom.
 */
uint16_t nvme_admin_cmd(NvmeCtrlBase *n, NvmeRequest *req)
{
    trace_pci_nvme_admin_cmd(nvme_cid(req), req->sq->sqid, req->cmd.opcode,
                             nvme_adm_opc_str(req->cmd.opcode));

    if (NVME_CMD_FLAGS_PSDT(req->cmd.flags) != NVME_PSDT_PRP) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (NVME_CMD_FLAGS_FUSE(req->cmd.flags)) {
        return NVME_INVALID_FIELD;
    }

    return nvme_admin_default(n, req);
}

/*
 * Base-class admin_cmd_custom default: reject any command outside the
 * generic admin set.
 */
uint16_t nvme_admin_cmd_custom(NvmeCtrlBase *n, NvmeRequest *req)
{
    return NVME_INVALID_OPCODE | NVME_DNR;
}
