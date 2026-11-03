
/*
 * QEMU NVM Express Production Controller (vnvme)
 *
 * Hardened, minimal NVMe I/O controller.  Only the mandatory subset of the
 * NVMe specification is emulated; everything else (ZNS, CMB, PMR, FDP, copy,
 * metadata, DIF, SR-IOV, SPDM, migration, ...) is intentionally absent and
 * lives in the test device (hw/nvme/test/).
 *
 * This device is covered by the QEMU security policy.
 *
 * Design principles
 * -----------------
 *  - Deferred processing via bottom halves: the doorbell handlers do as
 *    little work as possible (update the tail/head, schedule the SQ/CQ
 *    bottom half) and return, so the trapped vCPU resumes immediately.
 *  - Shadow doorbell buffer (DBBUF) support with the ioeventfd
 *    offload for the io queue doorbells (see core/queue.c). DBBUF is
 *    guest opt-in; there is no ioeventfd opt-in property.
 *  - MSI-X only: one vector per CQ (admin CQ = vector 0).
 *  - Single private namespace via the 'drive' block property.
 *  - No metadata, no DIF, no bounce buffers.
 *
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "system/accel-irq.h"
#include "hw/pci/pci.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "migration/blocker.h"
#include "block/block_int.h"
#include "system/block-backend.h"
#include "system/system.h"
#include "qemu/timer.h"

#include "hw/nvme/core/nvme.h"
#include "hw/nvme/trace.h"

#define NVME_SPEC_VER       0x00010400
#define NVME_DB_SIZE        4
#define NVME_PAGE_SIZE      4096
#define NVME_MPS_SHIFT      0
#define NVME_PAGE_MASK      (NVME_PAGE_SIZE - 1)

#define VNVME_CAP_MQES      0x7ff
#define VNVME_VID           0x1b36
#define VNVME_SVID          0x1b36
#define VNVME_IEEE_OUI0     0x00
#define VNVME_IEEE_OUI1     0x54
#define VNVME_IEEE_OUI2     0x52
#define VNVME_SN            "VNVMETEST"
#define VNVME_MN            "QEMU NVMe Prod Controller"
#define VNVME_FR            "RFC00001"

#define VNVME_FRMW_NUM_SLOTS  1
#define VNVME_FRMW_SLOT1_RO 1

#define VNVME_TEMPERATURE           0x143
#define VNVME_TEMPERATURE_WARNING   0x157

/*
 * Asynchronous Event Request Limit. Fixed, not a property: vnvme never
 * queues asynchronous events (NvmeBaseClass.process_aers stays NULL),
 * so this only feeds the identify value and the size of the AER parking
 * array.
 */
#define VNVME_AERL         3

/*
 * Maximum Data Transfer Size, in units of the emulated memory page size
 * (CAP.MPSMIN; vnvme pins MPS to NVME_PAGE_SIZE). Fixed at 2 MiB, not a
 * property: the mapping path's worst case is a fully-scattered PRP
 * transfer - one iovec per page, ~514 at 2 MiB - which has to stay
 * inside the dma-helpers IOV_MAX budget. Supporting MDTS above 9 takes
 * the IOV_MAX lifting (see the lift-iovmax-dma-limit work).
 */
#define VNVME_MDTS         9
QEMU_BUILD_BUG_ON((NVME_PAGE_SIZE << VNVME_MDTS) != 2 * MiB);

enum {
    NVME_AQA_MAX = 0xfff,
};

static const bool vnvme_feature_support[NVME_FID_MAX] = {
    [NVME_ARBITRATION]              = true,
    [NVME_POWER_MANAGEMENT]         = true,
    [NVME_TEMPERATURE_THRESHOLD]    = true,
    [NVME_ERROR_RECOVERY]           = true,
    [NVME_VOLATILE_WRITE_CACHE]     = true,
    [NVME_NUMBER_OF_QUEUES]         = true,
    [NVME_INTERRUPT_VECTOR_CONF]    = true,
    [NVME_WRITE_ATOMICITY]          = true,
    [NVME_ASYNCHRONOUS_EVENT_CONF]  = true,
};

static const uint32_t vnvme_feature_cap[NVME_FID_MAX] = {
    [NVME_TEMPERATURE_THRESHOLD]    = NVME_FEAT_CAP_CHANGE,
    [NVME_VOLATILE_WRITE_CACHE]     = NVME_FEAT_CAP_CHANGE,
    [NVME_NUMBER_OF_QUEUES]         = NVME_FEAT_CAP_CHANGE,
    [NVME_WRITE_ATOMICITY]          = NVME_FEAT_CAP_CHANGE,
    [NVME_ASYNCHRONOUS_EVENT_CONF]  = NVME_FEAT_CAP_CHANGE,
};


static void vnvme_req_complete(NvmeRequest *req)
{
    nvme_enqueue_req_completion(nvme_cq(req), req);
}

static void vnvme_misc_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;

    trace_pci_nvme_misc_cb(nvme_cid(req));

    if (ret) {
        if (!req->status) {
            req->status = NVME_INTERNAL_DEV_ERROR;
        }
        trace_pci_nvme_err_aio(nvme_cid(req), strerror(-ret), req->status);
    }

    vnvme_req_complete(req);
}

static void vnvme_rw_complete_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    NvmeNamespaceBase *ns = req->ns;
    BlockBackend *blk = ns->blkconf.blk;
    BlockAcctCookie *acct = &req->acct;
    BlockAcctStats *stats = blk_get_stats(blk);

    trace_pci_nvme_rw_complete_cb(nvme_cid(req), blk_name(blk));

    if (ret) {
        block_acct_failed(stats, acct);
        switch (req->cmd.opcode) {
        case NVME_CMD_READ:
            req->status = NVME_UNRECOVERED_READ;
            break;
        case NVME_CMD_WRITE:
        case NVME_CMD_WRITE_ZEROES:
            req->status = NVME_WRITE_FAULT;
            break;
        default:
            req->status = NVME_INTERNAL_DEV_ERROR;
            break;
        }
        trace_pci_nvme_err_aio(nvme_cid(req), strerror(-ret), req->status);
    } else {
        block_acct_done(stats, acct);
    }

    vnvme_req_complete(req);
}

static inline uint16_t vnvme_check_mdts(VnvmeCtrl *n, size_t len)
{
    uint8_t mdts = n->params.mdts;

    if (mdts && len > n->page_size << mdts) {
        trace_pci_nvme_err_mdts(len);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static inline uint16_t vnvme_check_bounds(NvmeNamespaceBase *ns, uint64_t slba,
                                          uint32_t nlb)
{
    uint64_t nsze = le64_to_cpu(ns->id_ns.nsze);

    if (unlikely(UINT64_MAX - slba < nlb || slba + nlb > nsze)) {
        trace_pci_nvme_err_invalid_lba_range(slba, nlb, nsze);
        return NVME_LBA_RANGE | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static uint16_t vnvme_map_data(VnvmeCtrl *n, uint32_t nlb, NvmeRequest *req,
                               NvmeTxDirection dir)
{
    NvmeNamespaceBase *ns = req->ns;
    size_t len = nvme_l2b(ns, nlb);

    return nvme_map_dptr(n, &req->map, len, &req->cmd, dir);
}

static uint16_t vnvme_read(VnvmeCtrl *n, NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)&req->cmd;
    NvmeNamespaceBase *ns = req->ns;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = (uint32_t)le16_to_cpu(rw->nlb) + 1;
    uint64_t data_size = nvme_l2b(ns, nlb);
    BlockBackend *blk = ns->blkconf.blk;
    uint16_t status;

    trace_pci_nvme_read(nvme_cid(req), nvme_nsid(ns), nlb, data_size, slba);

    status = vnvme_check_mdts(n, data_size);
    if (status) {
        goto invalid;
    }

    status = vnvme_check_bounds(ns, slba, nlb);
    if (status) {
        goto invalid;
    }

    status = vnvme_map_data(n, nlb, req, NVME_TX_DIRECTION_FROM_DEVICE);
    if (status) {
        goto invalid;
    }

    nvme_map_wrap(&req->map, &req->iov);

    block_acct_start(blk_get_stats(blk), &req->acct, data_size,
                     BLOCK_ACCT_READ);
    nvme_blk_read(blk, nvme_l2b(ns, slba),
                  vnvme_rw_complete_cb, req);
    return NVME_NO_COMPLETE;

invalid:
    block_acct_invalid(blk_get_stats(blk), BLOCK_ACCT_READ);
    return status | NVME_DNR;
}

static uint16_t vnvme_do_write(VnvmeCtrl *n, NvmeRequest *req, bool wrz)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)&req->cmd;
    NvmeNamespaceBase *ns = req->ns;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb = (uint32_t)le16_to_cpu(rw->nlb) + 1;
    uint64_t data_size = nvme_l2b(ns, nlb);
    BlockBackend *blk = ns->blkconf.blk;
    uint16_t status;

    trace_pci_nvme_write(nvme_cid(req), nvme_io_opc_str(rw->opcode),
                         nvme_nsid(ns), nlb, data_size, slba);

    if (!wrz) {
        status = vnvme_check_mdts(n, data_size);
        if (status) {
            goto invalid;
        }
    }

    status = vnvme_check_bounds(ns, slba, nlb);
    if (status) {
        goto invalid;
    }

    if (!wrz) {
        status = vnvme_map_data(n, nlb, req, NVME_TX_DIRECTION_TO_DEVICE);
        if (status) {
            goto invalid;
        }

        nvme_map_wrap(&req->map, &req->iov);

        block_acct_start(blk_get_stats(blk), &req->acct, data_size,
                         BLOCK_ACCT_WRITE);
        nvme_blk_write(blk, nvme_l2b(ns, slba),
                       vnvme_rw_complete_cb, req);
    } else {
        req->aiocb = blk_aio_pwrite_zeroes(blk, nvme_l2b(ns, slba),
                                           data_size, BDRV_REQ_MAY_UNMAP,
                                           vnvme_rw_complete_cb, req);
    }

    return NVME_NO_COMPLETE;

invalid:
    block_acct_invalid(blk_get_stats(blk), BLOCK_ACCT_WRITE);
    return status | NVME_DNR;
}

static uint16_t vnvme_write(VnvmeCtrl *n, NvmeRequest *req)
{
    return vnvme_do_write(n, req, false);
}

static uint16_t vnvme_write_zeroes(VnvmeCtrl *n, NvmeRequest *req)
{
    return vnvme_do_write(n, req, true);
}

static uint16_t vnvme_flush(VnvmeCtrl *n, NvmeRequest *req)
{
    NvmeNamespaceBase *ns = req->ns;

    req->aiocb = blk_aio_flush(ns->blkconf.blk, vnvme_misc_cb, req);
    return NVME_NO_COMPLETE;
}

typedef struct VnvmeDsmState {
    NvmeDsmRange *ranges;
    uint32_t nr;
    uint32_t idx;
    int ret;
} VnvmeDsmState;

static void vnvme_dsm_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    VnvmeDsmState *st = req->opaque;
    NvmeNamespaceBase *ns = req->ns;
    VnvmeCtrl *n = nvme_ctrl_base(req);
    int error;

    if (st->ret < 0) {
        goto done;
    }
    if (ret < 0) {
        st->ret = ret;
        goto done;
    }

    while (st->idx < st->nr) {
        NvmeDsmRange *r = &st->ranges[st->idx++];
        uint64_t slba = le64_to_cpu(r->slba);
        uint32_t nlb = le32_to_cpu(r->nlb);

        trace_pci_nvme_dsm_deallocate(slba, nlb);

        if (nlb == 0) {
            continue;
        }

        if (nlb > n->dmrsl) {
            nlb = n->dmrsl;
        }

        if (vnvme_check_bounds(ns, slba, nlb)) {
            continue;
        }

        req->aiocb = blk_aio_pdiscard(ns->blkconf.blk, nvme_l2b(ns, slba),
                                      nvme_l2b(ns, nlb), vnvme_dsm_cb, req);
        return;
    }

done:
    error = st->ret;
    g_free(st->ranges);
    g_free(st);
    req->opaque = NULL;

    if (error < 0 && !req->status) {
        req->status = NVME_INTERNAL_DEV_ERROR;
    }
    vnvme_req_complete(req);
}

static uint16_t vnvme_dsm(VnvmeCtrl *n, NvmeRequest *req)
{
    NvmeDsmCmd *dsm = (NvmeDsmCmd *)&req->cmd;
    uint32_t attr = le32_to_cpu(dsm->attributes);
    uint32_t nr = (le32_to_cpu(dsm->nr) & 0xff) + 1;
    VnvmeDsmState *st;
    uint16_t status;

    if (!(attr & NVME_DSMGMT_AD)) {
        return NVME_SUCCESS;
    }

    st = g_new0(VnvmeDsmState, 1);
    st->ranges = g_new(NvmeDsmRange, nr);
    st->nr = nr;
    st->idx = 0;
    st->ret = 0;

    status = nvme_h2c(n, (uint8_t *)st->ranges, sizeof(NvmeDsmRange) * nr, req);
    if (status) {
        g_free(st->ranges);
        g_free(st);
        return status | NVME_DNR;
    }

    req->opaque = st;
    vnvme_dsm_cb(req, 0);
    return NVME_NO_COMPLETE;
}

static uint16_t vnvme_io_cmd(VnvmeCtrl *n, NvmeRequest *req)
{
    uint32_t nsid = le32_to_cpu(req->cmd.nsid);
    NvmeNamespaceBase *ns;

    /*
     * The production device is single-namespace, hardcoded to NSID 1.
     * A 'flush all namespaces' targets the one namespace; any other
     * NSID that does not address it is rejected with Invalid Namespace
     * Or Format.
     */
    if (nsid == NVME_NSID_BROADCAST &&
        req->cmd.opcode == NVME_CMD_FLUSH) {
        nsid = 1;
    }

    ns = nvme_ns(n, nsid);
    if (!ns) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    if (ns->status) {
        return ns->status | NVME_DNR;
    }

    if (NVME_CMD_FLAGS_FUSE(req->cmd.flags)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    req->ns = ns;

    switch (req->cmd.opcode) {
    case NVME_CMD_READ:
        return vnvme_read(n, req);
    case NVME_CMD_WRITE:
        return vnvme_write(n, req);
    case NVME_CMD_WRITE_ZEROES:
        return vnvme_write_zeroes(n, req);
    case NVME_CMD_DSM:
        return vnvme_dsm(n, req);
    case NVME_CMD_FLUSH:
        return vnvme_flush(n, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

/* --- Identify --- */

static uint16_t vnvme_identify_ctrl(VnvmeCtrl *n, NvmeRequest *req)
{
    trace_pci_nvme_identify_ctrl();
    return nvme_c2h(n, (uint8_t *)&n->id_ctrl, sizeof(NvmeIdCtrl),
            NVME_IDENTIFY_DATA_SIZE, req);
}

static uint16_t vnvme_identify_ns(VnvmeCtrl *n, NvmeRequest *req)
{
    NvmeIdentify *c = (NvmeIdentify *)&req->cmd;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint32_t nn = le32_to_cpu(n->id_ctrl.nn);
    NvmeNamespaceBase *ns;

    /* ctrl does not support the NS management capability.
     * so checking separately for 0xFFFFFFFF is not necessary */
    if (!nsid || nsid > nn) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = nvme_ns(n, nsid);
    if (unlikely(!ns)) {
        /* invalid NS */
        g_autofree NvmeIdNs *id_ns = g_malloc0(sizeof(NvmeIdNs));
        return nvme_c2h(n, (uint8_t *)id_ns, sizeof(*id_ns),
                        NVME_IDENTIFY_DATA_SIZE, req);
    }

    trace_pci_nvme_identify_ns(nsid);
    return nvme_c2h(n, (uint8_t *)&ns->id_ns, sizeof(NvmeIdNs),
            NVME_IDENTIFY_DATA_SIZE, req);
}

static uint16_t vnvme_identify_ns_list(VnvmeCtrl *n, NvmeRequest *req)
{
    NvmeIdentify *c = (NvmeIdentify *)&req->cmd;
    uint32_t min_nsid = le32_to_cpu(c->nsid);
    uint32_t list[NVME_IDENTIFY_DATA_SIZE / sizeof(uint32_t)] = {};

    trace_pci_nvme_identify_nslist(min_nsid);

    /*
     * The list returns namespaces with ids *higher* than the NSID
     * specified in the command (NVM Express v1.4, Section 5.15.4).
     */
    if (min_nsid >= NVME_NSID_BROADCAST - 1) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    /* nsid 1 is the only namespace; it is active iff a drive is bound */
    if (n->namespaces[1] != NULL && min_nsid == 0) {
        list[0] = cpu_to_le32(1);
    }

    return nvme_c2h(n, (uint8_t *)list, sizeof(list),
            NVME_IDENTIFY_DATA_SIZE, req);
}

static uint16_t vnvme_identify_ns_descr_list(VnvmeCtrl *n, NvmeRequest *req)
{
    NvmeIdentify *c = (NvmeIdentify *)&req->cmd;
    NvmeNamespaceBase *ns;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint8_t list[NVME_IDENTIFY_DATA_SIZE] = {};
    uint8_t *pos = list;
    struct {
        NvmeIdNsDescr hdr;
        uint8_t v[NVME_NIDL_UUID];
    } QEMU_PACKED uuid = {};
    struct {
        NvmeIdNsDescr hdr;
        uint8_t v;
    } QEMU_PACKED csi = {};
    const char *serial;
    QemuUUID ns_uuid;

    trace_pci_nvme_identify_ns_descr_list(nsid);

    if (!nsid || nsid == NVME_NSID_BROADCAST || !nvme_ns(n, nsid)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    ns = nvme_ns(n, nsid);

    /*
     * vnvme exposes no configurable namespace identifiers; the UUID is
     * derived from the effective serial (the serial parameter if set,
     * the default SN otherwise) and the nsid, so it is stable across
     * boots and migration. See core/ns.c.
     */
    serial = n->params.serial;
    if (!serial || !serial[0]) {
        serial = VNVME_SN;
    }

    nvme_ns_derive_uuid(serial, nsid, &ns_uuid);

    uuid.hdr.nidt = NVME_NIDT_UUID;
    uuid.hdr.nidl = NVME_NIDL_UUID;
    memcpy(uuid.v, ns_uuid.data, NVME_NIDL_UUID);
    memcpy(pos, &uuid, sizeof(uuid));
    pos += sizeof(uuid);

    csi.hdr.nidt = NVME_NIDT_CSI;
    csi.hdr.nidl = NVME_NIDL_CSI;
    csi.v = ns->csi;
    memcpy(pos, &csi, sizeof(csi));
    pos += sizeof(csi);

    return nvme_c2h(n, list, sizeof(list),
            NVME_IDENTIFY_DATA_SIZE, req);
}

static uint16_t vnvme_identify(VnvmeCtrl *n, NvmeRequest *req)
{
    NvmeIdentify *c = (NvmeIdentify *)&req->cmd;

    trace_pci_nvme_identify(nvme_cid(req), c->cns, 0, 0);

    switch (c->cns) {
    case NVME_ID_CNS_CTRL:
        return vnvme_identify_ctrl(n, req);
    case NVME_ID_CNS_NS:
        return vnvme_identify_ns(n, req);
    case NVME_ID_CNS_NS_ACTIVE_LIST:
        return vnvme_identify_ns_list(n, req);
    case NVME_ID_CNS_NS_DESCR_LIST:
        return vnvme_identify_ns_descr_list(n, req);
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
}

/* --- Get / Set Features --- */

static uint16_t vnvme_get_feature(VnvmeCtrl *n, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(req->cmd.cdw10);
    uint32_t dw11 = le32_to_cpu(req->cmd.cdw11);
    uint8_t fid = dw10 & 0xff;
    uint32_t result = 0;

    trace_pci_nvme_getfeat(nvme_cid(req), le32_to_cpu(req->cmd.nsid), fid,
                           dw10 >> 8 & 0xf, dw11);

    if (!vnvme_feature_support[fid]) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    switch (fid) {
    case NVME_TEMPERATURE_THRESHOLD:
        result = 0;
        if (NVME_TEMP_TMPSEL(dw11) == NVME_TEMP_TMPSEL_COMPOSITE &&
            NVME_TEMP_THSEL(dw11) == NVME_TEMP_THSEL_OVER) {
            result = VNVME_TEMPERATURE_WARNING;
        }
        break;
    case NVME_NUMBER_OF_QUEUES:
        result = (n->conf_ioqpairs - 1) | ((n->conf_ioqpairs - 1) << 16);
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        result = dw11 & 0xffff;
        break;
    case NVME_WRITE_ATOMICITY:
        result = n->dn;
        break;
    case NVME_ARBITRATION:
        result = NVME_ARB_AB_NOLIMIT;
        break;
    default:
        result = 0;
        break;
    }

    req->cqe.result = cpu_to_le32(result);
    return NVME_SUCCESS;
}

static uint16_t vnvme_set_feature(VnvmeCtrl *n, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(req->cmd.cdw10);
    uint32_t dw11 = le32_to_cpu(req->cmd.cdw11);
    uint8_t fid = dw10 & 0xff;

    trace_pci_nvme_setfeat(nvme_cid(req), le32_to_cpu(req->cmd.nsid), fid,
                           dw10 >> 8 & 0xf, dw11);

    if (!vnvme_feature_support[fid]) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (!(vnvme_feature_cap[fid] & NVME_FEAT_CAP_CHANGE)) {
        return NVME_FEAT_NOT_CHANGEABLE | NVME_DNR;
    }

    switch (fid) {
    case NVME_VOLATILE_WRITE_CACHE:
        if (n->namespace.blkconf.blk) {
            blk_set_enable_write_cache(n->namespace.blkconf.blk, dw11 & 1);
        }
        break;
    case NVME_NUMBER_OF_QUEUES:
        if (n->qs_created) {
            return NVME_CMD_SEQ_ERROR | NVME_DNR;
        }
        if ((dw11 & 0xffff) == 0xffff || ((dw11 >> 16) & 0xffff) == 0xffff) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        req->cqe.result = cpu_to_le32((n->conf_ioqpairs - 1) |
                                       ((n->conf_ioqpairs - 1) << 16));
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        n->features.async_config = dw11;
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        if (NVME_TEMP_TMPSEL(dw11) == NVME_TEMP_TMPSEL_COMPOSITE) {
            if (NVME_TEMP_THSEL(dw11) == NVME_TEMP_THSEL_OVER) {
                n->features.temp_thresh_hi = dw11 & 0xffff;
            } else {
                n->features.temp_thresh_low = dw11 & 0xffff;
            }
        }
        break;
    case NVME_WRITE_ATOMICITY:
        n->dn = dw11 & 1;
        break;
    default:
        break;
    }

    return NVME_SUCCESS;
}

/* --- Create / Delete SQ / CQ --- */

/* --- Get Log Page --- */

static uint16_t vnvme_smart_info(VnvmeCtrl *n, uint32_t len, uint64_t off,
                                  NvmeRequest *req)
{
    NvmeSmartLog smart = {};

    if (off >= sizeof(smart)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    uint32_t buf_len = sizeof(smart) - off;

    smart.critical_warning = n->smart_critical_warning;
    smart.temperature = cpu_to_le16(n->temperature);

    smart.power_on_hours[0] =
        cpu_to_le64((qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) - n->starttime_ms)
                     / 3600 / 1000);

    if (n->namespace.blkconf.blk) {
        BlockAcctStats *stats = blk_get_stats(n->namespace.blkconf.blk);
        smart.data_units_read[0] =
            cpu_to_le64(stats->nr_ops[BLOCK_ACCT_READ] / 1000);
        smart.data_units_written[0] =
            cpu_to_le64(stats->nr_ops[BLOCK_ACCT_WRITE] / 1000);
        smart.host_read_commands[0] =
            cpu_to_le64(stats->nr_ops[BLOCK_ACCT_READ]);
        smart.host_write_commands[0] =
            cpu_to_le64(stats->nr_ops[BLOCK_ACCT_WRITE]);
    }

    uint32_t trans_len = MIN(buf_len, len);

    return nvme_c2h(n, (uint8_t *)&smart + off, trans_len, len, req);
}

static uint16_t vnvme_error_info(VnvmeCtrl *n, uint32_t len, uint64_t off,
                                  NvmeRequest *req)
{
    NvmeErrorLog err = {};

    if (off >= sizeof(err)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    uint32_t buf_len = sizeof(err) - off;

    uint32_t trans_len = MIN(buf_len, len);

    return nvme_c2h(n, (uint8_t *)&err + off, trans_len, len, req);
}

static uint16_t vnvme_fw_log_info(VnvmeCtrl *n, uint32_t len, uint64_t off,
                                   NvmeRequest *req)
{
    NvmeFwSlotInfoLog fw_log = { .afi = 0x1 };

    if (off >= sizeof(fw_log)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    uint32_t buf_len = sizeof(fw_log) - off;

    strpadcpy((char *)fw_log.frs1, sizeof(fw_log.frs1), "1.0", ' ');

    uint32_t trans_len = MIN(buf_len, len);

    return nvme_c2h(n, (uint8_t *)&fw_log + off, trans_len, len, req);
}

static uint16_t vnvme_get_log(VnvmeCtrl *n, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(req->cmd.cdw10);
    uint32_t dw11 = le32_to_cpu(req->cmd.cdw11);
    uint32_t dw12 = le32_to_cpu(req->cmd.cdw12);
    uint8_t lid = dw10 & 0xff;
    uint8_t rae = (dw10 >> 8) & 0xf;
    uint32_t len = ((dw10 >> 16) | ((uint32_t)dw11 << 16)) + 1;
    uint64_t off = ((uint64_t)dw12 |
                    ((uint64_t)le32_to_cpu(req->cmd.cdw13) << 32));

    trace_pci_nvme_get_log(nvme_cid(req), lid, 0, rae, len, off);

    switch (lid) {
    case NVME_LOG_ERROR_INFO:
        return vnvme_error_info(n, len, off, req);
    case NVME_LOG_SMART_INFO:
        return vnvme_smart_info(n, len, off, req);
    case NVME_LOG_FW_SLOT_INFO:
        return vnvme_fw_log_info(n, len, off, req);
    default:
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

/* --- Abort and AER are generic: see core/queue.c --- */

/* --- Admin dispatch --- */

/*
 * Commands beyond the generic set handled by the base-class admin_cmd
 * default (core/queue.c): the restricted production set of identify,
 * log page and feature semantics.
 */
static uint16_t vnvme_admin_cmd_custom(NvmeCtrlBase *bn, NvmeRequest *req)
{
    VnvmeCtrl *n = (VnvmeCtrl *)bn;

    switch (req->cmd.opcode) {
    case NVME_ADM_CMD_GET_LOG_PAGE:
        return vnvme_get_log(n, req);
    case NVME_ADM_CMD_IDENTIFY:
        return vnvme_identify(n, req);
    case NVME_ADM_CMD_SET_FEATURES:
        return vnvme_set_feature(n, req);
    case NVME_ADM_CMD_GET_FEATURES:
        return vnvme_get_feature(n, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

/* --- SQ processing (deferred via bottom half) --- */

/* --- Doorbell processing --- */

static void vnvme_process_db(VnvmeCtrl *n, hwaddr offset, uint32_t val)
{
    if (offset == NVME_MAX_DB + 0x0) {
        NvmeSQueue *sq = &n->admin_sq;
        trace_pci_nvme_mmio_doorbell_sq(0, val & 0xffff);
        if (n->dbbuf_enabled) {
            /*
             * Keep the shadow doorbell in sync with this MMIO write and
             * kick the processing through the event notifier; the
             * notifier handler re-reads the tail from the shadow
             * buffer.
             */
            stl_le_pci_dma(PCI_DEVICE(n), sq->db_addr, val & (sq->size - 1),
                           MEMTXATTRS_UNSPECIFIED);

            if (NVME_CSTS_RDY(le32_to_cpu(n->bar.csts))) {
                event_notifier_set(&sq->notifier);
            }

            return;
        }

        sq->tail = val & (sq->size - 1);
        if (NVME_CSTS_RDY(le32_to_cpu(n->bar.csts))) {
            qemu_bh_schedule(sq->bh);
        }
        return;
    }

    if (offset == NVME_MAX_DB + 0x4) {
        NvmeCQueue *cq = &n->admin_cq;
        trace_pci_nvme_mmio_doorbell_cq(0, val & 0xffff);
        /* deferred cqe posting if the queue was previously full */
        if (nvme_cq_full(cq)) {
            qemu_bh_schedule(cq->bh);
        }
        if (n->dbbuf_enabled) {
            /*
             * Keep the shadow doorbell in sync with this MMIO write and
             * kick the processing through the event notifier; the
             * notifier handler re-reads the head from the shadow
             * buffer.
             */
            stl_le_pci_dma(PCI_DEVICE(n), cq->db_addr, val & (cq->size - 1),
                           MEMTXATTRS_UNSPECIFIED);

            event_notifier_set(&cq->notifier);

            return;
        }

        cq->head = val & (cq->size - 1);
        nvme_cq_kick(cq);
        return;
    }

    if ((offset - NVME_MAX_DB) & 0x4) {
        /* CQ doorbell */
        uint16_t cqid = (offset - NVME_MAX_DB - 0x4) >> 3;
        NvmeCQueue *cq;

        if (nvme_check_cqid(n, cqid)) {
            return;
        }
        cq = n->cq[cqid];
        trace_pci_nvme_mmio_doorbell_cq(cqid, val & 0xffff);
        /* deferred cqe posting if the queue was previously full */
        if (nvme_cq_full(cq)) {
            qemu_bh_schedule(cq->bh);
        }
        cq->head = val & (cq->size - 1);
        nvme_cq_kick(cq);
    } else {
        /* SQ doorbell */
        uint16_t sqid = (offset - NVME_MAX_DB) >> 3;
        NvmeSQueue *sq;

        if (nvme_check_sqid(n, sqid)) {
            return;
        }
        sq = n->sq[sqid];
        trace_pci_nvme_mmio_doorbell_sq(sqid, val & 0xffff);
        sq->tail = val & (sq->size - 1);
        qemu_bh_schedule(sq->bh);
    }
}

/* --- Controller start / stop --- */

static int vnvme_start_ctrl(VnvmeCtrl *n)
{
    uint32_t cc = le32_to_cpu(n->bar.cc);
    uint32_t aqa = le32_to_cpu(n->bar.aqa);
    uint64_t asq = le64_to_cpu(n->bar.asq);
    uint64_t acq = le64_to_cpu(n->bar.acq);
    uint32_t page_bits = NVME_CC_MPS(cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (n->sq[0] || n->cq[0]) {
        return -1;
    }
    if (asq & (page_size - 1) || acq & (page_size - 1)) {
        return -1;
    }
    if (!NVME_AQA_ASQS(aqa) || !NVME_AQA_ACQS(aqa)) {
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = page_size;
    n->max_prp_ents = page_size / sizeof(uint64_t);

    nvme_init_cq(&n->admin_cq, n, acq, 0, 0, NVME_AQA_ACQS(aqa) + 1, 1);
    nvme_init_sq(&n->admin_sq, n, asq, 0, 0, NVME_AQA_ASQS(aqa) + 1);

    n->starttime_ms = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    n->temperature = VNVME_TEMPERATURE;
    n->features.temp_thresh_hi = VNVME_TEMPERATURE_WARNING;

    if (msix_enabled(PCI_DEVICE(n)) && accel_msi_via_irqfd_enabled()) {
        msix_set_vector_notifiers(PCI_DEVICE(n), nvme_irqchip_vector_unmask,
                                  nvme_irqchip_vector_mask,
                                  nvme_irqchip_vector_poll);
    }

    stl_le_p(&n->bar.csts, NVME_CSTS_READY);
    return 0;
}

static void vnvme_disable_ctrl(VnvmeCtrl *n)
{
    int i;

    /*
     * Cancel and wait out every inflight command on every queue first. A
     * reset is not required to be preceded by the guest's graceful Delete
     * I/O SQ/CQ sequence, so requests must not be freed below while a
     * blk_aio_* completion for them could still be in flight.
     */
    for (i = 0; i < n->num_queues; i++) {
        if (n->sq[i]) {
            nvme_sq_cancel_inflight(n->sq[i], NVME_CMD_ABORT_SQ_DEL);
        }
    }

    for (i = 1; i < n->num_queues; i++) {
        if (n->sq[i]) {
            nvme_free_sq(n->sq[i]);
        }
        if (n->cq[i]) {
            nvme_free_cq(n->cq[i]);
        }
    }

    /* Delete any pending scheduled BHs before freeing the admin queue. */
    qemu_bh_delete(n->admin_sq.bh);
    n->admin_sq.bh = NULL;
    qemu_bh_delete(n->admin_cq.bh);
    n->admin_cq.bh = NULL;

    g_free(n->admin_sq.io_req);
    n->admin_sq.io_req = NULL;

    n->bar.cc = 0;
    n->bar.csts = 0;
    n->dbbuf_dbs = 0;
    n->dbbuf_eis = 0;
    n->dbbuf_enabled = false;
    n->admin_sq.head = n->admin_sq.tail = 0;
    n->admin_cq.head = n->admin_cq.tail = 0;
    n->admin_sq.dma_addr = n->admin_cq.dma_addr = 0;
    n->admin_sq.size = n->admin_cq.size = 0;
    n->qs_created = false;
    n->outstanding_aers = 0;
    n->sq[0] = NULL;
    n->cq[0] = NULL;
}

static void vnvme_reset(VnvmeCtrl *n)
{
    if (NVME_CSTS_RDY(le32_to_cpu(n->bar.csts))) {
        vnvme_disable_ctrl(n);
    }
}

/* --- MMIO --- */

static uint64_t vnvme_mmio_read(void *opaque, hwaddr offset, unsigned size)
{
    VnvmeCtrl *n = VNVME(opaque);
    uint8_t *ptr = (uint8_t *)&n->bar;

    trace_pci_nvme_mmio_read(offset, size);

    if (offset + size > sizeof(n->bar)) {
        return 0;
    }

    switch (size) {
    case 4:
        return ldl_le_p(ptr + offset);
    case 8:
        return ldq_le_p(ptr + offset);
    default:
        return 0;
    }
}

/*
 * BAR register write. All the registers are 32-bit except the admin
 * queue addresses (ASQ/ACQ), which are 64-bit fields programmed with
 * separate low/high word accesses or with a single native-width 64-bit
 * write (vnvme_mmio_write() rejects 64-bit accesses anywhere else).
 */
static void vnvme_mmio_write_reg(VnvmeCtrl *n, hwaddr offset, uint64_t val,
                                 unsigned size)
{
    switch (offset) {
    case offsetof(NvmeBar, cc): {
        uint32_t old_cc = le32_to_cpu(n->bar.cc);
        uint32_t new_cc = val;
        bool was_en = NVME_CC_EN(old_cc);
        bool now_en = NVME_CC_EN(new_cc);

        n->bar.cc = cpu_to_le32(new_cc);

        trace_pci_nvme_mmio_cfg(new_cc);

        if (!was_en && now_en) {
            if (vnvme_start_ctrl(n) < 0) {
                trace_pci_nvme_err_startfail();
                stl_le_p(&n->bar.csts, NVME_CSTS_FAILED);
            } else {
                trace_pci_nvme_mmio_start_success();
            }
        } else if (was_en && !now_en) {
            trace_pci_nvme_mmio_stopped();
            vnvme_disable_ctrl(n);
        }
        break;
    }
    case offsetof(NvmeBar, aqa):
        stl_le_p(&n->bar.aqa, val);
        break;
    case offsetof(NvmeBar, asq):
        stn_le_p(&n->bar.asq, size, val);
        break;
    case offsetof(NvmeBar, asq) + 4:
        stl_le_p((uint8_t *)&n->bar.asq + 4, val);
        break;
    case offsetof(NvmeBar, acq):
        stn_le_p(&n->bar.acq, size, val);
        break;
    case offsetof(NvmeBar, acq) + 4:
        stl_le_p((uint8_t *)&n->bar.acq + 4, val);
        break;
    case offsetof(NvmeBar, intms): {
        uint32_t intms = le32_to_cpu(n->bar.intms) | val;

        stl_le_p(&n->bar.intms, intms);
        n->bar.intmc = n->bar.intms;
        trace_pci_nvme_mmio_intm_set(val & 0xffffffff, intms);
        nvme_irq_do_intx(n);
        break;
    }
    case offsetof(NvmeBar, intmc): {
        uint32_t intms = le32_to_cpu(n->bar.intms) & ~val;

        stl_le_p(&n->bar.intms, intms);
        n->bar.intmc = n->bar.intms;
        trace_pci_nvme_mmio_intm_clr(val & 0xffffffff, intms);
        nvme_irq_do_intx(n);
        break;
    }
    default:
        break;
    }
}

static void vnvme_mmio_write(void *opaque, hwaddr offset, uint64_t val,
                             unsigned size)
{
    VnvmeCtrl *n = VNVME(opaque);

    trace_pci_nvme_mmio_write(offset, val, size);

    if (offset >= NVME_MAX_DB) {
        if (unlikely(size == 8)) {
            /*
             * The doorbell registers are 32-bit; a 64-bit write
             * targets a portion of two doorbells. The host shall
             * access registers in their native width or in aligned
             * 32-bit accesses, so ignore it.
             */
            NVME_GUEST_ERR(pci_nvme_ub_mmiowr_spanning,
                           "MMIO write targets a portion of two or more "
                           "doorbell registers, offset=0x%"PRIx64", ignoring",
                           offset);
            return;
        }

        /*
         * The doorbell value is the 32-bit value written at the
         * doorbell offset.
         */
        vnvme_process_db(n, offset, val);
        return;
    }

    if (unlikely(size == 8 && offset != offsetof(NvmeBar, asq) &&
                 offset != offsetof(NvmeBar, acq))) {
        /*
         * The host shall access registers in their native width or in
         * aligned 32-bit accesses; accesses that target a portion of
         * two or more registers are not supported. Only the admin
         * queue addresses are 64-bit registers, so a 64-bit write
         * anywhere else is such an access: ignore it.
         */
        NVME_GUEST_ERR(pci_nvme_ub_mmiowr_spanning,
                       "MMIO write targets a portion of two or more "
                       "registers, offset=0x%"PRIx64", ignoring", offset);
        return;
    }

    vnvme_mmio_write_reg(n, offset, val, size);
}

static const MemoryRegionOps vnvme_mmio_ops = {
    .read = vnvme_mmio_read,
    .write = vnvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    /*
     * Accept 64-bit accesses as single dispatches on all paths (the
     * handler applies both halves of the register pairs itself)
     * instead of having the memory core split them.
     */
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

/* --- Namespace setup --- */

static int vnvme_ns_init_blk(NvmeNamespaceBase *ns, Error **errp)
{
    bool read_only;

    if (!blkconf_blocksizes(&ns->blkconf, errp)) {
        return -1;
    }

    read_only = !blk_supports_write_perm(ns->blkconf.blk);
    if (!blkconf_apply_backend_options(&ns->blkconf, read_only, false, errp)) {
        return -1;
    }

    if (ns->blkconf.discard_granularity == -1) {
        ns->blkconf.discard_granularity =
            MAX(ns->blkconf.logical_block_size, 4096);
    }

    ns->size = blk_getlength(ns->blkconf.blk);
    if (ns->size < 0) {
        error_setg_errno(errp, -ns->size, "could not get blockdev size");
        return -1;
    }

    return 0;
}

static void vnvme_ns_init_format(NvmeNamespaceBase *ns)
{
    NvmeIdNs *id_ns = &ns->id_ns;
    int64_t nlbas;

    ns->lbaf = id_ns->lbaf[NVME_ID_NS_FLBAS_INDEX(id_ns->flbas)];
    ns->lbasz = 1 << ns->lbaf.ds;

    nlbas = ns->size / (ns->lbasz + ns->lbaf.ms);

    id_ns->nsze = cpu_to_le64(nlbas);
    id_ns->ncap = id_ns->nsze;
    id_ns->nuse = id_ns->ncap;

    ns->moff = nlbas << ns->lbaf.ds;
}

static int vnvme_ns_init(NvmeNamespaceBase *ns, Error **errp)
{
    NvmeIdNs *id_ns = &ns->id_ns;
    uint8_t ds = 31 - clz32(ns->blkconf.logical_block_size);

    ns->csi = NVME_CSI_NVM;
    ns->status = 0;

    id_ns->dlfeat = 0x9;
    id_ns->nsfeat |= NVME_ID_NS_NSFEAT_DAE;

    id_ns->lbaf[0].ds = ds;
    ns->nlbaf = 1;
    id_ns->flbas = 0;
    id_ns->nlbaf = 0;

    vnvme_ns_init_format(ns);
    return 0;
}

static int vnvme_ns_setup(NvmeNamespaceBase *ns, Error **errp)
{
    if (vnvme_ns_init_blk(ns, errp)) {
        return -1;
    }
    if (vnvme_ns_init(ns, errp)) {
        return -1;
    }
    return 0;
}

/* --- Controller init --- */

static void vnvme_init_ctrl(VnvmeCtrl *n)
{
    NvmeIdCtrl *id = &n->id_ctrl;

    memset(id, 0, sizeof(*id));

    id->vid = cpu_to_le16(VNVME_VID);
    id->ssvid = cpu_to_le16(VNVME_SVID);
    id->ver = cpu_to_le32(NVME_SPEC_VER);
    id->ieee[0] = VNVME_IEEE_OUI0;
    id->ieee[1] = VNVME_IEEE_OUI1;
    id->ieee[2] = VNVME_IEEE_OUI2;
    id->cmic = 0;
    id->mdts = n->params.mdts;
    id->sqes = (NVME_SQES << 4) | NVME_SQES;
    id->cqes = (NVME_CQES << 4) | NVME_CQES;
    id->nn = cpu_to_le32(1);
    /*
     * vnvme does not support Format NVM: do not advertise it. Shadow
     * doorbell buffers are always supported (the Doorbell Buffer Config
     * command is handled by the shared base-class admin dispatch), so
     * advertise OACS.DBCS: without it, e.g. Linux never configures the
     * shadow doorbell buffers and takes a VM exit for every submission
     * doorbell write.
     */
    id->oacs = NVME_OACS_DBCS;
    id->acl = 3;
    id->aerl = n->params.aerl;
    id->frmw = (VNVME_FRMW_NUM_SLOTS << 1) | VNVME_FRMW_SLOT1_RO;
    id->lpa = 0;
    id->elpe = 0;
    id->npss = 0;
    id->wctemp = cpu_to_le16(VNVME_TEMPERATURE_WARNING);
    id->cctemp = cpu_to_le16(0x175);
    id->sgls = cpu_to_le32(NVME_CTRL_SGLS_SUPPORT_NO_ALIGN);
    id->fna = 0;
    id->oncs = cpu_to_le16(NVME_ONCS_WRITE_ZEROES | NVME_ONCS_DSM);
    id->vwc = NVME_VWC_NSID_BROADCAST_SUPPORT | NVME_VWC_PRESENT;
    id->cntrltype = 0x1; // I/O controller

    strpadcpy((char *)id->sn, sizeof(id->sn),
              (n->params.serial && n->params.serial[0]) ? n->params.serial
                                                        : VNVME_SN, ' ');
    strpadcpy((char *)id->mn, sizeof(id->mn), VNVME_MN, ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), VNVME_FR, ' ');

    snprintf((char *)id->subnqn, sizeof(id->subnqn),
             "nqn.2019-08.org.qemu:%s",
             (n->params.serial && n->params.serial[0]) ? n->params.serial
                                                        : VNVME_SN);
}

static void vnvme_init_bar(VnvmeCtrl *n)
{
    uint64_t cap = 0;

    NVME_CAP_SET_MQES(cap, VNVME_CAP_MQES);
    NVME_CAP_SET_CQR(cap, 1);
    NVME_CAP_SET_AMS(cap, 0);
    NVME_CAP_SET_TO(cap, 0);
    NVME_CAP_SET_DSTRD(cap, 0);
    NVME_CAP_SET_NSSRS(cap, 0);
    NVME_CAP_SET_CSS(cap, 0x1);
    NVME_CAP_SET_MPSMIN(cap, NVME_MPS_SHIFT);
    NVME_CAP_SET_MPSMAX(cap, NVME_MPS_SHIFT);

    n->bar.cap = cpu_to_le64(cap);
    n->bar.vs = cpu_to_le32(NVME_SPEC_VER);
    n->bar.cc = 0;
    n->bar.csts = 0;
    n->bar.aqa = 0;
    n->bar.asq = 0;
    n->bar.acq = 0;
}

static void vnvme_init_state(VnvmeCtrl *n)
{
    n->params.aerl = VNVME_AERL;
    n->params.mdts = VNVME_MDTS;

    n->conf_ioqpairs = n->params.max_ioqpairs;
    n->conf_msix_qsize = n->params.max_ioqpairs + 1;
    n->num_queues = n->params.max_ioqpairs + 1;

    n->sq = g_new0(NvmeSQueue *, n->num_queues);
    n->cq = g_new0(NvmeCQueue *, n->num_queues);
    n->temperature = VNVME_TEMPERATURE;
    n->starttime_ms = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    n->aer_reqs = g_new0(NvmeRequest *, n->params.aerl + 1);
    QTAILQ_INIT(&n->aer_queue);

    n->spdm_socket = -1;

    if (n->namespace.blkconf.blk) {
        n->dmrsl = BDRV_REQUEST_MAX_BYTES /
            MAX(1, 1 << (31 - clz32(n->namespace.blkconf.logical_block_size)));
    } else {
        n->dmrsl = 0;
    }
}

/* --- Realize / Exit --- */

static void vnvme_realize(PCIDevice *pci_dev, Error **errp)
{
    VnvmeCtrl *n = VNVME(pci_dev);
    Error *local_err = NULL;
    int ret;

    /* MMIO leaf region carrying the doorbell area (ioeventfd target) */
    n->db_region = &n->bar0;

    n->page_size = NVME_PAGE_SIZE;
    n->page_bits = 12;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);

    vnvme_init_state(n);

    if (n->namespace.blkconf.blk) {
        NvmeNamespaceBase *ns = &n->namespace;

        ns->params.nsid = 1;
        ns->ctrl = n;

        if (vnvme_ns_setup(ns, &local_err)) {
            error_propagate(errp, local_err);
            return;
        }

        n->namespaces[1] = ns;
        ns->attached++;
    }

    vnvme_init_bar(n);
    vnvme_init_ctrl(n);

    /* BAR0: controller registers + doorbells.
     * Size must be a power of 2 (PCI requirement).  sizeof(NvmeBar) is
     * 4096 (0x1000).  Admin doorbells start at 0x1000, I/O doorbells at
     * 0x1008.  Round up to the next power of two. */
    uint64_t bar_size = sizeof(n->bar) + NVME_MAX_DB +
                        (n->params.max_ioqpairs * 2 * NVME_DB_SIZE);
    bar_size = 1ULL << (64 - clz64(bar_size - 1));

    memory_region_init_io(&n->bar0, OBJECT(n), &vnvme_mmio_ops, n,
                          "vnvme-bar0", bar_size);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &n->bar0);

    ret = msix_init_exclusive_bar(pci_dev, n->params.max_ioqpairs + 1, 4,
                                  errp);
    if (ret < 0 && ret != -ENOTSUP) {
        return;
    }
    if (ret == -ENOTSUP) {
        warn_report_err(*errp);
        *errp = NULL;
        ret = msi_init(pci_dev, 0x60, 1, true, false, &local_err);
        if (ret < 0) {
            /*
             * Neither MSI-X nor MSI is supported (e.g. the sparc64 sabre
             * controller supports neither) - fall back to pin-based
             * interrupts like the test device does.
             */
            warn_report_err(local_err);
        }
    }

    nvme_irq_init_notifiers(n, n->params.max_ioqpairs + 1);

    pci_dev->config[PCI_INTERRUPT_PIN] = 1;

    pci_config_set_vendor_id(pci_dev->config, VNVME_VID);
    pci_config_set_device_id(pci_dev->config, VNVME_VID);
    pci_config_set_class(pci_dev->config, PCI_CLASS_STORAGE_EXPRESS);
    pci_config_set_prog_interface(pci_dev->config, 0x2);
    pci_config_set_revision(pci_dev->config, 2);
    pcie_endpoint_cap_init(pci_dev, 0x80);

    error_setg(&n->migration_blocker,
               "vnvme device does not support migration yet");
    if (migrate_add_blocker(&n->migration_blocker, errp) < 0) {
        return;
    }
}

static void vnvme_exit(PCIDevice *pci_dev)
{
    VnvmeCtrl *n = VNVME(pci_dev);

    vnvme_reset(n);

    nvme_irq_cleanup_notifiers(n);

    g_free(n->sq);
    g_free(n->cq);
    g_free(n->aer_reqs);
    g_free(n->admin_sq.io_req);

    migrate_del_blocker(&n->migration_blocker);
}

/* --- Properties, class init, type registration --- */

static const Property vnvme_props[] = {
    DEFINE_PROP_STRING("serial", VnvmeCtrl, params.serial),
    DEFINE_PROP_UINT32("num_queues", VnvmeCtrl, params.max_ioqpairs, 64),
    DEFINE_BLOCK_PROPERTIES(VnvmeCtrl, namespace.blkconf),
};

static void vnvme_class_init(ObjectClass *oc, const void *data)
{
    NvmeBaseClass *bc = NVME_BASE_CLASS(oc);
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    /* the base-class admin_cmd default handles the generic command
     * set (queue creation/deletion, abort, AER, shadow doorbell
     * buffer configuration); this adds the restricted production set */
    bc->io_cmd = vnvme_io_cmd;
    bc->admin_cmd_custom = vnvme_admin_cmd_custom;

    pc->realize = vnvme_realize;
    pc->exit = vnvme_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->revision = 2;

    dc->desc = "NVMe Production Controller (hardened, minimal)";
    device_class_set_props(dc, vnvme_props);
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->user_creatable = true;
}

static void vnvme_instance_init(Object *obj)
{
    VnvmeCtrl *n = VNVME(obj);

    /*
     * Like the test device's legacy namespace, the (only, embedded,
     * drive-backed) nsid 1 namespace is the boot device: expose its
     * bootindex as a controller property.
     */
    device_add_bootindex_property(obj, &n->namespace.blkconf.bootindex,
                                  "bootindex", "/namespace@1,0",
                                  DEVICE(obj));
}

static void vnvme_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_PCIE_DEVICE },
        { }
    };

    static TypeInfo info = {
        .name = TYPE_VNVME,
        .parent = TYPE_NVME_BASE,
        .instance_size = sizeof(VnvmeCtrl),
        .instance_init = vnvme_instance_init,
        .class_init = vnvme_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&info);
}

type_init(vnvme_register_types)
