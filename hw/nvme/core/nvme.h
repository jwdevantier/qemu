/*
 * QEMU NVM Express
 *
 * Copyright (c) 2012 Intel Corporation
 * Copyright (c) 2021 Minwoo Im
 * Copyright (c) 2021 Samsung Electronics Co., Ltd.
 *
 * Authors:
 *   Keith Busch            <kbusch@kernel.org>
 *   Klaus Jensen           <k.jensen@samsung.com>
 *   Gollu Appalanaidu      <anaidu.gollu@samsung.com>
 *   Dmitry Fomichev        <dmitry.fomichev@wdc.com>
 *   Minwoo Im              <minwoo.im.dev@gmail.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#ifndef HW_NVME_NVME_H
#define HW_NVME_NVME_H

#include "qemu/log.h"
#include "qemu/aiocb.h"
#include "hw/pci/pci_device.h"
#include "hw/block/block.h"

#include "block/nvme.h"

#define NVME_MAX_CONTROLLERS 256
#define NVME_MAX_NAMESPACES  256

/*
 * The controller only supports Submission and Completion Queue Entry Sizes of
 * 64 and 16 bytes respectively.
 */
#define NVME_SQES 6
#define NVME_CQES 4

QEMU_BUILD_BUG_ON(NVME_MAX_NAMESPACES > NVME_NSID_BROADCAST - 1);

#define NVME_GUEST_ERR(trace, fmt, ...) \
    do { \
        (trace_##trace)(__VA_ARGS__); \
        qemu_log_mask(LOG_GUEST_ERROR, #trace \
            " in %s: " fmt "\n", __func__, ## __VA_ARGS__); \
    } while (0)

typedef struct NvmeCtrlBase NvmeCtrlBase;
typedef struct NvmeNamespaceBase NvmeNamespaceBase;

/*
 * Namespace device parameters: the base carries only the "legacy"
 * (drive-backed, controller-embedded) namespace with nsid 1. The
 * test device defines its own NvmeNamespaceParams (see test/nvme.h)
 * with the configurable namespace parameters (zoned, FDP, DIF, ...).
 */
typedef struct NvmeNamespaceParamsBase {
    uint32_t    nsid;
} NvmeNamespaceParamsBase;

/*
 * The shared namespace state: block configuration, geometry and the
 * Identify Namespace structure. The test device extends this into
 * NvmeNamespace (see test/nvme.h) with the namespace features (zoned,
 * FDP, DIF, atomic writes).
 */
typedef struct NvmeNamespaceBase {
    DeviceState  parent_obj;
    BlockConf    blkconf;
    int64_t      size;
    int64_t      moff;
    NvmeIdNs     id_ns;
    NvmeLBAF     lbaf;
    unsigned int nlbaf;
    size_t       lbasz;
    uint8_t      csi;
    uint16_t     status;
    int          attached;

    NvmeNamespaceParamsBase params;

    /* NULL for shared namespaces; set to specific controller if private */
    NvmeCtrlBase *ctrl;
} NvmeNamespaceBase;

static inline uint32_t nvme_nsid(NvmeNamespaceBase *ns)
{
    if (ns) {
        return ns->params.nsid;
    }

    return 0;
}

static inline size_t nvme_l2b(NvmeNamespaceBase *ns, uint64_t lba)
{
    return lba << ns->lbaf.ds;
}

static inline size_t nvme_m2b(NvmeNamespaceBase *ns, uint64_t lba)
{
    return ns->lbaf.ms * lba;
}

static inline int64_t nvme_moff(NvmeNamespaceBase *ns, uint64_t lba)
{
    return ns->moff + nvme_m2b(ns, lba);
}

static inline bool nvme_ns_ext(NvmeNamespaceBase *ns)
{
    return !!NVME_ID_NS_FLBAS_EXTENDED(ns->id_ns.flbas);
}
typedef struct NvmeAsyncEvent {
    QTAILQ_ENTRY(NvmeAsyncEvent) entry;
    NvmeAerResult result;
} NvmeAsyncEvent;

enum {
    NVME_SG_ALLOC = 1 << 0,
    NVME_SG_DMA   = 1 << 1,
};

typedef struct NvmeSg {
    int flags;

    union {
        QEMUSGList   qsg;
        QEMUIOVector iov;
    };
} NvmeSg;

typedef enum NvmeTxDirection {
    NVME_TX_DIRECTION_TO_DEVICE   = 0,
    NVME_TX_DIRECTION_FROM_DEVICE = 1,
} NvmeTxDirection;

typedef struct NvmeRequest {
    struct NvmeSQueue       *sq;
    struct NvmeNamespaceBase    *ns;
    BlockAIOCB              *aiocb;
    uint16_t                status;
    void                    *opaque;
    NvmeCqe                 cqe;
    NvmeCmd                 cmd;
    BlockAcctCookie         acct;
    NvmeSg                  sg;
    unsigned                flags;  /* device-defined request flags */
    QTAILQ_ENTRY(NvmeRequest)entry;
    /*
     * If you add a new field here, please make sure to update
     * nvme_vmstate_request, pre_save_validate_aer_req() and
     * pre_save_validate_cq_req().
     */
} NvmeRequest;

static inline const char *nvme_adm_opc_str(uint8_t opc)
{
    switch (opc) {
    case NVME_ADM_CMD_DELETE_SQ:        return "NVME_ADM_CMD_DELETE_SQ";
    case NVME_ADM_CMD_CREATE_SQ:        return "NVME_ADM_CMD_CREATE_SQ";
    case NVME_ADM_CMD_GET_LOG_PAGE:     return "NVME_ADM_CMD_GET_LOG_PAGE";
    case NVME_ADM_CMD_DELETE_CQ:        return "NVME_ADM_CMD_DELETE_CQ";
    case NVME_ADM_CMD_CREATE_CQ:        return "NVME_ADM_CMD_CREATE_CQ";
    case NVME_ADM_CMD_IDENTIFY:         return "NVME_ADM_CMD_IDENTIFY";
    case NVME_ADM_CMD_ABORT:            return "NVME_ADM_CMD_ABORT";
    case NVME_ADM_CMD_SET_FEATURES:     return "NVME_ADM_CMD_SET_FEATURES";
    case NVME_ADM_CMD_GET_FEATURES:     return "NVME_ADM_CMD_GET_FEATURES";
    case NVME_ADM_CMD_ASYNC_EV_REQ:     return "NVME_ADM_CMD_ASYNC_EV_REQ";
    case NVME_ADM_CMD_NS_ATTACHMENT:    return "NVME_ADM_CMD_NS_ATTACHMENT";
    case NVME_ADM_CMD_DIRECTIVE_SEND:   return "NVME_ADM_CMD_DIRECTIVE_SEND";
    case NVME_ADM_CMD_VIRT_MNGMT:       return "NVME_ADM_CMD_VIRT_MNGMT";
    case NVME_ADM_CMD_DIRECTIVE_RECV:   return "NVME_ADM_CMD_DIRECTIVE_RECV";
    case NVME_ADM_CMD_DBBUF_CONFIG:     return "NVME_ADM_CMD_DBBUF_CONFIG";
    case NVME_ADM_CMD_FORMAT_NVM:       return "NVME_ADM_CMD_FORMAT_NVM";
    case NVME_ADM_CMD_SECURITY_SEND:    return "NVME_ADM_CMD_SECURITY_SEND";
    case NVME_ADM_CMD_SECURITY_RECV:    return "NVME_ADM_CMD_SECURITY_RECV";
    default:                            return "NVME_ADM_CMD_UNKNOWN";
    }
}

static inline const char *nvme_io_opc_str(uint8_t opc)
{
    switch (opc) {
    case NVME_CMD_FLUSH:            return "NVME_NVM_CMD_FLUSH";
    case NVME_CMD_WRITE:            return "NVME_NVM_CMD_WRITE";
    case NVME_CMD_READ:             return "NVME_NVM_CMD_READ";
    case NVME_CMD_COMPARE:          return "NVME_NVM_CMD_COMPARE";
    case NVME_CMD_WRITE_ZEROES:     return "NVME_NVM_CMD_WRITE_ZEROES";
    case NVME_CMD_DSM:              return "NVME_NVM_CMD_DSM";
    case NVME_CMD_VERIFY:           return "NVME_NVM_CMD_VERIFY";
    case NVME_CMD_COPY:             return "NVME_NVM_CMD_COPY";
    case NVME_CMD_ZONE_MGMT_SEND:   return "NVME_ZONED_CMD_MGMT_SEND";
    case NVME_CMD_ZONE_MGMT_RECV:   return "NVME_ZONED_CMD_MGMT_RECV";
    case NVME_CMD_ZONE_APPEND:      return "NVME_ZONED_CMD_ZONE_APPEND";
    default:                        return "NVME_NVM_CMD_UNKNOWN";
    }
}

typedef struct NvmeSQueue {
    struct NvmeCtrlBase *ctrl;
    uint16_t    sqid;
    uint16_t    cqid;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    size;
    uint64_t    dma_addr;
    uint64_t    db_addr;
    uint64_t    ei_addr;
    QEMUBH      *bh;
    EventNotifier notifier;
    NvmeRequest *io_req;
    QTAILQ_HEAD(, NvmeRequest) req_list;
    QTAILQ_HEAD(, NvmeRequest) out_req_list;
    QTAILQ_ENTRY(NvmeSQueue) entry;
} NvmeSQueue;

typedef struct NvmeCQueue {
    struct NvmeCtrlBase *ctrl;
    uint8_t     phase;
    uint16_t    cqid;
    uint32_t    head;
    uint32_t    tail;
    int         vector;
    uint32_t    size;
    uint64_t    dma_addr;
    uint64_t    db_addr;
    uint64_t    ei_addr;
    QEMUBH      *bh;
    EventNotifier notifier;
    QTAILQ_HEAD(, NvmeSQueue) sq_list;
    QTAILQ_HEAD(, NvmeRequest) req_list;
} NvmeCQueue;

/*
 * Controller device parameters. The test device derives its own
 * NvmeParams (see test/nvme.h) with the configurable test device
 * parameters (cmb_size_mb, zasl, sr-iov, ...).
 */
typedef struct NvmeParamsBase {
    char     *serial;
    uint32_t max_ioqpairs;
    uint8_t  mdts;
    uint8_t  aerl;
} NvmeParamsBase;

typedef struct NvmeCtrlBase {
    PCIDevice    parent_obj;
    MemoryRegion bar0;
    NvmeBar      bar;
    NvmeParamsBase params;

    bool        qs_created;
    uint32_t    page_size;
    uint16_t    page_bits;
    uint16_t    max_prp_ents;
    uint32_t    max_q_ents;
    uint8_t     outstanding_aers;
    uint64_t    starttime_ms;
    uint16_t    temperature;
    uint8_t     smart_critical_warning;
    uint32_t    conf_msix_qsize;
    uint32_t    conf_ioqpairs;

    NvmeRequest **aer_reqs;
    QTAILQ_HEAD(, NvmeAsyncEvent) aer_queue;

    uint32_t    dmrsl;

    NvmeNamespaceBase   namespace;
    NvmeNamespaceBase   *namespaces[NVME_MAX_NAMESPACES + 1];
    uint32_t        num_queues;
    NvmeSQueue      **sq;
    NvmeCQueue      **cq;
    NvmeSQueue      admin_sq;
    NvmeCQueue      admin_cq;
    NvmeIdCtrl      id_ctrl;

    struct {
        struct {
            uint16_t temp_thresh_hi;
            uint16_t temp_thresh_low;
        };

        uint32_t                async_config;
        NvmeHostBehaviorSupport hbs;
    } features;

    uint32_t    dn; /* Disable Normal */

    /* Socket mapping to SPDM over NVMe Security In/Out commands */
    int spdm_socket;

    /* Migration-related stuff */
    Error *migration_blocker;

    struct {
        struct {
            int pending;
        } intx;
    } irq;
} NvmeCtrlBase;

typedef enum NvmeResetType {
    NVME_RESET_FUNCTION   = 0,
    NVME_RESET_CONTROLLER = 1,
} NvmeResetType;

static inline NvmeNamespaceBase *nvme_ns(NvmeCtrlBase *n, uint32_t nsid)
{
    if (!nsid || nsid > NVME_MAX_NAMESPACES) {
        return NULL;
    }

    return n->namespaces[nsid];
}

static inline NvmeCQueue *nvme_cq(NvmeRequest *req)
{
    NvmeSQueue *sq = req->sq;

    return sq->ctrl->cq[sq->cqid];
}

static inline NvmeCtrlBase *nvme_ctrl_base(NvmeRequest *req)
{
    NvmeSQueue *sq = req->sq;
    return sq->ctrl;
}

static inline uint16_t nvme_cid(NvmeRequest *req)
{
    if (!req) {
        return 0xffff;
    }

    return le16_to_cpu(req->cqe.cid);
}

uint16_t nvme_map_dptr(NvmeCtrlBase *n, NvmeSg *sg, size_t len,
                       NvmeCmd *cmd);

/*
 * Inline helpers shared by core/ and test/. These are small, hot
 * functions that benefit from inlining and only reference NvmeCtrlBase fields
 * already defined in this header.
 */

static inline void nvme_req_clear(NvmeRequest *req)
{
    req->ns = NULL;
    req->opaque = NULL;
    req->aiocb = NULL;
    memset(&req->cqe, 0x0, sizeof(req->cqe));
    req->status = NVME_SUCCESS;
    req->flags = 0;
}

static inline void nvme_sg_init(NvmeCtrlBase *n, NvmeSg *sg, bool dma)
{
    if (dma) {
        pci_dma_sglist_init(&sg->qsg, PCI_DEVICE(n), 0);
        sg->flags = NVME_SG_DMA;
    } else {
        qemu_iovec_init(&sg->iov, 0);
    }

    sg->flags |= NVME_SG_ALLOC;
}

static inline void nvme_sg_unmap(NvmeSg *sg)
{
    if (!(sg->flags & NVME_SG_ALLOC)) {
        return;
    }

    if (sg->flags & NVME_SG_DMA) {
        qemu_sglist_destroy(&sg->qsg);
    } else {
        qemu_iovec_destroy(&sg->iov);
    }

    memset(sg, 0x0, sizeof(*sg));
}

static inline bool nvme_addr_is_iomem(NvmeCtrlBase *n, hwaddr addr)
{
    hwaddr hi, lo;

    lo = n->bar0.addr;
    hi = lo + int128_get64(n->bar0.size);

    return addr >= lo && addr < hi;
}

/*
 * CMB/PMR-aware address operations, implemented by the test device
 * (test/ctrl.c). The test device is the only device model using the
 * core at this point, so core/dptr.c calls these directly; dispatch
 * through a QOM base class arrives with the production device ("move
 * device dispatch hooks to a QOM base class").
 */
uint16_t nvme_map_addr(NvmeCtrlBase *n, NvmeSg *sg, hwaddr addr, size_t len);
int nvme_addr_read(NvmeCtrlBase *n, hwaddr addr, void *buf, int size);
int nvme_addr_write(NvmeCtrlBase *n, hwaddr addr, const void *buf, int size);
bool nvme_is_dma_addr(NvmeCtrlBase *n, hwaddr addr);

/*
 * Functions implemented in core/dptr.c and core/dma.c. Declared here so
 * the device models can call them.
 */
uint16_t nvme_map_sgl(NvmeCtrlBase *n, NvmeSg *sg, NvmeSglDescriptor sgl,
                      size_t len, NvmeCmd *cmd);

uint16_t nvme_tx(NvmeCtrlBase *n, NvmeSg *sg, void *ptr, uint32_t len,
                 NvmeTxDirection dir);
uint16_t nvme_c2h(NvmeCtrlBase *n, void *ptr, size_t len, uint32_t hostlen,
                  NvmeRequest *req);
uint16_t nvme_h2c(NvmeCtrlBase *n, void *ptr, uint32_t len, NvmeRequest *req);

void nvme_blk_read(BlockBackend *blk, int64_t offset, uint32_t align,
                   BlockCompletionFunc *cb, NvmeRequest *req);
void nvme_blk_write(BlockBackend *blk, int64_t offset, uint32_t align,
                    BlockCompletionFunc *cb, NvmeRequest *req);

/*
 * Interrupt delivery implemented in core/irq.c. Declared here so
 * the device models can call it.
 */
void nvme_irq_check_intx(NvmeCtrlBase *n);
void nvme_irq_msix(NvmeCtrlBase *n, int vector);
void nvme_irq_msi(NvmeCtrlBase *n);

#endif /* HW_NVME_NVME_H */
