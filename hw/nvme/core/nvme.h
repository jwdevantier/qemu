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
#define NVME_MAX_DB         0x1000

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
 * Interrupt vector with the event notifier used to defer the actual
 * interrupt delivery to the main loop.
 */
typedef struct NvmeIV {
    NvmeCtrlBase *ctrl;

    EventNotifier notifier;
} NvmeIV;

/*
 * The production device state. It is the base state verbatim; the test
 * device derives from NvmeCtrlBase (see test/nvme.h).
 */
typedef struct NvmeCtrlBase VnvmeCtrl;

/*
 * Namespace device parameters shared with the production device: the
 * production device only ever uses the "legacy" (drive-backed,
 * controller-embedded) namespace with nsid 1. The test device defines
 * its own NvmeNamespaceParams (see test/nvme.h) with the configurable
 * namespace parameters (zoned, FDP, DIF, ...).
 */
typedef struct NvmeNamespaceParamsBase {
    uint32_t    nsid;
} NvmeNamespaceParamsBase;

/*
 * The shared namespace state: block configuration, geometry and the
 * Identify Namespace structure. The test device extends this into
 * NvmeNamespace (see test/nvme.h) with the namespace features (zoned,
 * FDP, DIF, atomic writes) that the production device does not
 * implement.
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

typedef enum NvmeTxDirection {
    NVME_TX_DIRECTION_TO_DEVICE   = 0,
    NVME_TX_DIRECTION_FROM_DEVICE = 1,
} NvmeTxDirection;

/*
 * An eagerly mapped data buffer: a QEMUIOVector of host memory
 * fragments, plus the bookkeeping required to release the underlying
 * mappings (see core/dptr.c).
 *
 * `frag` records the owned mappings, one per dma_memory_map() call or
 * bounce buffer; `iov` may hold sub-ranges of the fragments (the test
 * device carves data/metadata views out of a mapped buffer that holds
 * both interleaved).
 */
typedef struct NvmeMap {
    QEMUIOVector iov;

    struct {
        void   *ptr;    /* host pointer (mapping or bounce buffer) */
        size_t  len;    /* length of the mapping */
        hwaddr  addr;   /* guest address (bounce buffer writeback) */
        bool    bounce; /* malloc'd bounce buffer, not a mapping */
    } *frag;

    int nfrag;
    int dir;            /* NVME_TX_DIRECTION_* */
} NvmeMap;

typedef struct NvmeRequest {
    struct NvmeSQueue       *sq;
    struct NvmeNamespaceBase    *ns;
    BlockAIOCB              *aiocb;
    uint16_t                status;
    void                    *opaque;
    NvmeCqe                 cqe;
    NvmeCmd                 cmd;
    BlockAcctCookie         acct;
    NvmeMap                 map;
    QEMUIOVector            iov;    /* view into `map`, consumed by tx/blk_* */
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

#define TYPE_VNVME "vnvme"
#define VNVME(obj) \
        OBJECT_CHECK(VnvmeCtrl, (obj), TYPE_VNVME)

/*
 * Controller device parameters shared with the production device. The
 * test device derives its own NvmeParams (see test/nvme.h) with the
 * configurable test device parameters (cmb_size_mb, zasl, sr-iov,
 * ...).
 */
typedef struct NvmeParamsBase {
    char     *serial;
    uint32_t max_ioqpairs;
    uint8_t  mdts;
    uint8_t  aerl;

    /*
     * Deprecated: the io queue doorbell ioeventfd wiring (see
     * core/queue.c) is always attempted when a doorbell buffer is
     * configured. Kept for command line compatibility; ignored.
     */
    bool     ioeventfd;
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

    /*
     * Shadow doorbell buffer (DBBUF) state. The shadow addresses are
     * negotiated with the Doorbell Buffer Config admin command
     * (nvme_dbbuf_config, core/queue.c) and are common state: prod
     * supports the feature since relying on doorbell buffer traps is
     * a major virtualization performance bottleneck.
     */
    uint64_t    dbbuf_dbs;
    uint64_t    dbbuf_eis;
    bool        dbbuf_enabled;

    /*
     * MMIO leaf region that carries the doorbell area: the test device
     * registers its own "nvme" subregion on the BAR0 container, while
     * prod uses the BAR0 region itself. The dbbuf ioeventfd wiring (see
     * core/queue.c) attaches its event notifiers to this region.
     */
    MemoryRegion *db_region;

    /* Migration-related stuff */
    Error *migration_blocker;

    struct {
        NvmeIV *msix;

        struct {
            EventNotifier notifier;
        } msi;

        struct {
            int pending;
            EventNotifier notifier;
        } intx;
    } irq;
} NvmeCtrlBase;

/*
 * Abstract base class for the NVMe device models: the 'nvme' test
 * device and the 'vnvme' production device both derive from it.
 *
 * It holds the dispatch hooks that the shared core code invokes:
 * the submission queue bottom half runs the core's fetch loop
 * (nvme_process_sq in core/queue.c), which calls io_cmd()/admin_cmd()
 * and, if installed, sq_admit() before starting a fetched command.
 * These are per-class (constant after class_init), not per-instance
 * state.
 *
 * io_cmd() and admin_cmd() have no default and must be provided by
 * every device. sq_admit() is optional (a device whose submission
 * processing carries device-specific admission semantics installs
 * it; the test device holds back commands at atomic write batch
 * boundaries; the production device leaves it NULL): the core calls
 * it once a command has been fetched and its request set up, and a
 * decline makes the core put the request back, leave the command
 * unconsumed and retry on the next run of the bottom half.
 *
 * 'bounce' selects the policy for data pointers in memory that
 * address_space_map() cannot map directly (e.g. MMIO of another
 * device): the test device bounces such fragments through a host
 * buffer, while the hardened production device rejects the command
 * with a Data Transfer Error.
 *
 * Class defaults: core installs default implementations of
 * admin_cmd (the generic NVM Express admin command semantics) and
 * admin_cmd_custom (rejecting any command outside that set) in
 * nvme_base_class_init(); a device model inherits the generic
 * dispatcher and only overrides admin_cmd_custom to add its own
 * commands, or overrides admin_cmd entirely (the test device wraps
 * the generic dispatcher with its command-effects gate and its
 * extended command set).
 *
 * 'process_aers' is called by the core default AER handler when
 * asynchronous events are queued; the test device installs its
 * event dispatcher, the production device never queues events and
 * leaves it NULL.
 */
typedef struct NvmeBaseClass {
    PCIDeviceClass parent_class;

    uint16_t (*io_cmd)(NvmeCtrlBase *n, NvmeRequest *req);
    uint16_t (*admin_cmd)(NvmeCtrlBase *n, NvmeRequest *req);
    uint16_t (*admin_cmd_custom)(NvmeCtrlBase *n, NvmeRequest *req);
    bool (*sq_admit)(NvmeSQueue *sq, NvmeRequest *req);
    void (*process_aers)(NvmeCtrlBase *n);

    bool bounce;
} NvmeBaseClass;

#define TYPE_NVME_BASE "nvme-base"
#define NVME_BASE_CLASS(klass) \
    OBJECT_CLASS_CHECK(NvmeBaseClass, (klass), TYPE_NVME_BASE)
#define NVME_BASE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(NvmeBaseClass, (obj), TYPE_NVME_BASE)

typedef enum NvmeResetType {
    NVME_RESET_FUNCTION   = 0,
    NVME_RESET_CONTROLLER = 1,
} NvmeResetType;

/*
 * Queue mechanics shared by both devices.
 *
 * Note that the queue id checks use conf_ioqpairs (the currently
 * negotiated queue count), not the allocated num_queues: the test
 * device can shrink conf_ioqpairs via Set Features (NUMBER_OF_QUEUES
 * negotiation, secondary controller takeover).
 */
static inline bool nvme_sq_empty(NvmeSQueue *sq)
{
    return sq->head == sq->tail;
}

static inline bool nvme_cq_full(NvmeCQueue *cq)
{
    return (cq->tail + 1) % cq->size == cq->head;
}

static inline bool nvme_cq_empty(NvmeCQueue *cq)
{
    return cq->head == cq->tail;
}

static inline bool nvme_sq_full(NvmeSQueue *sq)
{
    return (sq->tail + 1) % sq->size == sq->head;
}

static inline void nvme_inc_sq_head(NvmeSQueue *sq)
{
    sq->head = (sq->head + 1) % sq->size;
}

static inline void nvme_inc_cq_tail(NvmeCQueue *cq)
{
    cq->tail++;
    if (cq->tail >= cq->size) {
        cq->tail = 0;
        cq->phase = !cq->phase;
    }
}

static inline bool nvme_check_sqid(NvmeCtrlBase *n, uint16_t sqid)
{
    return sqid > n->conf_ioqpairs || !n->sq[sqid];
}

static inline bool nvme_check_cqid(NvmeCtrlBase *n, uint16_t cqid)
{
    return cqid > n->conf_ioqpairs || !n->cq[cqid];
}

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

/*
 * Eager data buffer mapping (core/dptr.c): nvme_map_dptr() maps the
 * command's data pointer into host memory fragments and the callers
 * carve whatever view they need out of the result.
 */
void nvme_map_init(NvmeMap *map, NvmeTxDirection dir);
void nvme_map_unmap(NvmeCtrlBase *n, NvmeMap *map);
uint16_t nvme_map_range(NvmeCtrlBase *n, NvmeMap *map, hwaddr addr, size_t len);
uint16_t nvme_map_dptr(NvmeCtrlBase *n, NvmeMap *map, size_t len,
                       NvmeCmd *cmd, NvmeTxDirection dir);
uint16_t nvme_map_sgl(NvmeCtrlBase *n, NvmeMap *map, NvmeSglDescriptor sgl,
                      size_t len, NvmeCmd *cmd);

/* wrap `map`'s full iovec as the view `view` (no copy, no ownership) */
static inline void nvme_map_wrap(NvmeMap *map, QEMUIOVector *view)
{
    qemu_iovec_init_external(view, map->iov.iov, map->iov.niov);
}

/*
 * Inline helpers shared by core/, prod/ and test/. These are small, hot
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

static inline bool nvme_addr_is_iomem(NvmeCtrlBase *n, hwaddr addr)
{
    hwaddr hi, lo;

    lo = n->bar0.addr;
    hi = lo + int128_get64(n->bar0.size);

    return addr >= lo && addr < hi;
}

/*
 * Functions implemented in core/dptr.c and core/dma.c. Declared here so
 * both prod/ and test/ can call them.
 */
uint16_t nvme_tx(QEMUIOVector *iov, void *ptr, uint32_t len,
                 NvmeTxDirection dir);
uint16_t nvme_c2h(NvmeCtrlBase *n, void *ptr, size_t len, uint32_t hostlen,
                  NvmeRequest *req);
uint16_t nvme_h2c(NvmeCtrlBase *n, void *ptr, uint32_t len, NvmeRequest *req);

void nvme_blk_read(BlockBackend *blk, int64_t offset,
                   BlockCompletionFunc *cb, NvmeRequest *req);
void nvme_blk_write(BlockBackend *blk, int64_t offset,
                    BlockCompletionFunc *cb, NvmeRequest *req);

/*
 * Interrupt delivery implemented in core/irq.c; queue mechanics in
 * core/queue.c. Declared here so both prod/ and test/ can call them.
 */
void nvme_irq_do_intx(NvmeCtrlBase *n);
void nvme_irq_check_intx(NvmeCtrlBase *n);
void nvme_irq_msix(NvmeCtrlBase *n, int vector);
void nvme_irq_msi(NvmeCtrlBase *n);
void nvme_irq_init_notifiers(NvmeCtrlBase *n, int vectors);
void nvme_irq_cleanup_notifiers(NvmeCtrlBase *n);

void nvme_cq_kick(NvmeCQueue *cq);
void nvme_init_cq_common(NvmeCQueue *cq);
void nvme_init_cq(NvmeCQueue *cq, NvmeCtrlBase *n, uint64_t dma_addr,
                  uint16_t cqid, int vector, uint16_t size,
                  bool irq_enabled);
void nvme_post_cqes(void *opaque);
void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req);
void nvme_free_cq(NvmeCQueue *cq);
uint16_t nvme_del_cq(NvmeCtrlBase *n, NvmeRequest *req);
uint16_t nvme_create_cq(NvmeCtrlBase *n, NvmeRequest *req);

void nvme_init_sq_common(NvmeSQueue *sq);
void nvme_init_sq(NvmeSQueue *sq, NvmeCtrlBase *n, uint64_t dma_addr,
                  uint16_t sqid, uint16_t cqid, uint16_t size);
void nvme_sq_cancel_inflight(NvmeSQueue *sq, uint16_t status);
void nvme_free_sq(NvmeSQueue *sq);
uint16_t nvme_del_sq(NvmeCtrlBase *n, NvmeRequest *req);
uint16_t nvme_create_sq(NvmeCtrlBase *n, NvmeRequest *req);
void nvme_process_sq(NvmeSQueue *sq);

/*
 * Shadow doorbell buffer (DBBUF) support, common to both devices.
 */
uint16_t nvme_dbbuf_config(NvmeCtrlBase *n, const NvmeRequest *req);

/*
 * Generic admin command semantics, implemented in core/admin.c and
 * installed as the NvmeBaseClass admin_cmd default in nvme_base_class_init().
 *
 * Devices may implement either of two integration styles:
 * - leave the default in place and only provide admin_cmd_custom
 *   (the production device: the generic set plus a small custom set),
 * - override admin_cmd entirely to add a gate and an extended switch,
 *   chaining generic commands to nvme_admin_default() (the test
 *   device: command-effects gate plus the extended command set).
 */
uint16_t nvme_admin_cmd(NvmeCtrlBase *n, NvmeRequest *req);
uint16_t nvme_admin_default(NvmeCtrlBase *n, NvmeRequest *req);
uint16_t nvme_admin_cmd_custom(NvmeCtrlBase *n, NvmeRequest *req);

/*
 * Generic admin payloads, shared by both devices.
 */
uint16_t nvme_abort(NvmeCtrlBase *n, NvmeRequest *req);
uint16_t nvme_aer(NvmeCtrlBase *n, NvmeRequest *req);

#endif /* HW_NVME_NVME_H */
