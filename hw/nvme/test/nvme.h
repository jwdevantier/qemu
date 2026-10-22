/*
 * QEMU NVM Express Test Device
 *
 * Copyright (c) 2021 Samsung Electronics Co., Ltd.
 *
 * Authors:
 *   Klaus Jensen           <k.jensen@samsung.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#ifndef HW_NVME_TEST_NVME_H
#define HW_NVME_TEST_NVME_H

#include "qemu/uuid.h"
#include "hw/pci/pcie_sriov.h"
#include "system/hostmem.h"

#include "hw/nvme/core/nvme.h"

/*
 * Types, state and helpers that only the test device implements: the
 * namespace "bus" (for nvme-ns qdevs), NVMe subsystems, zoned
 * namespaces, FDP reclaim units, NGUIDs, atomic writes, and the
 * configurable namespace parameters.
 */
#define NVME_EUI64_DEFAULT ((uint64_t)0x5254000000000000)
#define NVME_FDP_MAX_EVENTS 63
#define NVME_FDP_MAXPIDS 128

/*
 * Device-defined NvmeRequest flag bits (NvmeRequest.flags, core/nvme.h):
 * NVME_REQ_ATOMIC_WRITE is set on write commands that are part of an
 * atomic write sequence and must not overlap other in-flight commands.
 */
#define NVME_REQ_ATOMIC_WRITE (1u << 0)

#define TYPE_NVME_BUS "nvme-bus"
OBJECT_DECLARE_SIMPLE_TYPE(NvmeBus, NVME_BUS)

typedef struct NvmeBus {
    BusState parent_bus;
} NvmeBus;

#define TYPE_NVME_SUBSYS "nvme-subsys"
#define NVME_SUBSYS(obj) \
    OBJECT_CHECK(NvmeSubsystem, (obj), TYPE_NVME_SUBSYS)
#define SUBSYS_SLOT_RSVD (void *)0xFFFF

typedef struct NvmeReclaimUnit {
    uint64_t ruamw;
} NvmeReclaimUnit;

typedef struct NvmeRuHandle {
    uint8_t  ruht;
    uint8_t  ruha;
    uint64_t event_filter;
    uint8_t  lbafi;
    uint64_t ruamw;

    /* reclaim units indexed by reclaim group */
    NvmeReclaimUnit *rus;
} NvmeRuHandle;

typedef struct NvmeFdpEventBuffer {
    NvmeFdpEvent     events[NVME_FDP_MAX_EVENTS];
    unsigned int     nelems;
    unsigned int     start;
    unsigned int     next;
} NvmeFdpEventBuffer;

typedef struct NvmeEnduranceGroup {
    uint8_t event_conf;

    struct {
        NvmeFdpEventBuffer host_events, ctrl_events;

        uint16_t nruh;
        uint16_t nrg;
        uint8_t  rgif;
        uint64_t runs;

        uint64_t hbmw;
        uint64_t mbmw;
        uint64_t mbe;

        bool enabled;

        NvmeRuHandle *ruhs;
    } fdp;
} NvmeEnduranceGroup;

typedef struct NvmeSubsystem {
    DeviceState parent_obj;
    NvmeBus     bus;
    uint8_t     subnqn[256];
    char        *serial;

    NvmeCtrlBase       *ctrls[NVME_MAX_CONTROLLERS];
    NvmeNamespaceBase      *namespaces[NVME_MAX_NAMESPACES + 1];
    NvmeEnduranceGroup endgrp;

    struct {
        char *nqn;

        struct {
            bool     enabled;
            uint64_t runs;
            uint16_t nruh;
            uint32_t nrg;
        } fdp;
    } params;
} NvmeSubsystem;

static inline NvmeCtrlBase *nvme_subsys_ctrl(NvmeSubsystem *subsys,
                                         uint32_t cntlid)
{
    if (!subsys || cntlid >= NVME_MAX_CONTROLLERS) {
        return NULL;
    }

    if (subsys->ctrls[cntlid] == SUBSYS_SLOT_RSVD) {
        return NULL;
    }

    return subsys->ctrls[cntlid];
}

static inline NvmeNamespaceBase *nvme_subsys_ns(NvmeSubsystem *subsys,
                                            uint32_t nsid)
{
    if (!subsys || !nsid || nsid > NVME_MAX_NAMESPACES) {
        return NULL;
    }

    return subsys->namespaces[nsid];
}

typedef struct NvmeZone {
    NvmeZoneDescr   d;
    uint64_t        w_ptr;
    QTAILQ_ENTRY(NvmeZone) entry;
} NvmeZone;

#define FDP_EVT_MAX 0xff
#define NVME_FDP_MAX_NS_RUHS 32u
#define FDPVSS 0

/*
 * NOTE: Apart from event type 0, any event type with a shift value of 0 is
 * considered unsupported and thus skipped in get/set features calls.
 *
 * NOTE: NvmeRuHandle uses a 64bit event mask - refactor to support event types
 *       of 63 or greater.
 */
static const uint8_t nvme_fdp_evf_shifts[FDP_EVT_MAX + 1] = {
    /* Host events */
    [FDP_EVT_RU_NOT_FULLY_WRITTEN]      = 0,
    [FDP_EVT_RU_ATL_EXCEEDED]           = 1,
    [FDP_EVT_CTRL_RESET_RUH]            = 2,
    [FDP_EVT_INVALID_PID]               = 3,
    /* CTRL events */
    [FDP_EVT_MEDIA_REALLOC]             = 32,
    [FDP_EVT_RUH_IMPLICIT_RU_CHANGE]    = 33,
};

#define NGUID_LEN 16

typedef struct {
    uint8_t data[NGUID_LEN];
} NvmeNGUID;

bool nvme_nguid_is_null(const NvmeNGUID *nguid);

extern const PropertyInfo qdev_prop_nguid;

#define DEFINE_PROP_NGUID_NODEFAULT(_name, _state, _field) \
    DEFINE_PROP(_name, _state, _field, qdev_prop_nguid, NvmeNGUID)

typedef struct NvmeNamespaceParams {
    bool      detached;
    bool      shared;
    uint32_t  nsid;
    QemuUUID  uuid;
    NvmeNGUID nguid;
    uint64_t  eui64;
    bool      eui64_default;

    uint16_t ms;
    uint8_t  mset;
    uint8_t  pi;
    uint8_t  pil;
    uint8_t  pif;

    uint16_t mssrl;
    uint32_t mcl;
    uint8_t  msrc;

    bool     zoned;
    bool     cross_zone_read;
    uint64_t zone_size_bs;
    uint64_t zone_cap_bs;
    uint32_t max_active_zones;
    uint32_t max_open_zones;
    uint32_t zd_extension_size;

    uint32_t numzrwa;
    uint64_t zrwas;
    uint64_t zrwafg;

    struct {
        char *ruhs;
    } fdp;

    struct {
        uint16_t nawun;
        uint16_t nawupf;
        uint16_t nabsn;
        uint16_t nabspf;
        uint16_t nabo;
    } atomic;
} NvmeNamespaceParams;

typedef struct NvmeAtomic {
    uint32_t    atomic_max_write_size;
    uint64_t    atomic_boundary;
    uint64_t    atomic_nabo;
    bool        atomic_writes;
} NvmeAtomic;

/*
 * Test device controller parameters ("nvme"); the shared set (serial,
 * max_ioqpairs, mdts, aerl) lives in NvmeParamsBase in core/nvme.h.
 */
typedef struct NvmeParams {
    char     *model;
    char     *firmware_version;
    uint32_t num_queues; /* deprecated since 5.1 */
    uint16_t msix_qsize;
    uint16_t mqes;
    uint32_t cmb_size_mb;
    uint32_t aer_max_queued;
    uint8_t  vsl;
    bool     use_intel_id;
    uint8_t  zasl;
    bool     auto_transition_zones;
    bool     legacy_cmb;
    bool     dbcs;
    uint16_t  sriov_max_vfs;
    uint16_t sriov_vq_flexible;
    uint16_t sriov_vi_flexible;
    uint32_t  sriov_max_vq_per_vf;
    uint32_t  sriov_max_vi_per_vf;
    bool     msix_exclusive_bar;
    bool     ocp;

    struct {
        bool mem;
    } ctratt;

    uint16_t atomic_awun;
    uint16_t atomic_awupf;
    bool     atomic_dn;
} NvmeParams;

/*
 * NVM Express namespace device (test device only). The prod device uses
 * the shared NvmeNamespaceBase state directly; only the test device
 * instantiates the "nvme-ns" qdev type.
 */
#define TYPE_NVME_NS "nvme-ns"
#define NVME_NS(obj) \
    OBJECT_CHECK(NvmeNamespace, (obj), TYPE_NVME_NS)

typedef struct NvmeNamespace {
    NvmeNamespaceBase base;

    /*
     * Test device namespace state: everything the test device
     * supports but the production device does not.
     */
    int32_t      bootindex;
    char         bootindex_suffix[24];
    NvmeIdNsNvm  id_ns_nvm;
    NvmeIdNsInd  id_ns_ind;
    uint8_t      pif;

    struct {
        uint16_t zrwas;
        uint16_t zrwafg;
        uint32_t numzrwa;
    } zns;

    QTAILQ_ENTRY(NvmeNamespace) entry;

    NvmeIdNsZoned   *id_ns_zoned;
    NvmeZone        *zone_array;
    QTAILQ_HEAD(, NvmeZone) exp_open_zones;
    QTAILQ_HEAD(, NvmeZone) imp_open_zones;
    QTAILQ_HEAD(, NvmeZone) closed_zones;
    QTAILQ_HEAD(, NvmeZone) full_zones;
    uint32_t        num_zones;
    uint64_t        zone_size;
    uint64_t        zone_capacity;
    uint32_t        zone_size_log2;
    uint8_t         *zd_extensions;
    int32_t         nr_open_zones;
    int32_t         nr_active_zones;

    NvmeNamespaceParams params;
    NvmeSubsystem *subsys;
    NvmeEnduranceGroup *endgrp;

    struct {
        uint32_t err_rec;
    } features;

    struct {
        uint16_t nphs;
        /* reclaim unit handle identifiers indexed by placement handle */
        uint16_t *phs;
    } fdp;

    NvmeAtomic  atomic;
} NvmeNamespace;

/*
 * Recover the test namespace from a base pointer.
 */
static inline NvmeNamespace *nvme_ns_of(NvmeNamespaceBase *ns)
{
    return container_of(ns, NvmeNamespace, base);
}

/*
 * Bounce buffer fallbacks (test device only; prod uses the plain
 * pci_dma data path): context used by nvme_bounce_data/mdata.
 */
typedef struct NvmeBounceContext {
    NvmeRequest *req;

    struct {
        QEMUIOVector iov;
        uint8_t *bounce;
    } data, mdata;
} NvmeBounceContext;

/*
 * Zoned namespace helpers. These operate on the derived namespace
 * state (zone bookkeeping lives in NvmeNamespace, not the base).
 */
static inline NvmeZoneState nvme_get_zone_state(NvmeZone *zone)
{
    return zone->d.zs >> 4;
}

static inline void nvme_set_zone_state(NvmeZone *zone, NvmeZoneState state)
{
    zone->d.zs = state << 4;
}

static inline uint64_t nvme_zone_rd_boundary(NvmeNamespace *ns, NvmeZone *zone)
{
    return zone->d.zslba + ns->zone_size;
}

static inline uint64_t nvme_zone_wr_boundary(NvmeZone *zone)
{
    return zone->d.zslba + zone->d.zcap;
}

static inline bool nvme_wp_is_valid(NvmeZone *zone)
{
    uint8_t st = nvme_get_zone_state(zone);

    return st != NVME_ZONE_STATE_FULL &&
           st != NVME_ZONE_STATE_READ_ONLY &&
           st != NVME_ZONE_STATE_OFFLINE;
}

static inline uint8_t *nvme_get_zd_extension(NvmeNamespace *ns,
                                             uint32_t zone_idx)
{
    return &ns->zd_extensions[zone_idx * ns->params.zd_extension_size];
}

static inline void nvme_aor_inc_open(NvmeNamespace *ns)
{
    assert(ns->nr_open_zones >= 0);
    if (ns->params.max_open_zones) {
        ns->nr_open_zones++;
        assert(ns->nr_open_zones <= ns->params.max_open_zones);
    }
}

static inline void nvme_aor_dec_open(NvmeNamespace *ns)
{
    if (ns->params.max_open_zones) {
        assert(ns->nr_open_zones > 0);
        ns->nr_open_zones--;
    }
    assert(ns->nr_open_zones >= 0);
}

static inline void nvme_aor_inc_active(NvmeNamespace *ns)
{
    assert(ns->nr_active_zones >= 0);
    if (ns->params.max_active_zones) {
        ns->nr_active_zones++;
        assert(ns->nr_active_zones <= ns->params.max_active_zones);
    }
}

static inline void nvme_aor_dec_active(NvmeNamespace *ns)
{
    if (ns->params.max_active_zones) {
        assert(ns->nr_active_zones > 0);
        ns->nr_active_zones--;
        assert(ns->nr_active_zones >= ns->nr_open_zones);
    }
    assert(ns->nr_active_zones >= 0);
}

static inline void nvme_fdp_stat_inc(uint64_t *a, uint64_t b)
{
    uint64_t ret = *a + b;
    *a = ret < *a ? UINT64_MAX : ret;
}

#define TYPE_NVME "nvme"
#define NVME(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_NVME)

typedef struct NvmeCtrl {
    NvmeCtrlBase base;

    /* Test device state — everything the test device supports but the
     * production (vnvme) device does not. */
    MemoryRegion iomem;
    NvmeBus      bus;

    uint16_t    cntlid;

    uint64_t    host_timestamp;                 /* Timestamp sent by the host */
    uint64_t    timestamp_set_qemu_clock_ms;    /* QEMU clock time */

    struct {
        uint32_t acs[256];
        struct {
            uint32_t nvm[256];
            uint32_t zoned[256];
        } iocs;
    } cse;

    struct {
        MemoryRegion mem;
        uint8_t      *buf;
        bool         cmse;
        hwaddr       cba;
    } cmb;

    struct {
        HostMemoryBackend *dev;
        bool              cmse;
        hwaddr            cba;
    } pmr;

    uint8_t     aer_mask;
    int         aer_queued;

    /* Namespace ID is started with 1 so bitmap should be 1-based */
#define NVME_CHANGED_NSID_SIZE  (NVME_MAX_NAMESPACES + 1)
    DECLARE_BITMAP(changed_nsids, NVME_CHANGED_NSID_SIZE);

    NvmeSubsystem   *subsys;

    /*
     * The "legacy" namespace: set up from the controller 'drive'
     * property. The production device uses the plain
     * NvmeNamespaceBase embedded in NvmeCtrlBase; the test device
     * embeds a fully derived NvmeNamespace here so that the
     * drive-backed namespace keeps all of the (zeroed) derived
     * state that it had before the device split.
     */
    NvmeNamespace   namespace;

    /* Test device ("nvme") controller parameters. */
    NvmeParams  params;

    NvmePriCtrlCap  pri_ctrl_cap;
    uint32_t nr_sec_ctrls;
    NvmeSecCtrlEntry *sec_ctrl_list;
    struct {
        uint16_t    vqrfap;
        uint16_t    virfap;
    } next_pri_ctrl_cap;    /* These override pri_ctrl_cap after reset */
    NvmeAtomic  atomic;
} NvmeCtrl;

/*
 * Migration stream description for the "nvme-ns" child device and
 * the legacy (drive-backed) namespace embedded in the controller.
 */
extern const VMStateDescription nvme_vmstate_ns;

/*
 * Namespace lifecycle (test device implementation; called from test/
 * device code only).
 */
void nvme_ns_init_format(NvmeNamespace *ns);
int nvme_ns_setup(NvmeNamespace *ns, Error **errp);
void nvme_ns_drain(NvmeNamespace *ns);
void nvme_ns_shutdown(NvmeNamespace *ns);
void nvme_ns_cleanup(NvmeNamespace *ns);
void nvme_attach_ns(NvmeCtrl *n, NvmeNamespace *ns);

/*
 * Bounce buffer fallbacks and rw completion (test device only; core
 * uses the base-typed ops/dma paths directly).
 */
uint16_t nvme_bounce_data(NvmeCtrlBase *n, void *ptr, uint32_t len,
                          NvmeTxDirection dir, NvmeRequest *req);
uint16_t nvme_bounce_mdata(NvmeCtrlBase *n, void *ptr, uint32_t len,
                           NvmeTxDirection dir, NvmeRequest *req);
void nvme_rw_complete_cb(void *opaque, int ret);

/*
 * NVM subsystem controller registration (test device only).
 */
int nvme_subsys_register_ctrl(NvmeCtrl *n, Error **errp);
void nvme_subsys_unregister_ctrl(NvmeSubsystem *subsys, NvmeCtrl *n);

/*
 * Atomic write configuration (test device only).
 */
void nvme_atomic_configure_max_write_size(bool dn, uint16_t awun,
                                          uint16_t awupf, NvmeAtomic *atomic);
void nvme_ns_atomic_configure_boundary(bool dn, uint16_t nabsn,
                                       uint16_t nabspf, NvmeAtomic *atomic);
void nvme_ctrl_notify_ns_resize(NvmeCtrl *ctrl, NvmeNamespace *ns);

extern const VMStateDescription nvme_vmstate_atomic;

/*
 * Recover the test device state from a base pointer.
 */
static inline NvmeCtrl *nvme_ctrl_of(NvmeCtrlBase *n)
{
    return container_of(n, NvmeCtrl, base);
}

/*
 * Recover the test device state from something that carries a base
 * pointer (a submission/completion queue or a request).
 */
static inline NvmeCtrl *nvme_ctrl(NvmeRequest *req)
{
    return container_of(req->sq->ctrl, NvmeCtrl, base);
}

static inline NvmeCtrl *nvme_ctrl_from_sq(NvmeSQueue *sq)
{
    return container_of(sq->ctrl, NvmeCtrl, base);
}

static inline NvmeCtrl *nvme_ctrl_from_cq(NvmeCQueue *cq)
{
    return container_of(cq->ctrl, NvmeCtrl, base);
}

/*
 * SR-IOV secondary controller helpers. The secondary controller list is
 * test device state.
 */
static inline NvmeSecCtrlEntry *nvme_sctrl(NvmeCtrl *n)
{
    PCIDevice *pci_dev = &n->base.parent_obj;
    NvmeCtrl *pf = NVME(pcie_sriov_get_pf(pci_dev));

    if (pci_is_vf(pci_dev)) {
        return &pf->sec_ctrl_list[pcie_sriov_vf_number(pci_dev)];
    }

    return NULL;
}

static inline NvmeSecCtrlEntry *nvme_sctrl_for_cntlid(NvmeCtrl *n,
                                                      uint16_t cntlid)
{
    NvmeSecCtrlEntry *list = n->sec_ctrl_list;
    uint8_t i;

    for (i = 0; i < n->nr_sec_ctrls; i++) {
        if (le16_to_cpu(list[i].scid) == cntlid) {
            return &list[i];
        }
    }

    return NULL;
}

#endif /* HW_NVME_TEST_NVME_H */
