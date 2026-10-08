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

#include "hw/pci/pcie_sriov.h"

#include "hw/nvme/core/nvme.h"

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

    uint64_t    dbbuf_dbs;
    uint64_t    dbbuf_eis;
    bool        dbbuf_enabled;

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
 * NVM Express namespace device (test device only). The prod device uses
 * the shared NvmeNamespaceBase state directly; only the test device
 * instantiates the "nvme-ns" qdev type.
 */
#define TYPE_NVME_NS "nvme-ns"
#define NVME_NS(obj) \
    OBJECT_CHECK(NvmeNamespace, (obj), TYPE_NVME_NS)

typedef struct NvmeNamespace {
    /*
     * Currently a wrapper holding the shared state: all namespace state
     * lives in the base. The next commit moves test device fields out
     * of NvmeNamespaceBase and into this structure.
     */
    NvmeNamespaceBase base;
} NvmeNamespace;

/*
 * Recover the test namespace from a base pointer.
 */
static inline NvmeNamespace *nvme_ns_of(NvmeNamespaceBase *ns)
{
    return container_of(ns, NvmeNamespace, base);
}

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
