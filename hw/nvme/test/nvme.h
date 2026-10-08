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
    /*
     * Currently a pure wrapper: all state lives in the base. The next
     * commit moves the test device fields out of NvmeCtrlBase and into
     * this structure.
     */
    NvmeCtrlBase base;
} NvmeCtrl;

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
        return &pf->base.sec_ctrl_list[pcie_sriov_vf_number(pci_dev)];
    }

    return NULL;
}

static inline NvmeSecCtrlEntry *nvme_sctrl_for_cntlid(NvmeCtrl *n,
                                                      uint16_t cntlid)
{
    NvmeSecCtrlEntry *list = n->base.sec_ctrl_list;
    uint8_t i;

    for (i = 0; i < n->base.nr_sec_ctrls; i++) {
        if (le16_to_cpu(list[i].scid) == cntlid) {
            return &list[i];
        }
    }

    return NULL;
}

/*
 * Online namespace resize notification (test device only).
 */
void nvme_ctrl_notify_ns_resize(NvmeCtrl *ctrl, NvmeNamespace *ns);

#endif /* HW_NVME_TEST_NVME_H */
