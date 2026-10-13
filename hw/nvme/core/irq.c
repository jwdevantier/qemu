/*
 * QEMU NVM Express shared interrupt delivery (core)
 *
 * IRQ handling for the NVMe device models: all completions are
 * delivered through these helpers, so the
 * interrupt delivery model exists in exactly one place:
 *
 *  - MSI-X: notify the CQ vector.
 *  - MSI:   notify vector 0.
 *  - INTx:  level-based on the aggregate irq.intx.pending counter,
 *           with support for INTMS masking (legacy VFs do not
 *           implement INTx).
 *
 * This code is covered by the QEMU security policy.
 *
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "hw/nvme/trace.h"
#include "hw/nvme/core/nvme.h"

void nvme_irq_check_intx(NvmeCtrlBase *n)
{
    PCIDevice *pci = PCI_DEVICE(n);
    uint32_t intms = ldl_le_p(&n->bar.intms);
    int level = n->irq.intx.pending > 0 && (~intms & 1) ? 1 : 0;

    /* vfs does not implement INTx. */
    if (pci_is_vf(pci)) {
        return;
    }

    trace_pci_nvme_irq_check_intx(intms);

    pci_set_irq(pci, level);
}

void nvme_irq_msix(NvmeCtrlBase *n, int vector)
{
    PCIDevice *pci = PCI_DEVICE(n);

    trace_pci_nvme_irq_msix(vector);

    msix_notify(pci, vector);
}

/*
 * Placeholder for the irq notifiers introduced later; notifies the
 * single MSI vector directly.
 */
void nvme_irq_msi(NvmeCtrlBase *n)
{
    PCIDevice *pci = PCI_DEVICE(n);

    trace_pci_nvme_irq_msi();

    msi_notify(pci, 0);
}
