/*
 * QEMU NVM Express shared interrupt delivery (core)
 *
 * IRQ handling shared by the vnvme (prod) and nvme (test) devices.
 * Both devices deliver completions through these helpers, so the
 * interrupt delivery model exists in exactly one place:
 *
 *  - MSI-X: notify the CQ vector, or route through the accelerator
 *           irqchip (irqfd) when available.
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
#include "qemu/event_notifier.h"
#include "system/accel-irq.h"
#include "hw/nvme/trace.h"
#include "hw/nvme/core/nvme.h"

/*
 * Interrupt plumbing: QEMU's interrupt emulation is not thread safe, so
 * use event notifiers to assert and deassert interrupts in the main
 * loop. If the notifier is not available (initialization failed or the
 * caller is already running in the main loop, e.g. the bar write
 * handler), fall back to delivering the interrupt directly.
 */
void nvme_irq_do_intx(NvmeCtrlBase *n)
{
    PCIDevice *pci = PCI_DEVICE(n);
    uint32_t intms = ldl_le_p(&n->bar.intms);
    int level = n->irq.intx.pending > 0 && (~intms & 1) ? 1 : 0;

    /* vfs does not implement INTx. */
    if (pci_is_vf(pci)) {
        return;
    }

    trace_pci_nvme_irq_do_intx(intms);

    pci_set_irq(pci, level);
}

static void nvme_irq_intx_notify(EventNotifier *e)
{
    NvmeCtrlBase *n = container_of(e, NvmeCtrlBase, irq.intx.notifier);

    trace_pci_nvme_irq_intx_notify();

    if (event_notifier_test_and_clear(e)) {
        nvme_irq_do_intx(n);
    }
}

void nvme_irq_check_intx(NvmeCtrlBase *n)
{
    trace_pci_nvme_irq_check_intx();

    if (n->irq.intx.notifier.initialized) {
        event_notifier_set(&n->irq.intx.notifier);
        return;
    }

    nvme_irq_do_intx(n);
}

static void nvme_irq_do_msix(NvmeCtrlBase *n, int vector)
{
    PCIDevice *pci = PCI_DEVICE(n);

    trace_pci_nvme_irq_do_msix(vector);

    msix_notify(pci, vector);
}

static void nvme_irq_msix_notify(EventNotifier *e)
{
    NvmeIV *iv = container_of(e, NvmeIV, notifier);
    NvmeCtrlBase *n = iv->ctrl;
    int vector = iv - n->irq.msix;

    trace_pci_nvme_irq_msix_notify(vector);

    if (event_notifier_test_and_clear(e)) {
        nvme_irq_do_msix(n, vector);
    }
}

void nvme_irq_msix(NvmeCtrlBase *n, int vector)
{
    NvmeIV *iv = &n->irq.msix[vector];

    trace_pci_nvme_irq_msix(vector);

    if (iv->notifier.initialized) {
        event_notifier_set(&iv->notifier);
        return;
    }

    nvme_irq_do_msix(n, vector);
}

static void nvme_irq_do_msi(NvmeCtrlBase *n)
{
    PCIDevice *pci = PCI_DEVICE(n);

    trace_pci_nvme_irq_do_msi();

    msi_notify(pci, 0);
}

static void nvme_irq_msi_notify(EventNotifier *e)
{
    NvmeCtrlBase *n = container_of(e, NvmeCtrlBase, irq.msi.notifier);

    trace_pci_nvme_irq_msi_notify();

    if (event_notifier_test_and_clear(e)) {
        nvme_irq_do_msi(n);
    }
}

void nvme_irq_msi(NvmeCtrlBase *n)
{
    trace_pci_nvme_irq_msi();

    if (n->irq.msi.notifier.initialized) {
        event_notifier_set(&n->irq.msi.notifier);
        return;
    }

    nvme_irq_do_msi(n);
}

/*
 * Accelerated irqchip route helpers (see system/accel-irq.h): since
 * NvmeCtrlBase embeds the PCIDevice
 * (parent_obj) as its first member and both device models embed
 * NvmeCtrlBase at the head of their state, the controller state can be
 * recovered with container_of() in either device.
 */
static NvmeCtrlBase *nvme_irqchip_ctrl(PCIDevice *pci)
{
    return container_of(pci, NvmeCtrlBase, parent_obj);
}

int nvme_irqchip_vector_use(NvmeCtrlBase *n, uint32_t vector)
{
    AccelRouteChange c = accel_irqchip_begin_route_changes();
    int ret;

    trace_pci_nvme_irqchip_vector_use(vector);

    ret = accel_irqchip_add_msi_route(&c, vector, &n->parent_obj);
    if (ret < 0) {
        return ret;
    }

    accel_irqchip_commit_route_changes(&c);

    return ret;
}

int nvme_irqchip_vector_unmask(PCIDevice *pci, unsigned vector,
                               MSIMessage msg)
{
    NvmeCtrlBase *n = nvme_irqchip_ctrl(pci);
    NvmeIV *iv = &n->irq.msix[vector];
    int ret;

    trace_pci_nvme_irqchip_unmask(vector, msg.address, msg.data);

    if (iv->virq < 0) {
        iv->virq = nvme_irqchip_vector_use(n, vector);
    }

    ret = accel_irqchip_update_msi_route(iv->virq, msg, pci);
    if (ret < 0) {
        return ret;
    }

    accel_irqchip_commit_routes();

    return accel_irqchip_add_irqfd_notifier_gsi(&iv->notifier, NULL,
                                                iv->virq);
}

void nvme_irqchip_vector_mask(PCIDevice *pci, unsigned vector)
{
    NvmeCtrlBase *n = nvme_irqchip_ctrl(pci);
    NvmeIV *iv = &n->irq.msix[vector];

    trace_pci_nvme_irqchip_mask(vector);

    accel_irqchip_remove_irqfd_notifier_gsi(&iv->notifier, iv->virq);
}

void nvme_irqchip_vector_poll(PCIDevice *pci, unsigned int start,
                              unsigned int end)
{
    trace_pci_nvme_irqchip_poll(start, end);

    for (int i = start; i < end; i++) {
        NvmeCtrlBase *n = nvme_irqchip_ctrl(pci);
        NvmeIV *iv = &n->irq.msix[i];

        if (!msix_is_masked(pci, i)) {
            continue;
        }

        if (event_notifier_test_and_clear(&iv->notifier)) {
            msix_set_pending(pci, i);
        }
    }
}

void nvme_irq_init_notifiers(NvmeCtrlBase *n, int vectors)
{
    PCIDevice *pci = PCI_DEVICE(n);

    if (pci->cap_present & QEMU_PCI_CAP_MSIX) {
        bool with_irqfd = accel_msi_via_irqfd_enabled();

        n->irq.msix = g_new0(NvmeIV, vectors);

        for (int i = 0; i < vectors; i++) {
            NvmeIV *iv = &n->irq.msix[i];

            iv->virq = -1;
            iv->ctrl = n;

            if (event_notifier_init(&iv->notifier, 0)) {
                continue;
            }

            if (!with_irqfd) {
                event_notifier_set_handler(&iv->notifier,
                                            nvme_irq_msix_notify);
            }
        }

        return;
    }

    if (pci->cap_present & QEMU_PCI_CAP_MSI) {
        if (event_notifier_init(&n->irq.msi.notifier, 0)) {
            return;
        }

        event_notifier_set_handler(&n->irq.msi.notifier, nvme_irq_msi_notify);

        return;
    }

    if (event_notifier_init(&n->irq.intx.notifier, 0)) {
        return;
    }

    event_notifier_set_handler(&n->irq.intx.notifier, nvme_irq_intx_notify);
}

void nvme_irq_cleanup_notifiers(NvmeCtrlBase *n)
{
    PCIDevice *pci = PCI_DEVICE(n);

    if (pci->cap_present & QEMU_PCI_CAP_MSIX) {
        bool with_irqfd = accel_msi_via_irqfd_enabled();

        if (with_irqfd) {
            msix_unset_vector_notifiers(pci);
        }

        for (int i = 0; i < msix_nr_vectors_allocated(pci); i++) {
            NvmeIV *iv = &n->irq.msix[i];

            if (with_irqfd && iv->virq != -1) {
                accel_irqchip_remove_irqfd_notifier_gsi(&iv->notifier,
                                                        iv->virq);
                accel_irqchip_release_virq(iv->virq);

                iv->virq = -1;
            }

            event_notifier_set_handler(&iv->notifier, NULL);
            event_notifier_cleanup(&iv->notifier);
        }

        g_free(n->irq.msix);

        return;
    }

    if (pci->cap_present & QEMU_PCI_CAP_MSI) {
        event_notifier_set_handler(&n->irq.msi.notifier, NULL);
        event_notifier_cleanup(&n->irq.msi.notifier);

        return;
    }

    event_notifier_set_handler(&n->irq.intx.notifier, NULL);
    event_notifier_cleanup(&n->irq.intx.notifier);
}
