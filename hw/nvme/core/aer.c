/*
 * QEMU NVM Express — asynchronous event request handling
 *
 * Core code for processing asynchronous event requests.
 *
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include "qemu/osdep.h"
#include "hw/nvme/core/nvme.h"
#include "hw/nvme/trace.h"

void nvme_aer_free_events(NvmeCtrlBase *n)
{
    while (!QTAILQ_EMPTY(&n->aer.queue)) {
        NvmeAsyncEvent *event = QTAILQ_FIRST(&n->aer.queue);

        QTAILQ_REMOVE(&n->aer.queue, event, entry);
        g_free(event);
    }
    n->aer.queued = 0;
    n->aer.mask = 0;
}

void nvme_aer_process(NvmeCtrlBase *n)
{
    NvmeAsyncEvent *event, *next;

    trace_pci_nvme_process_aers(n->aer.queued);

    QTAILQ_FOREACH_SAFE(event, &n->aer.queue, entry, next) {
        NvmeRequest *req;
        NvmeAerResult *result;
        uint8_t bit = 1 << event->result.event_type;

        if (!n->aer.outstanding) {
            trace_pci_nvme_aer_no_outstanding();
            break;
        }

        /* Masked: leave it queued until the host clears the event. */
        if (n->aer.mask & bit) {
            trace_pci_nvme_aer_masked(event->result.event_type, n->aer.mask);
            continue;
        }

        QTAILQ_REMOVE(&n->aer.queue, event, entry);
        n->aer.queued--;

        n->aer.mask |= bit;
        n->aer.outstanding--;

        req = n->aer.reqs[n->aer.outstanding];
        result = (NvmeAerResult *)&req->cqe.result;
        result->event_type = event->result.event_type;
        result->event_info = event->result.event_info;
        result->log_page = event->result.log_page;
        g_free(event);

        trace_pci_nvme_aer_post_cqe(result->event_type, result->event_info,
                                    result->log_page);

        nvme_enqueue_req_completion(&n->admin_cq, req);
    }
}

void nvme_aer_enqueue(NvmeCtrlBase *n, uint8_t event_type,
                      uint8_t event_info, uint8_t log_page)
{
    NvmeAsyncEvent *event;

    trace_pci_nvme_aer_enqueue(event_type, event_info, log_page);

    if ((n->aer.mask & (1 << event_type)) ||
        n->aer.queued == n->aer.queued_max) {
        trace_pci_nvme_aer_enqueue_noqueue(n->aer.queued);
        return;
    }

    event = g_new(NvmeAsyncEvent, 1);
    event->result = (NvmeAerResult) {
        .event_type = event_type,
        .event_info = event_info,
        .log_page = log_page,
    };

    QTAILQ_INSERT_TAIL(&n->aer.queue, event, entry);
    n->aer.queued++;

    nvme_aer_process(n);
}

void nvme_aer_clear_event(NvmeCtrlBase *n, uint8_t event_type)
{
    NvmeAsyncEvent *event, *next;
    uint8_t bit = 1 << event_type;

    n->aer.mask &= ~bit;

    QTAILQ_FOREACH_SAFE(event, &n->aer.queue, entry, next) {
        if (event->result.event_type == event_type) {
            QTAILQ_REMOVE(&n->aer.queue, event, entry);
            n->aer.queued--;
            g_free(event);
        }
    }
}
