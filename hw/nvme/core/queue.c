/*
 * QEMU NVM Express shared queue plumbing (core)
 *
 * Submission and completion queue mechanics: queue creation, deletion
 * and teardown, completion posting, the shadow doorbell buffer
 * configuration and the per-queue ioeventfd wiring. Interrupt
 * delivery lives in core/irq.c and the generic admin command
 * semantics in core/admin.c.
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
#include "system/block-backend.h"
#include "qemu/event_notifier.h"
#include "hw/nvme/trace.h"
#include "hw/nvme/core/nvme.h"

static inline bool nvme_msix_enabled(NvmeCtrlBase *n)
{
    return msix_enabled(PCI_DEVICE(n));
}

static inline bool nvme_msi_enabled(NvmeCtrlBase *n)
{
    return msi_enabled(PCI_DEVICE(n));
}

/*
 * Check that the guest range [addr, addr + len) is directly accessible
 * memory (guest RAM, CMB or PMR) for the given access direction. Used
 * to validate the shadow doorbell buffer placement: since that memory
 * is accessed on the submission/completion paths without bouncing, an
 * unmappable range would leave the host polling on a stale shadow
 * buffer.
 */
static bool nvme_addr_is_mappable(NvmeCtrlBase *n, hwaddr addr, size_t len,
                                  bool is_write)
{
    AddressSpace *as = pci_get_address_space(PCI_DEVICE(n));
    const MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;

    if (UINT64_MAX - addr < len) {
        return false;
    }

    while (len) {
        hwaddr xlat;
        MemoryRegion *mr;
        hwaddr clen = len;

        mr = address_space_translate(as, addr, &xlat, &clen, is_write, attrs);

        if (unlikely(!clen) ||
            !memory_access_is_direct(mr, is_write, attrs)) {
            return false;
        }

        addr += clen;
        len -= clen;
    }

    return true;
}

/*
 * The host advanced the CQ head (via a real doorbell write or through
 * the shadow doorbell buffer ioeventfd): process the new head, i.e.
 * account for the consumed completions and re-evaluate the irq state
 * if the queue was drained, and schedule deferred completion posting.
 */
void nvme_cq_kick(NvmeCQueue *cq)
{
    NvmeCtrlBase *n = cq->ctrl;

    if (!QTAILQ_EMPTY(&cq->req_list)) {
        qemu_bh_schedule(cq->bh);
    }

    if (nvme_cq_empty(cq) && cq->vector != -1 && !nvme_msix_enabled(n)) {
        /*
         * nvme_cq_kick is only called when the head changes so it is safe to
         * decrement intx.pending unconditionally.
         */
        n->irq.intx.pending--;

        nvme_irq_check_intx(n);
    }
}

/* --- CQ lifecycle --- */

/*
 * Shadow doorbell buffer helpers: with DBBUF enabled, the host writes
 * submission queue tails and completion queue heads into the shadow
 * buffers instead of ringing the BAR doorbells; the event index
 * shadows are written by the controller to announce consumption.
 */
static void nvme_cq_set_eventidx(const NvmeCQueue *cq)
{
    trace_pci_nvme_cq_set_eventidx(cq->cqid, cq->head);

    stl_le_pci_dma(PCI_DEVICE(cq->ctrl), cq->ei_addr, cq->head,
                   MEMTXATTRS_UNSPECIFIED);
}

static bool nvme_cq_update_head(NvmeCQueue *cq)
{
    uint32_t head = cq->head;

    ldl_le_pci_dma(PCI_DEVICE(cq->ctrl), cq->db_addr, &cq->head,
                   MEMTXATTRS_UNSPECIFIED);

    if (head != cq->head) {
        trace_pci_nvme_cq_update_head(cq->cqid, head, cq->head);
        return true;
    }

    return false;
}

static void nvme_sq_set_eventidx(const NvmeSQueue *sq)
{
    trace_pci_nvme_sq_set_eventidx(sq->sqid, sq->tail);

    stl_le_pci_dma(PCI_DEVICE(sq->ctrl), sq->ei_addr, sq->tail,
                   MEMTXATTRS_UNSPECIFIED);
}

static bool nvme_sq_update_tail(NvmeSQueue *sq)
{
    uint32_t tail = sq->tail;

    ldl_le_pci_dma(PCI_DEVICE(sq->ctrl), sq->db_addr, &sq->tail,
                   MEMTXATTRS_UNSPECIFIED);

    if (tail != sq->tail) {
        trace_pci_nvme_sq_update_tail(sq->sqid, tail, sq->tail);
        return true;
    }

    return false;
}

/*
 * Shadow doorbell notifier wiring (defined after the queue
 * lifecycle): when a doorbell buffer is configured, an event
 * notifier is registered on the queue's doorbell offset of the
 * doorbell MMIO region so doorbell writes can be dispatched by the
 * accelerator without trapping. The authoritative queue indices are
 * then taken from the shadow buffers.
 */
static void nvme_cq_notifier(EventNotifier *e);
static void nvme_cq_init_notifier(NvmeCQueue *cq);
static void nvme_cq_teardown_notifier(NvmeCQueue *cq);
static void nvme_sq_notifier(EventNotifier *e);
static void nvme_sq_init_notifier(NvmeSQueue *sq);
static void nvme_sq_teardown_notifier(NvmeSQueue *sq);

/* --- CQ lifecycle --- */

/*
 * Common part of the CQ setup, called after the queue fields have
 * been initialized (nvme_init_cq) or restored (test device migration
 * path): msix vector use, dbbuf shadow wiring and (when configured)
 * ioeventfd registration for non-admin queues.
 */
void nvme_init_cq_common(NvmeCQueue *cq)
{
    NvmeCtrlBase *n = cq->ctrl;

    if (msix_present(PCI_DEVICE(n)) && cq->vector != -1) {
        msix_vector_use(PCI_DEVICE(n), cq->vector);
    }

    QTAILQ_INIT(&cq->sq_list);

    if (n->dbbuf_enabled) {
        /*
         * CAP.DSTRD is 0, so offset of the ith cq db_addr is
         * (i << 3) + (1 << 2). Be consistent with nvme_dbbuf_config()
         * and the doorbell offset calculation in the per-device
         * nvme_process_db() implementations.
         */
        cq->db_addr = n->dbbuf_dbs + (cq->cqid << 3) + (1 << 2);
        cq->ei_addr = n->dbbuf_eis + (cq->cqid << 3) + (1 << 2);
    }

    if (n->dbbuf_enabled && cq->cqid != 0) {
        assert(n->db_region);
        nvme_cq_init_notifier(cq);
    }

    n->cq[cq->cqid] = cq;
    cq->bh = qemu_bh_new_guarded(nvme_post_cqes, cq,
                                 &DEVICE(n)->mem_reentrancy_guard);
}

void nvme_init_cq(NvmeCQueue *cq, NvmeCtrlBase *n, uint64_t dma_addr,
                  uint16_t cqid, uint16_t vector, uint16_t size,
                  uint16_t irq_enabled)
{
    cq->ctrl = n;
    cq->cqid = cqid;
    cq->size = size;
    cq->dma_addr = dma_addr;
    cq->phase = 1;
    cq->vector = irq_enabled ? vector : -1;
    cq->head = cq->tail = 0;
    QTAILQ_INIT(&cq->req_list);

    nvme_init_cq_common(cq);
}

void nvme_post_cqes(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeCtrlBase *n = cq->ctrl;
    NvmeRequest *req, *next;
    bool pending = cq->head != cq->tail;
    int ret;

    QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
        NvmeSQueue *sq;
        hwaddr addr;

        if (nvme_cq_full(cq)) {
            break;
        }

        /*
         * Here we take the following fields from NvmeRequest structure
         * and write cqe to the guest RAM based on them:
         * - req->sq
         * - req->status
         * - req->cqe
         *
         * If you change this code and more fields from NvmeRequest are
         * used, please make sure that you have handled this in:
         * nvme_vmstate_request and nvme_ctrl_pre_save().
         */

        sq = req->sq;
        req->cqe.status = cpu_to_le16((req->status << 1) | cq->phase);
        req->cqe.sq_head = cpu_to_le16(sq->head);
        addr = cq->dma_addr + (cq->tail << NVME_CQES);
        ret = pci_dma_write(PCI_DEVICE(n), addr, (void *)&req->cqe,
                            sizeof(req->cqe));
        if (ret) {
            NVME_GUEST_ERR(pci_nvme_err_addr_write,
                           "failed to write CQE to guest addr 0x%" PRIx64,
                           addr);
            trace_pci_nvme_err_cfs();
            stl_le_p(&n->bar.csts, NVME_CSTS_FAILED);
            break;
        }

        QTAILQ_REMOVE(&cq->req_list, req, entry);

        nvme_inc_cq_tail(cq);

        /*
         * Re-arm the submission queue: this request is about to become
         * available again, so if the SQ has commands waiting and there
         * were no free requests, get processing scheduled.
         */
        if (QTAILQ_EMPTY(&sq->req_list) && !nvme_sq_empty(sq)) {
            qemu_bh_schedule(sq->bh);
        }

        QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
    }

    if (cq->vector < 0) {
        return;
    }

    if (cq->tail != cq->head) {
        if (nvme_msix_enabled(n)) {
            nvme_irq_msix(n, cq->vector);
        } else if (nvme_msi_enabled(n)) {
            nvme_irq_msi(n);
        } else if (!pending) {
            n->irq.intx.pending++;

            nvme_irq_check_intx(n);
        }
    }
}

void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req)
{
    assert(cq->cqid == req->sq->cqid);
    trace_pci_nvme_enqueue_req_completion(nvme_cid(req), cq->cqid,
                                          le32_to_cpu(req->cqe.result),
                                          le32_to_cpu(req->cqe.dw1),
                                          req->status);

    if (req->status) {
        trace_pci_nvme_err_req_status(nvme_cid(req), nvme_nsid(req->ns),
                                      req->status, req->cmd.opcode);
    }

    nvme_map_unmap(cq->ctrl, &req->map);
    qemu_iovec_destroy(&req->iov);

    QTAILQ_REMOVE(&req->sq->out_req_list, req, entry);
    QTAILQ_INSERT_TAIL(&cq->req_list, req, entry);

    qemu_bh_schedule(cq->bh);
}

void nvme_free_cq(NvmeCQueue *cq)
{
    NvmeCtrlBase *n = cq->ctrl;

    /* detach from the controller before freeing: glibc clobbers the
     * first bytes of freed memory, so cq->cqid may not be read after
     * g_free() */
    n->cq[cq->cqid] = NULL;

    qemu_bh_delete(cq->bh);
    nvme_cq_teardown_notifier(cq);
    if (msix_present(PCI_DEVICE(n)) && cq->vector != -1) {
        msix_vector_unuse(PCI_DEVICE(n), cq->vector);
    }
    if (cq->cqid) {
        g_free(cq);
    }
}

uint16_t nvme_del_cq(NvmeCtrlBase *n, NvmeRequest *req)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)&req->cmd;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);

    if (unlikely(!qid || nvme_check_cqid(n, qid))) {
        trace_pci_nvme_err_invalid_del_cq_cqid(qid);
        return NVME_INVALID_CQID | NVME_DNR;
    }

    cq = n->cq[qid];
    if (unlikely(!QTAILQ_EMPTY(&cq->sq_list))) {
        trace_pci_nvme_err_invalid_del_cq_notempty(qid);
        return NVME_INVALID_QUEUE_DEL;
    }

    if (!nvme_cq_empty(cq) && cq->vector != -1 && !nvme_msix_enabled(n)) {
        n->irq.intx.pending--;

        nvme_irq_check_intx(n);
    }

    trace_pci_nvme_del_cq(qid);
    nvme_free_cq(cq);
    return NVME_SUCCESS;
}

uint16_t nvme_create_cq(NvmeCtrlBase *n, NvmeRequest *req)
{
    NvmeCreateCq *c = (NvmeCreateCq *)&req->cmd;
    NvmeCQueue *cq;
    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t vector = le16_to_cpu(c->irq_vector);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->cq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint32_t cc = ldq_le_p(&n->bar.cc);
    uint8_t iocqes = NVME_CC_IOCQES(cc);
    uint8_t iosqes = NVME_CC_IOSQES(cc);

    trace_pci_nvme_create_cq(prp1, cqid, vector, qsize, qflags,
                             NVME_CQ_FLAGS_IEN(qflags) != 0);

    if (iosqes != NVME_SQES || iocqes != NVME_CQES) {
        trace_pci_nvme_err_invalid_create_cq_entry_size(iosqes, iocqes);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }

    if (unlikely(!cqid || cqid > n->conf_ioqpairs || n->cq[cqid] != NULL)) {
        trace_pci_nvme_err_invalid_create_cq_cqid(cqid);
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(ldq_le_p(&n->bar.cap)))) {
        trace_pci_nvme_err_invalid_create_cq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(prp1 & (n->page_size - 1))) {
        trace_pci_nvme_err_invalid_create_cq_addr(prp1);
        return NVME_INVALID_PRP_OFFSET | NVME_DNR;
    }
    if (unlikely(nvme_addr_is_iomem(n, prp1))) {
        /*
         * Placing a queue in the controller's own MMIO would wedge the
         * controller in CSTS.FAILED at the first completion posting
         * (the re-entrancy guard blocks the access) instead of failing
         * the creation here.
         */
        trace_pci_nvme_err_invalid_create_cq_addr(prp1);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (unlikely(!msix_enabled(PCI_DEVICE(n)) && vector)) {
        trace_pci_nvme_err_invalid_create_cq_vector(vector);
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (unlikely(vector >= n->conf_msix_qsize)) {
        trace_pci_nvme_err_invalid_create_cq_vector(vector);
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (unlikely(!(NVME_CQ_FLAGS_PC(qflags)))) {
        trace_pci_nvme_err_invalid_create_cq_qflags(NVME_CQ_FLAGS_PC(qflags));
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    cq = g_malloc0(sizeof(*cq));
    nvme_init_cq(cq, n, prp1, cqid, vector, qsize + 1,
                 NVME_CQ_FLAGS_IEN(qflags));

    /*
     * It is only required to set qs_created when creating a completion
     * queue; creating a submission queue without a matching completion
     * queue will fail.
     */
    n->qs_created = true;
    return NVME_SUCCESS;
}

/* --- SQ lifecycle --- */

/*
 * Bottom-half entry: run the submission queue fetch loop.
 */
static void nvme_sq_bh(void *opaque)
{
    NvmeSQueue *sq = opaque;

    nvme_process_sq(sq);
}

/*
 * Common part of the SQ setup (like the CQ counterpart; see
 * nvme_init_cq_common).
 */
void nvme_init_sq_common(NvmeSQueue *sq)
{
    NvmeCtrlBase *n = sq->ctrl;
    int i;

    sq->io_req = g_new0(NvmeRequest, sq->size);

    QTAILQ_INIT(&sq->req_list);
    QTAILQ_INIT(&sq->out_req_list);
    for (i = 0; i < sq->size; i++) {
        sq->io_req[i].sq = sq;
        QTAILQ_INSERT_TAIL(&sq->req_list, &sq->io_req[i], entry);
    }

    sq->bh = qemu_bh_new_guarded(nvme_sq_bh, sq,
                                 &DEVICE(n)->mem_reentrancy_guard);

    if (n->dbbuf_enabled) {
        /* CAP.DSTRD is 0, so offset of the ith sq db_addr is (i << 3). */
        sq->db_addr = n->dbbuf_dbs + (sq->sqid << 3);
        sq->ei_addr = n->dbbuf_eis + (sq->sqid << 3);
    }

    if (n->dbbuf_enabled && sq->sqid != 0) {
        assert(n->db_region);
        nvme_sq_init_notifier(sq);
    }

    assert(n->cq[sq->cqid]);
    QTAILQ_INSERT_TAIL(&n->cq[sq->cqid]->sq_list, sq, entry);
    n->sq[sq->sqid] = sq;
}

void nvme_init_sq(NvmeSQueue *sq, NvmeCtrlBase *n, uint64_t dma_addr,
                  uint16_t sqid, uint16_t cqid, uint16_t size)
{
    sq->ctrl = n;
    sq->dma_addr = dma_addr;
    sq->sqid = sqid;
    sq->size = size;
    sq->cqid = cqid;
    sq->head = sq->tail = 0;

    nvme_init_sq_common(sq);
}

/*
 * A pending Async Event Request has no aiocb (the AER command is parked
 * without issuing any block I/O), so there is nothing to cancel; just
 * drop it.
 */
void nvme_sq_cancel_inflight(NvmeSQueue *sq, uint16_t status)
{
    NvmeRequest *r;

    while (!QTAILQ_EMPTY(&sq->out_req_list)) {
        r = QTAILQ_FIRST(&sq->out_req_list);
        r->status = status;

        if (r->aiocb) {
            blk_aio_cancel(r->aiocb);
        } else {
            QTAILQ_REMOVE(&sq->out_req_list, r, entry);
        }
    }
}

void nvme_free_sq(NvmeSQueue *sq)
{
    NvmeCtrlBase *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    if (cq) {
        QTAILQ_REMOVE(&cq->sq_list, sq, entry);
    }

    /* detach from the controller before freeing: glibc clobbers the
     * first bytes of freed memory, so sq->sqid may not be read after
     * g_free() */
    n->sq[sq->sqid] = NULL;

    qemu_bh_delete(sq->bh);
    nvme_sq_teardown_notifier(sq);
    g_free(sq->io_req);
    if (sq->sqid) {
        g_free(sq);
    }
}

uint16_t nvme_del_sq(NvmeCtrlBase *n, NvmeRequest *req)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)&req->cmd;
    NvmeRequest *r, *next;
    NvmeSQueue *sq;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);

    if (unlikely(!qid || nvme_check_sqid(n, qid))) {
        trace_pci_nvme_err_invalid_del_sq(qid);
        return NVME_INVALID_QID | NVME_DNR;
    }

    trace_pci_nvme_del_sq(qid);

    sq = n->sq[qid];
    nvme_sq_cancel_inflight(sq, NVME_CMD_ABORT_SQ_DEL);

    if (!nvme_check_cqid(n, sq->cqid)) {
        cq = n->cq[sq->cqid];

        nvme_post_cqes(cq);
        QTAILQ_FOREACH_SAFE(r, &cq->req_list, entry, next) {
            if (r->sq == sq) {
                QTAILQ_REMOVE(&cq->req_list, r, entry);
                QTAILQ_INSERT_TAIL(&sq->req_list, r, entry);
            }
        }
    }

    nvme_free_sq(sq);
    return NVME_SUCCESS;
}

uint16_t nvme_create_sq(NvmeCtrlBase *n, NvmeRequest *req)
{
    NvmeSQueue *sq;
    NvmeCreateSq *c = (NvmeCreateSq *)&req->cmd;

    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t sqid = le16_to_cpu(c->sqid);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->sq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    trace_pci_nvme_create_sq(prp1, sqid, cqid, qsize, qflags);

    if (unlikely(!cqid || nvme_check_cqid(n, cqid))) {
        trace_pci_nvme_err_invalid_create_sq_cqid(cqid);
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (unlikely(!sqid || sqid > n->conf_ioqpairs || n->sq[sqid] != NULL)) {
        trace_pci_nvme_err_invalid_create_sq_sqid(sqid);
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(ldq_le_p(&n->bar.cap)))) {
        trace_pci_nvme_err_invalid_create_sq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(prp1 & (n->page_size - 1))) {
        trace_pci_nvme_err_invalid_create_sq_addr(prp1);
        return NVME_INVALID_PRP_OFFSET | NVME_DNR;
    }
    if (unlikely(nvme_addr_is_iomem(n, prp1))) {
        /*
         * Placing a queue in the controller's own MMIO would wedge the
         * controller in CSTS.FAILED at the first command fetch (the
         * re-entrancy guard blocks the access) instead of failing the
         * creation here.
         */
        trace_pci_nvme_err_invalid_create_sq_addr(prp1);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (unlikely(!(NVME_SQ_FLAGS_PC(qflags)))) {
        trace_pci_nvme_err_invalid_create_sq_qflags(NVME_SQ_FLAGS_PC(qflags));
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    sq = g_malloc0(sizeof(*sq));
    nvme_init_sq(sq, n, prp1, sqid, cqid, qsize + 1);
    return NVME_SUCCESS;
}

/*
 * The single submission queue fetch loop, run by the queue's bottom
 * half (and by the shadow doorbell event notifier). A device model
 * with device-specific admission semantics installs the sq_admit
 * class hook: it is called once a command has been fetched and its
 * request set up, and may decline to start the command.
 */
void nvme_process_sq(NvmeSQueue *sq)
{
    NvmeCtrlBase *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeBaseClass *nc = NVME_BASE_GET_CLASS(n);

    uint16_t status;
    hwaddr addr;
    NvmeCmd cmd;
    NvmeRequest *req;

    /*
     * We don't want to have a race with nvme_ctrl_pre_save().
     * What implicitly protects us from this is BQL.
     */
    assert(bql_locked());

    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list))) {
        addr = sq->dma_addr + (sq->head << NVME_SQES);
        if (dma_memory_read(pci_get_address_space(PCI_DEVICE(n)), addr,
                            (void *)&cmd, sizeof(cmd),
                            MEMTXATTRS_UNSPECIFIED)) {
            trace_pci_nvme_err_addr_read(addr);
            trace_pci_nvme_err_cfs();
            stl_le_p(&n->bar.csts, NVME_CSTS_FAILED);
            break;
        }

        req = QTAILQ_FIRST(&sq->req_list);
        QTAILQ_REMOVE(&sq->req_list, req, entry);
        QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);
        nvme_req_clear(req);
        req->cqe.sq_id = cpu_to_le16(sq->sqid);
        req->cqe.cid = cmd.cid;
        memcpy(&req->cmd, &cmd, sizeof(NvmeCmd));

        if (nc->sq_admit && !nc->sq_admit(sq, req)) {
            /*
             * The device declines to start this command yet: put the
             * request back and leave the command unconsumed. The
             * decline is re-evaluated as the in-flight state changes
             * (the test device holds a command back at an atomic
             * write batch boundary until the outstanding write has
             * completed), so re-arm and retry on the next run.
             */
            QTAILQ_REMOVE(&sq->out_req_list, req, entry);
            QTAILQ_INSERT_HEAD(&sq->req_list, req, entry);
            qemu_bh_schedule(sq->bh);
            return;
        }

        nvme_inc_sq_head(sq);

        status = sq->sqid ? nc->io_cmd(n, req) : nc->admin_cmd(n, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion(cq, req);
        }
    }
}

/*
 * Process the Doorbell Buffer Config admin command: set up the shadow
 * doorbell buffer (and event index buffer) for the controller. The
 * buffers are page-sized and the offsets of the queue entries within
 * them follow the doorbell layout of the BAR (CAP.DSTRD is 0).
 *
 * For queues that already exist, rewire and initialize their shadow
 * entries with the current values; queues created later get their
 * wiring in nvme_init_sq_common()/nvme_init_cq_common().
 */
uint16_t nvme_dbbuf_config(NvmeCtrlBase *n, const NvmeRequest *req)
{
    PCIDevice *pci = PCI_DEVICE(n);
    uint64_t dbs_addr = le64_to_cpu(req->cmd.dptr.prp1);
    uint64_t eis_addr = le64_to_cpu(req->cmd.dptr.prp2);
    int i;

    /* Address should be page aligned */
    if (dbs_addr & (n->page_size - 1) ||
        eis_addr & (n->page_size - 1)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    /*
     * The shadow buffers are accessed without bouncing: the device
     * initializes the shadow doorbells, writes the event indexes on
     * every consumption, and re-reads the doorbells when a queue is
     * kicked. Validate the ranges up front instead of silently
     * dropping the per-queue writes below - a stale shadow buffer can
     * wedge a host polling on it. CAP.DSTRD is 0, so the entries are 8
     * bytes apart and the last byte touched (the last cq doorbell at
     * an offset of 4, written as a dword) is (num_queues << 3) - 1.
     */
    if (unlikely(!nvme_addr_is_mappable(n, dbs_addr,
                                        (size_t)n->num_queues << 3, true)) ||
        unlikely(!nvme_addr_is_mappable(n, eis_addr,
                                        (size_t)n->num_queues << 3, true))) {
        trace_pci_nvme_err_dbbuf_addr(dbs_addr, eis_addr);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    /* Save shadow buffer base addr for use during queue creation */
    assert(n->db_region);

    n->dbbuf_dbs = dbs_addr;
    n->dbbuf_eis = eis_addr;
    n->dbbuf_enabled = true;

    for (i = 0; i < n->num_queues; i++) {
        NvmeSQueue *sq = n->sq[i];
        NvmeCQueue *cq = n->cq[i];

        if (sq) {
            /*
             * CAP.DSTRD is 0, so offset of ith sq db_addr is (i<<3)
             * nvme_process_db() uses this hard-coded way to calculate
             * doorbell offsets. Be consistent with that here.
             */
            sq->db_addr = dbs_addr + (i << 3);
            sq->ei_addr = eis_addr + (i << 3);
            stl_le_pci_dma(pci, sq->db_addr, sq->tail,
                           MEMTXATTRS_UNSPECIFIED);

            if (i != 0) {
                nvme_sq_init_notifier(sq);
            }
        }

        if (cq) {
            /* CAP.DSTRD is 0, so offset of ith cq db_addr is (i<<3)+(1<<2) */
            cq->db_addr = dbs_addr + (i << 3) + (1 << 2);
            cq->ei_addr = eis_addr + (i << 3) + (1 << 2);
            stl_le_pci_dma(pci, cq->db_addr, cq->head,
                           MEMTXATTRS_UNSPECIFIED);

            if (i != 0) {
                nvme_cq_init_notifier(cq);
            }
        }
    }

    trace_pci_nvme_dbbuf_config(dbs_addr, eis_addr);

    return NVME_SUCCESS;
}

/*
 * Shadow doorbell notifier wiring. See the declarations near the top of
 * this file for the overall description.
 */
static void nvme_cq_notifier(EventNotifier *e)
{
    NvmeCQueue *cq = container_of(e, NvmeCQueue, notifier);

    trace_pci_nvme_cq_notifier(cq->cqid);

    if (!event_notifier_test_and_clear(e)) {
        return;
    }

    while (nvme_cq_update_head(cq)) {
cq_kick:
        nvme_cq_kick(cq);
    }

    nvme_cq_set_eventidx(cq);

    /*
     * The driver may have written the cq head after we last checked it, but
     * before we wrote the eventidx, causing the driver to skip mmio, so check
     * the head just one more time.
     */
    if (nvme_cq_update_head(cq)) {
        trace_pci_nvme_cq_notifier_race(cq->cqid);
        goto cq_kick;
    }
}

static void nvme_cq_init_notifier(NvmeCQueue *cq)
{
    NvmeCtrlBase *n = cq->ctrl;
    uint16_t offset = (cq->cqid << 3) + (1 << 2);

    if (event_notifier_init(&cq->notifier, 0)) {
        return;
    }

    event_notifier_set_handler(&cq->notifier, nvme_cq_notifier);
    memory_region_add_eventfd(n->db_region,
                              NVME_MAX_DB + offset, 4, false, 0,
                              &cq->notifier);
}

static void nvme_cq_teardown_notifier(NvmeCQueue *cq)
{
    NvmeCtrlBase *n = cq->ctrl;
    uint16_t offset = (cq->cqid << 3) + (1 << 2);

    if (cq->cqid && cq->notifier.initialized) {
        memory_region_del_eventfd(n->db_region,
                                  NVME_MAX_DB + offset, 4, false, 0,
                                  &cq->notifier);
        event_notifier_set_handler(&cq->notifier, NULL);
        event_notifier_cleanup(&cq->notifier);
    }
}

static void nvme_sq_notifier(EventNotifier *e)
{
    NvmeSQueue *sq = container_of(e, NvmeSQueue, notifier);

    trace_pci_nvme_sq_notifier(sq->sqid);

    if (!event_notifier_test_and_clear(e)) {
        return;
    }

    while (nvme_sq_update_tail(sq)) {
process_sq:
        nvme_process_sq(sq);
    }

    nvme_sq_set_eventidx(sq);

    /*
     * The driver may have written the sq tail after we last checked it, but
     * before we wrote the eventidx, causing the driver to skip mmio, so check
     * the tail just one more time.
     *
     *      HOST                    DEVICE
     *      -------------------------------------------------
     *      (post sqe at 0)
     *      sq_tail <- 1
     *      eventidx -> 0
     *      (do mmio)
     *                              (wake up)
     *                              sq_tail -> 1
     *                              (process sqe at 0)
     *                              sq_tail -> 1
     *      (post sqe at 1)
     *      sq_tail <- 2
     *      eventidx -> 0
     *      (skip mmio)
     *                              eventidx <- 1
     *                              (sleep, lost sqe at 1)
     */

    if (nvme_sq_update_tail(sq)) {
        trace_pci_nvme_sq_notifier_race(sq->sqid);
        goto process_sq;
    }
}

static void nvme_sq_init_notifier(NvmeSQueue *sq)
{
    NvmeCtrlBase *n = sq->ctrl;
    uint16_t offset = sq->sqid << 3;

    if (event_notifier_init(&sq->notifier, 0)) {
        return;
    }

    event_notifier_set_handler(&sq->notifier, nvme_sq_notifier);
    memory_region_add_eventfd(n->db_region,
                              NVME_MAX_DB + offset, 4, false, 0,
                              &sq->notifier);
}

static void nvme_sq_teardown_notifier(NvmeSQueue *sq)
{
    NvmeCtrlBase *n = sq->ctrl;
    uint16_t offset = sq->sqid << 3;

    if (sq->sqid && sq->notifier.initialized) {
        memory_region_del_eventfd(n->db_region,
                                  NVME_MAX_DB + offset, 4, false, 0,
                                  &sq->notifier);
        event_notifier_set_handler(&sq->notifier, NULL);
        event_notifier_cleanup(&sq->notifier);
    }
}
