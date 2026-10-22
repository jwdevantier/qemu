/*
 * QEMU NVM Express — abstract device base class
 *
 * Registers the abstract 'nvme-base' type that the NVMe device models
 * derive from. This code is in the
 * QEMU security boundary.
 *
 * Copyright (c) 2025 Samsung Electronics Co., Ltd.
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/nvme/core/nvme.h"

static void nvme_base_class_init(ObjectClass *oc, const void *data)
{
    NvmeBaseClass *bc = NVME_BASE_CLASS(oc);

    /*
     * Install the generic admin command semantics as class defaults:
     * a device model that does not override admin_cmd inherits the
     * generic dispatcher, which delegates commands outside the
     * generic set to admin_cmd_custom (defaulting to a rejection).
     *
     * io_cmd has no default (every device must install its command
     * dispatch in its own class_init), sq_admit and process_aers are
     * optional and default to NULL, and 'bounce' defaults to false
     * (reject non-mappable data pointers; only the test device opts
     * into bouncing).
     */
    bc->admin_cmd = nvme_admin_cmd;
    bc->admin_cmd_custom = nvme_admin_cmd_custom;
}

static const TypeInfo nvme_base_info = {
    .name = TYPE_NVME_BASE,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(NvmeCtrlBase),
    .class_size = sizeof(NvmeBaseClass),
    .class_init = nvme_base_class_init,
    .abstract = true,
};

static void nvme_base_register_types(void)
{
    type_register_static(&nvme_base_info);
}

type_init(nvme_base_register_types);
