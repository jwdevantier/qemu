# Core shared helpers: the abstract base class (base.c), PRP/SGL mapping
# (dptr.c), DMA transfer (dma.c), queue mechanics (queue.c), interrupt
# delivery (irq.c) and the generic admin command semantics installed as
# base-class defaults (admin.c). In the security boundary. Built when
# the nvme device is enabled.
core_files = files('core/base.c', 'core/dptr.c', 'core/dma.c', 'core/queue.c', 'core/irq.c', 'core/admin.c')
system_ss.add(when: 'CONFIG_NVME_PCI', if_true: core_files)

# Test (everything) device: -device nvme. NOT in the security boundary.
system_ss.add(when: 'CONFIG_NVME_PCI', if_true: files(
  'test/ctrl.c',
  'test/dif.c',
  'test/ns.c',
  'test/subsys.c',
  'test/nguid.c',
))
