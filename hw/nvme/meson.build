# Core shared helpers: PRP/SGL mapping (dptr.c), DMA transfer (dma.c), queue
# mechanics (queue.c) and interrupt delivery (irq.c). In the security
# boundary. Built when either device is enabled.
system_ss.add(when: 'CONFIG_NVME_PCI', if_true: files('core/dptr.c', 'core/dma.c', 'core/queue.c', 'core/irq.c'))

# Test (everything) device: -device nvme. NOT in the security boundary.
system_ss.add(when: 'CONFIG_NVME_PCI', if_true: files(
  'test/ctrl.c',
  'test/dif.c',
  'test/ns.c',
  'test/subsys.c',
  'test/nguid.c',
))
