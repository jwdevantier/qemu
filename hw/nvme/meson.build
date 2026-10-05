# Test (everything) device: -device nvme. NOT in the security boundary.
system_ss.add(when: 'CONFIG_NVME_PCI', if_true: files(
  'test/ctrl.c',
  'test/dif.c',
  'test/ns.c',
  'test/subsys.c',
  'test/nguid.c',
))
