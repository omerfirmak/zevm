OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
  rom   (xa)  : ORIGIN = 0x80000000, LENGTH = 0x10000000
  ram   (wxa) : ORIGIN = 0xa0020000, LENGTH = 0x1FFE0000
}

PHDRS {
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  bss PT_LOAD FLAGS(6);
}

SECTIONS
{
  /DISCARD/ : { *(.eh_frame) *(.eh_frame.*) *(.eh_frame_hdr) *(.eh_frame_hdr.*) }

  .text : ALIGN(8) SUBALIGN(8) { *(.text.init) *(.text .text.*) } >rom AT>rom :text

  . = ALIGN(8);
  PROVIDE(_global_pointer = .);
  PROVIDE(__global_pointer$ = .);
  .rodata : ALIGN(8) SUBALIGN(8) { *(.rodata .rodata.*) } >rom AT>rom :rodata

  .data : ALIGN(8) SUBALIGN(8) { *(.data .data.* .sdata .sdata.*) } >ram AT>ram :data

  .bss : ALIGN(8) SUBALIGN(8) {
    PROVIDE(_bss_start = .);
    *(.bss .bss.*);
    PROVIDE(_bss_end = .);
  } >ram AT>ram :bss

  . = ALIGN(16);
  PROVIDE(_init_stack_top = . + 0x100000);

  /* ziskos' Rust bump allocator reads these symbols; cap it to a fixed 16 MiB
     region so its (never-freed) precompile scratch can't collide with zevm's
     allocator, which shares the same RAM. */
  PROVIDE(_kernel_heap_bottom = _init_stack_top);
  PROVIDE(_kernel_heap_top = _kernel_heap_bottom + 0x1000000);
  PROVIDE(_kernel_heap_size = _kernel_heap_top - _kernel_heap_bottom);

  /* zevm's FixedBufferAllocator owns the remainder of RAM, disjoint from the
     ziskos region above. */
  PROVIDE(_evm_heap_bottom = _kernel_heap_top);
  PROVIDE(_evm_heap_top = ORIGIN(ram) + LENGTH(ram));
  PROVIDE(_evm_heap_size = _evm_heap_top - _evm_heap_bottom);

  _end = .;
}
