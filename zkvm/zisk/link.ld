OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH("riscv")
ENTRY(_start)

/* ZisK pins this layout by constant (zisk-core, core/src/mem.rs), so the guest
   image has to line up with it exactly:
     0x80000000 ROM_ADDR            program instructions
     0x87f00000 FLOAT_LIB_ROM_ADDR  float library instructions
     0xa0000000 RAM_ADDR            4 MiB program stack, sp starts at its top
     0xa0400000 SYS_ADDR            64 KiB: the 32 registers, UART, float regs, CSRs
     0xa0410000 OUTPUT_ADDR         128 KiB public output; ziskemu and the prover
                                    read the guest's output back from here
     0xa0430000                     general purpose RAM
     0xbfff0000 FLOAT_LIB_RAM_ADDR  float library RAM and its stack
     0xc0000000                     end of RAM
   The stack, sys and output windows are reserved below as empty NOLOAD sections
   (as zisk's own ziskbuild/zisk_linker_script.ld does) so that .data/.bss/heap
   land in the general purpose RAM behind them: anything we place over those
   windows corrupts the emulated registers or the output the verifier reads back. */
MEMORY {
  rom   (xa)  : ORIGIN = 0x80000000, LENGTH = 0x07F00000
  ram   (wxa) : ORIGIN = 0xa0000000, LENGTH = 0x20000000
}

_stack_size                  = 0x400000;  /* 4 MiB, STACK_SIZE */
_general_registers_data_size = 0x8000;    /* 32 KiB */
_float_registers_data_size   = 0x8000;    /* 32 KiB, together the 64 KiB sys window */
_output_data_size            = 0x20000;   /* 128 KiB, OUTPUT_MAX_SIZE */
_float_ram_data_size         = 0x10000;   /* 64 KiB reserved at the top of RAM */

PHDRS {
  text PT_LOAD FLAGS(1);
  rodata PT_LOAD FLAGS(4);
  stack_data PT_LOAD FLAGS(6);
  general_registers_data PT_LOAD FLAGS(6);
  float_registers_data PT_LOAD FLAGS(6);
  output_data PT_LOAD FLAGS(6);
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

  /* ziskos' _zisk_main walks these arrays around the guest entry point, and it
     references the bound symbols strongly, so both sections must exist even
     though Zig emits no static initializers: without them lld synthesizes the
     symbols at the ELF header (~0x0) and the auipc pairs in _zisk_main blow
     past the +-2GiB PC-relative range from .text at 0x80000000. They stay
     empty (start == end) here, so they cost nothing. */
  .init_array : ALIGN(8) SUBALIGN(8) {
    PROVIDE(__init_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP(*(.init_array))
    PROVIDE(__init_array_end = .);
  } >rom AT>rom :rodata

  .fini_array : ALIGN(8) SUBALIGN(8) {
    PROVIDE(__fini_array_start = .);
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP(*(.fini_array))
    PROVIDE(__fini_array_end = .);
  } >rom AT>rom :rodata

  /* ziskos' _start does `la sp, _init_stack_top` */
  . = ORIGIN(ram);
  .stack_data (NOLOAD) : {
    PROVIDE(_stack_start = .);
    PROVIDE(_init_stack_bottom = .);
    . = . + _stack_size;
    PROVIDE(_init_stack_top = .);
  } >ram AT>ram :stack_data

  .general_registers_data (NOLOAD) : {
    PROVIDE(_general_registers_data_start = .);
    . = . + _general_registers_data_size;
    PROVIDE(_general_registers_data_end = .);
  } >ram AT>ram :general_registers_data

  .float_registers_data (NOLOAD) : {
    PROVIDE(_float_registers_data_start = .);
    . = . + _float_registers_data_size;
    PROVIDE(_float_registers_data_end = .);
  } >ram AT>ram :float_registers_data

  .output_data (NOLOAD) : {
    PROVIDE(_output_data_start = .);
    . = . + _output_data_size;
    PROVIDE(_output_data_end = .);
  } >ram AT>ram :output_data

  .data : ALIGN(8) SUBALIGN(8) { *(.data .data.* .sdata .sdata.*) } >ram AT>ram :data

  .bss : ALIGN(8) SUBALIGN(8) {
    PROVIDE(_bss_start = .);
    *(.bss .bss.* .sbss .sbss.*);
    PROVIDE(_bss_end = .);
  } >ram AT>ram :bss

  . = ALIGN(16);

  /* zevm's FixedBufferAllocator owns the rest of the general purpose RAM.
     ziskos keeps its own heap in a static .bss buffer inside libziskos.a, so
     nothing else claims this region. */
  PROVIDE(_evm_heap_bottom = .);
  PROVIDE(_evm_heap_top = ORIGIN(ram) + LENGTH(ram) - _float_ram_data_size);
  PROVIDE(_evm_heap_size = _evm_heap_top - _evm_heap_bottom);

  _end = .;
}
