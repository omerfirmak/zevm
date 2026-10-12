# Instruction-boundary scanning

The lazy decoder marks instruction starts in 64-bit words. It accumulates each
word in a register and merges it once, preserving earlier bits when a partial
scan resumes. A 256-byte opcode-length table handles PUSH data; Amsterdam's
validated immediates retain their fork-specific handling.

Build and run the opt-in benchmark with Zig 0.17.0:

```sh
zig build bench-bytecode -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v3
zig-out/bin/zevm-bytecode-bench 500 50
```

Each iteration initializes bytecode, validates a far jump, and releases it.
The fixed-buffer allocator resets between iterations. Workloads are seeded and
include PUSH1/JUMPDEST filler, PUSH32 data, and synthetic mixes of ordinary
opcodes. They are not application traces or full EVM throughput measurements.

On an AMD Ryzen 5 3600, in a one-CPU container on a shared host, four alternating
process runs per version produced these medians of per-run median nanoseconds.
Each run used 500 measured iterations after 50 warmups. The baseline is
`9afa3dd`, with the same benchmark source and compiler options.

| Fork | Workload | Baseline ns | Word bitmap and table ns |
| --- | --- | ---: | ---: |
| Amsterdam | 64 KiB PUSH1/JUMPDEST | 182,399 | 105,397 |
| Amsterdam | 64 KiB PUSH32 | 5,096 | 5,955 |
| Amsterdam | 64 KiB ordinary-opcode mix | 96,592 | 79,226.5 |
| Amsterdam | 128-byte ordinary-opcode mix | 325 | 340 |
| Osaka | 64 KiB PUSH1/JUMPDEST | 109,797 | 104,252 |
| Osaka | 64 KiB PUSH32 | 6,265 | 5,665 |
| Osaka | 64 KiB ordinary-opcode mix | 80,251.5 | 77,626.5 |
| Osaka | 128-byte ordinary-opcode mix | 405 | 355 |

The branch-heavy far-jump case improves, but the Amsterdam PUSH32 and short
cases regress. Results differ by CPU and code distribution; no general EVM
speedup is implied. The benchmark has no timing assertions.

Six additional tests compare boundary classification with an independent
scalar scan and cover resumed words, padding, truncated PUSH data, page
frontiers, and Amsterdam immediate combinations. All 90 unit tests pass in
Debug and ReleaseSafe. The changed scanner also passes all 5,199 Amsterdam and
Osaka state fixture files from execution-specs `tests@v21.0.1`, covering 31,671
cases. This fixture run uses the default owned-code path and does not cover an
integrator's external code store or the blockchain/Engine suites.
