# ChaCha20-Poly1305 Encrypt Optimization Comparison

## Base (original implementation)
- **Allocations**: 5 allocs/op
- **Memory**: 144B (16B), 288B (64B), 480B (128B), 896B (256B), 1760B (512B)
- **Performance**: ~322ns (16B), ~368ns (64B), ~470ns (128B), ~768ns (256B), ~1130ns (512B)

## Pre-allocated Buffer (current "after" version)
- **Allocations**: 4 allocs/op (-1 allocation, 20% reduction)
- **Memory**: 112B (16B), 208B (64B), 336B (128B), 608B (256B), 1184B (512B)
- **Performance**: ~322ns (16B), ~350ns (64B), ~425ns (128B), ~760ns (256B), ~1100ns (512B)
- **Result**: 5-10% faster, 1 fewer allocation ✓

## Buffer Pool (sync.Pool)
- **Allocations**: 4 allocs/op (same as pre-allocated)
- **Memory**: 112B (16B), 208B (64B), 336B (128B), 608B (256B), 1184B (512B)
- **Performance**: ~340ns (16B), ~360ns (64B), ~430ns (128B), ~740ns (256B), ~1065ns (512B)
- **Result**: Comparable to pre-allocated, slightly slower on small sizes

## Comparison: Pre-allocated vs Buffer Pool

| Size | Pre-allocated (ns) | Buffer Pool (ns) | Difference |
|------|-------------------|------------------|------------|
| 16B  | ~322              | ~340             | +18ns (5% slower) |
| 64B  | ~350              | ~360             | +10ns (3% slower) |
| 128B | ~425              | ~430             | +5ns (1% slower) |
| 256B | ~760              | ~740             | -20ns (3% faster) |
| 512B | ~1100             | ~1065            | -35ns (3% faster) |

## Analysis

**Pre-allocated buffer wins for small packets (16B-128B)** - most common in DTLS
- Simpler code
- No pool overhead
- No extra copy needed

**Buffer pool shows minimal benefit**:
- Requires extra copy (can't return pooled buffer directly)
- Pool get/put overhead
- Only slightly faster on larger sizes (256B+)

## Recommendation

**Use pre-allocated buffer approach** - cleaner, faster for common DTLS packet sizes, and simpler to maintain.
