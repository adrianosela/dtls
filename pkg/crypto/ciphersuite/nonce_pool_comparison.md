# ChaCha20-Poly1305 Nonce Pooling Results

## Comparison: Pre-allocated Buffer vs Nonce Pool

### Encrypt

| Metric | Pre-allocated (after) | Nonce Pool | Improvement |
|--------|----------------------|------------|-------------|
| **Allocations** | 4 allocs/op | **3 allocs/op** | **-1 alloc (25% reduction)** ✓ |
| **Memory (16B)** | 112 B/op | **96 B/op** | **-16B (14% reduction)** ✓ |
| **Memory (64B)** | 208 B/op | **192 B/op** | **-16B** ✓ |
| **Memory (128B)** | 336 B/op | **320 B/op** | **-16B** ✓ |
| **Memory (256B)** | 608 B/op | **592 B/op** | **-16B** ✓ |
| **Perf (16B)** | ~322ns | ~307ns | Comparable/slightly better |
| **Perf (64B)** | ~350ns | ~346ns | Comparable |
| **Perf (128B)** | ~425ns | ~411ns | **3% faster** ✓ |
| **Perf (256B)** | ~760ns | ~700ns | **8% faster** ✓ |

### Decrypt

| Metric | Pre-allocated (after) | Nonce Pool | Improvement |
|--------|----------------------|------------|-------------|
| **Allocations** | 4 allocs/op | **3 allocs/op** | **-1 alloc (25% reduction)** ✓ |
| **Memory (16B)** | 96 B/op | **80 B/op** | **-16B (17% reduction)** ✓ |
| **Memory (64B)** | 192 B/op | **176 B/op** | **-16B** ✓ |
| **Memory (256B)** | 576 B/op | **560 B/op** | **-16B** ✓ |
| **Memory (512B)** | 1120 B/op | **1104 B/op** | **-16B** ✓ |
| **Perf (16B)** | ~315ns | ~319ns | Comparable |
| **Perf (64B)** | ~365ns | ~353ns | **3% faster** ✓ |
| **Perf (256B)** | ~725ns | ~720ns | Comparable |
| **Perf (512B)** | ~1080ns | ~1060ns | **2% faster** ✓ |

## Overall Improvement vs Base

### Encrypt
- **Base**: 5 allocs/op, 144B (16B), ~322ns
- **Nonce Pool**: **3 allocs/op** (-2), **96B** (-48B), ~307ns
- **Result**: 40% fewer allocations, 33% less memory ✓✓✓

### Decrypt
- **Base**: 4 allocs/op, 96B (16B), ~315ns
- **Nonce Pool**: **3 allocs/op** (-1), **80B** (-16B), ~319ns
- **Result**: 25% fewer allocations, 17% less memory ✓✓

## Recommendation

**Use nonce pooling!** It provides:
1. One fewer allocation per operation
2. 16 bytes less memory per operation
3. Comparable or slightly better performance
4. Consistent with the AEAD abstraction pattern

The nonce is fixed-size (12 bytes for ChaCha20-Poly1305), making it perfect for pooling.
