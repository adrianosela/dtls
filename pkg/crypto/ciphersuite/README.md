# Ciphersuite Package

This package provides DTLS cipher suite implementations for GCM, CCM, and CBC modes.

## Benchmarking

The package includes comprehensive benchmarks for all cipher operations across multiple payload sizes.

<<<<<<< HEAD
**Note:** Benchmarks are excluded from regular test runs using build tags. You must specify `-tags=bench` to run them.

### Running all ciphersuite benchmarks

```bash
go test -tags=bench -bench=. -benchmem
=======
### Running all ciphersuite benchmarks

```bash
go test -bench=. -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

### Running a specific benchmark

- GCM benchmarks only:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkGCM -benchmem
=======
go test -bench=BenchmarkGCM -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- GCM `Encrypt` benchmark only:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkGCMEncrypt -benchmem
=======
go test -bench=BenchmarkGCMEncrypt -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- GCM `Decrypt` benchmark only:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkGCMDecrypt -benchmem
=======
go test -bench=BenchmarkGCMDecrypt -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- CCM benchmarks only:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkCCM -benchmem
=======
go test -bench=BenchmarkCCM -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- CCM `Encrypt` benchmark only:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkCCMEncrypt -benchmem
=======
go test -bench=BenchmarkCCMEncrypt -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- CCM `Decrypt` benchmark only:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkCCMDecrypt -benchmem
=======
go test -bench=BenchmarkCCMDecrypt -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- CBC benchmarks only:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkCBC -benchmem
=======
go test -bench=BenchmarkCBC -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- CBC `Encrypt` benchmark only:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkCBCEncrypt -benchmem
=======
go test -bench=BenchmarkCBCEncrypt -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- CBC `Decrypt` benchmark only:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkCBCDecrypt -benchmem
=======
go test -bench=BenchmarkCBCDecrypt -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- All cipgers, with 1KB payloads only

```bash
<<<<<<< HEAD
go test -tags=bench -bench=/1KB -benchmem
=======
go test -bench=/1KB -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

- All cipgers, with 16B payloads only

```bash
<<<<<<< HEAD
go test -tags=bench -bench=/16B -benchmem
=======
go test -bench=/16B -benchmem
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

### Benchmark Options

Increase benchmark time for more accurate results:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkGCM -benchmem -benchtime=5s
=======
go test -bench=BenchmarkGCM -benchmem -benchtime=5s
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

Run benchmarks multiple times:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkGCM -benchmem -count=5
=======
go test -bench=BenchmarkGCM -benchmem -count=5
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
```

### Understanding Results

Example output:

```
BenchmarkGCMEncrypt/016B-8  5895367  202.6 ns/op  78.99 MB/s   160 B/op  5 allocs/op
```

- `5895367`: Number of iterations
- `202.6 ns/op`: Time per operation
- `78.99 MB/s`: Throughput
- `160 B/op`: Bytes allocated per operation
- `5 allocs/op`: Number of allocations per operation


## Profiling

Generate CPU profile:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkGCMEncrypt -benchmem -cpuprofile=cpu.prof
=======
go test -bench=BenchmarkGCMEncrypt -benchmem -cpuprofile=cpu.prof
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
go tool pprof -top cpu.prof
```

Generate memory profile:

```bash
<<<<<<< HEAD
go test -tags=bench -bench=BenchmarkGCMEncrypt -benchmem -memprofile=mem.prof
=======
go test -bench=BenchmarkGCMEncrypt -benchmem -memprofile=mem.prof
>>>>>>> 03d6239 (Add Ciphersuite Benchmark Tests)
go tool pprof -top -alloc_objects mem.prof
```