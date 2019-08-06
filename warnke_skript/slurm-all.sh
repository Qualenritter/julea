#!/bin/bash
./waf.sh configure --out build-gcc-benchmark --prefix=prefix-gcc-benchmark --libdir=prefix-gcc-benchmark --bindir=prefix-gcc-benchmark --destdir=prefix-gcc-benchmark
./waf.sh build
./waf.sh install
sbatch slurm-benchmark-hdd.sh
sbatch slurm-benchmark-zram.sh
sbatch slurm-benchmark-memory.sh
