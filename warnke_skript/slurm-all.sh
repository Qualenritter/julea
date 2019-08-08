#!/bin/bash
./waf.sh configure --out build-gcc-benchmark --prefix=prefix-gcc-benchmark --libdir=prefix-gcc-benchmark --bindir=prefix-gcc-benchmark --destdir=prefix-gcc-benchmark
./waf.sh build
./waf.sh install
sleep 5
sbatch ./warnke_skript/slurm-benchmark-hdd.sh
sleep 5
sbatch ./warnke_skript/slurm-benchmark-zram.sh
sleep 5
sbatch ./warnke_skript/slurm-benchmark-memory.sh
