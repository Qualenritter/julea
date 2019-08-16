#!/bin/bash
./waf.sh configure --out build-gcc-benchmark --prefix=prefix-gcc-benchmark --libdir=prefix-gcc-benchmark --bindir=prefix-gcc-benchmark --destdir=prefix-gcc-benchmark
./waf.sh build
./waf.sh install
sleep 5
sbatch ./warnke_skript/slurm-enzo-hdd-julea.sh
sleep 5
sbatch ./warnke_skript/slurm-enzo-hdd-native.sh
sleep 5
sbatch ./warnke_skript/slurm-enzo-memory-julea.sh
sleep 5
sbatch ./warnke_skript/slurm-enzo-zram-julea.sh
sleep 5
sbatch ./warnke_skript/slurm-enzo-zram-native.sh
