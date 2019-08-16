#!/bin/bash
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
