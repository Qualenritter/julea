#!/bin/bash
#SBATCH -J ${name}
#SBATCH --output=${name}-slurm.out
#SBATCH --partition=west
#SBATCH --ntasks=1
#SBATCH --nodes=1
./scripts/warnke_script/afl.sh $(($RANDOM * 100))
