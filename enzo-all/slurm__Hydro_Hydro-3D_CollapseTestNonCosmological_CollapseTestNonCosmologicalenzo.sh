#!/bin/bash
#SBATCH -J enzo
#SBATCH --partition=west
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --time=01:30:00

tmpdir=/dev/shm/warnke/julea

rm -rf $tmpdir
mkdir -p $tmpdir

echo $(hostname)
echo slurm__Hydro_Hydro-3D_CollapseTestNonCosmological_CollapseTestNonCosmologicalenzo.sh
echo $tmpdir

export LD_LIBRARY_PATH=${HOME}/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-$(hostname)
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-hdf-julea/lib
#export LD_PRELOAD="$(locate libSegFault.so | tail -n 1)"
#export SEGFAULT_SIGNALS="all"
export J_TIMER_DB="${HOME}/julea/slurm__Hydro_Hydro-3D_CollapseTestNonCosmological_CollapseTestNonCosmologicalenzo.sqlite"
export G_MESSAGES_DEBUG=all

cat ${HOME}/.config/julea/julea-$(hostname)

${HOME}/julea/build-hdf-julea/server/julea-server &

sleep 1s

cp -r ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/CollapseTestNonCosmological/* $tmpdir
cd $tmpdir
echo $PWD
ls -la
time ${HOME}/enzo-dev/src/enzo/enzo.exe -d ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/CollapseTestNonCosmological/CollapseTestNonCosmological.enzo
du -sh *
du -sh .
