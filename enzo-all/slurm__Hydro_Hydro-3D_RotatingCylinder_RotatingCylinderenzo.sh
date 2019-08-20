#!/bin/bash
#SBATCH -J enzo
#SBATCH --partition=west
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --time=01:30:00

tmpdir=/dev/shm/warnke/julea

rm -rf $tmpdir
mkdir -p $tmpdir

echo slurm__Hydro_Hydro-3D_RotatingCylinder_RotatingCylinderenzo.sh
echo $tmpdir

export LD_LIBRARY_PATH=${HOME}/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-west-10
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-hdf-julea/lib
export LD_PRELOAD="$(locate libSegFault.so | tail -n 1)"
export SEGFAULT_SIGNALS="all"
export J_TIMER_DB="${HOME}/julea/slurm__Hydro_Hydro-3D_RotatingCylinder_RotatingCylinderenzo.sqlite"
export G_MESSAGES_DEBUG=all

sleep 10s

cat ${HOME}/.config/julea/julea-slurm__Hydro_Hydro-3D_RotatingCylinder_RotatingCylinderenzo

${HOME}/julea/build-hdf-julea/server/julea-server &

sleep 10s

cp -r ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/RotatingCylinder/* $tmpdir
cd $tmpdir
echo $PWD
ls -la
time ${HOME}/enzo-dev/src/enzo/enzo.exe -d ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/RotatingCylinder/RotatingCylinder.enzo
du -sh *
du -sh .
