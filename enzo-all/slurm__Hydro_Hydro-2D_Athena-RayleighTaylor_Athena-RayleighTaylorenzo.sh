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
echo slurm__Hydro_Hydro-2D_Athena-RayleighTaylor_Athena-RayleighTaylorenzo.sh
echo $tmpdir

export LD_LIBRARY_PATH=${HOME}/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-$(hostname)
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-hdf-julea/lib
export J_TIMER_DB_RUN="${HOME}/julea/slurm__Hydro_Hydro-2D_Athena-RayleighTaylor_Athena-RayleighTaylorenzo.sqlite"
export J_TIMER_DB="${HOME}/julea/slurm__Hydro_Hydro-2D_Athena-RayleighTaylor_Athena-RayleighTaylorenzo.sqlite"
#export G_MESSAGES_DEBUG=all

cat ${HOME}/.config/julea/julea-$(hostname)

${HOME}/julea/build-hdf-julea/server/julea-server &

sleep 1s

cp -r ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/Athena-RayleighTaylor/* $tmpdir
cd $tmpdir
echo $PWD
ls -la

rm $J_TIMER_DB

cat ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/Athena-RayleighTaylor/Athena-RayleighTaylor.enzo | grep -v "ResubmitOn" | grep -v "StopCPUTime" | grep -v "ResubmitCommand" > ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/Athena-RayleighTaylor/Athena-RayleighTaylor.enzo.tmp
echo "ResubmitOn = 1" >> ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/Athena-RayleighTaylor/Athena-RayleighTaylor.enzo.tmp
echo "StopCPUTime = 1" >> ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/Athena-RayleighTaylor/Athena-RayleighTaylor.enzo.tmp
echo "ResubmitCommand = ${HOME}/julea/enzo-all/run-continue.sh" >> ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/Athena-RayleighTaylor/Athena-RayleighTaylor.enzo.tmp


time ${HOME}/enzo-dev/src/enzo/enzo.exe ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/Athena-RayleighTaylor/Athena-RayleighTaylor.enzo.tmp

du -sh *
du -sh .