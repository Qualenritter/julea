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
echo slurm__Hydro_Hydro-2D_ValidatedNonlinearKelvinHelmholtz_2D-LongKH-AMRenzo.sh
echo $tmpdir

export LD_LIBRARY_PATH=${HOME}/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-$(hostname)
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-hdf-julea/lib
export J_TIMER_DB_RUN="${HOME}/julea/slurm__Hydro_Hydro-2D_ValidatedNonlinearKelvinHelmholtz_2D-LongKH-AMRenzo.sqlite"
export J_TIMER_DB="${HOME}/julea/slurm__Hydro_Hydro-2D_ValidatedNonlinearKelvinHelmholtz_2D-LongKH-AMRenzo.sqlite"
#export G_MESSAGES_DEBUG=all

cat ${HOME}/.config/julea/julea-$(hostname)

${HOME}/julea/build-hdf-julea/server/julea-server &

sleep 1s

cp -r ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/ValidatedNonlinearKelvinHelmholtz/* $tmpdir
cd $tmpdir
echo $PWD
ls -la

rm 

cat ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/ValidatedNonlinearKelvinHelmholtz/2D-LongKH-AMR.enzo | grep -v "ResubmitOn" | grep -v "StopCPUTime" | grep -v "ResubmitCommand" > ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/ValidatedNonlinearKelvinHelmholtz/2D-LongKH-AMR.enzo.tmp1
echo "ResubmitOn = 1" >> ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/ValidatedNonlinearKelvinHelmholtz/2D-LongKH-AMR.enzo.tmp1
echo "StopCPUTime = 1" >> ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/ValidatedNonlinearKelvinHelmholtz/2D-LongKH-AMR.enzo.tmp1
echo "ResubmitCommand = ${HOME}/julea/enzo-all/run-continue.sh" >> ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/ValidatedNonlinearKelvinHelmholtz/2D-LongKH-AMR.enzo.tmp1


time ${HOME}/enzo-dev/src/enzo/enzo.exe ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/ValidatedNonlinearKelvinHelmholtz/2D-LongKH-AMR.enzo

du -sh *
du -sh .
