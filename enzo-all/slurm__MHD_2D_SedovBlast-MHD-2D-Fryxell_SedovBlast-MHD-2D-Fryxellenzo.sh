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
echo slurm__MHD_2D_SedovBlast-MHD-2D-Fryxell_SedovBlast-MHD-2D-Fryxellenzo.sh
echo $tmpdir

export LD_LIBRARY_PATH=${HOME}/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-$(hostname)
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-hdf-julea/lib
export J_TIMER_DB_RUN="${HOME}/julea/slurm__MHD_2D_SedovBlast-MHD-2D-Fryxell_SedovBlast-MHD-2D-Fryxellenzo.sqlite"
export J_TIMER_DB="${HOME}/julea/slurm__MHD_2D_SedovBlast-MHD-2D-Fryxell_SedovBlast-MHD-2D-Fryxellenzo.sqlite"
#export G_MESSAGES_DEBUG=all

cat ${HOME}/.config/julea/julea-$(hostname)

${HOME}/julea/build-hdf-julea/server/julea-server &

sleep 1s

cp -r ${HOME}/enzo-dev/run/./MHD/2D/SedovBlast-MHD-2D-Fryxell/* $tmpdir
cd $tmpdir
echo $PWD
ls -la

rm $J_TIMER_DB

cat ${HOME}/enzo-dev/run/./MHD/2D/SedovBlast-MHD-2D-Fryxell/SedovBlast-MHD-2D-Fryxell.enzo | grep -v "ResubmitOn" | grep -v "StopCPUTime" | grep -v "ResubmitCommand" > ${HOME}/enzo-dev/run/./MHD/2D/SedovBlast-MHD-2D-Fryxell/SedovBlast-MHD-2D-Fryxell.enzo.tmp
echo "ResubmitOn = 1" >> ${HOME}/enzo-dev/run/./MHD/2D/SedovBlast-MHD-2D-Fryxell/SedovBlast-MHD-2D-Fryxell.enzo.tmp
echo "StopCPUTime = 1" >> ${HOME}/enzo-dev/run/./MHD/2D/SedovBlast-MHD-2D-Fryxell/SedovBlast-MHD-2D-Fryxell.enzo.tmp
echo "ResubmitCommand = ${HOME}/julea/enzo-all/run-continue.sh" >> ${HOME}/enzo-dev/run/./MHD/2D/SedovBlast-MHD-2D-Fryxell/SedovBlast-MHD-2D-Fryxell.enzo.tmp


time ${HOME}/enzo-dev/src/enzo/enzo.exe ${HOME}/enzo-dev/run/./MHD/2D/SedovBlast-MHD-2D-Fryxell/SedovBlast-MHD-2D-Fryxell.enzo.tmp

du -sh *
du -sh .