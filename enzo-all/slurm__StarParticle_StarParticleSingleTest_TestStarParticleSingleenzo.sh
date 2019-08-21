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
echo slurm__StarParticle_StarParticleSingleTest_TestStarParticleSingleenzo.sh
echo $tmpdir

export LD_LIBRARY_PATH=${HOME}/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-$(hostname)
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-hdf-julea/lib
export J_TIMER_DB_RUN="${HOME}/julea/slurm__StarParticle_StarParticleSingleTest_TestStarParticleSingleenzo.sqlite"
export J_TIMER_DB="${HOME}/julea/slurm__StarParticle_StarParticleSingleTest_TestStarParticleSingleenzo.sqlite"
#export G_MESSAGES_DEBUG=all

cat ${HOME}/.config/julea/julea-$(hostname)

${HOME}/julea/build-hdf-julea/server/julea-server &

sleep 1s

cp -r ${HOME}/enzo-dev/run/./StarParticle/StarParticleSingleTest/* $tmpdir
cd $tmpdir
echo $PWD
ls -la

rm $J_TIMER_DB

cat ${HOME}/enzo-dev/run/./StarParticle/StarParticleSingleTest/TestStarParticleSingle.enzo | grep -v "ResubmitOn" | grep -v "StopCPUTime" | grep -v "ResubmitCommand" > ${HOME}/enzo-dev/run/./StarParticle/StarParticleSingleTest/TestStarParticleSingle.enzo.tmp
echo "ResubmitOn = 1" >> ${HOME}/enzo-dev/run/./StarParticle/StarParticleSingleTest/TestStarParticleSingle.enzo.tmp
echo "StopCPUTime = 1" >> ${HOME}/enzo-dev/run/./StarParticle/StarParticleSingleTest/TestStarParticleSingle.enzo.tmp
echo "ResubmitCommand = ${HOME}/julea/enzo-all/run-continue.sh" >> ${HOME}/enzo-dev/run/./StarParticle/StarParticleSingleTest/TestStarParticleSingle.enzo.tmp


time ${HOME}/enzo-dev/src/enzo/enzo.exe ${HOME}/enzo-dev/run/./StarParticle/StarParticleSingleTest/TestStarParticleSingle.enzo.tmp

du -sh *
du -sh .