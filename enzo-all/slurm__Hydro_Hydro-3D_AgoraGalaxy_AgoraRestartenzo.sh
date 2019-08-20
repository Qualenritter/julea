#!/bin/bash
#SBATCH -J enzo
#SBATCH --partition=west
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --time=01:30:00

thepath=${PWD}
name=slurm__Hydro_Hydro-3D_AgoraGalaxy_AgoraRestartenzo
builddir="hdf-julea"
tmpdir=/dev/shm/warnke/julea

rm -rf $tmpdir
mkdir -p $tmpdir

echo $tmpdir
echo $thepath
echo $name
echo $builddir

${thepath}/build-${builddir}/tools/julea-config --user   --object-servers="$(hostname)" --kv-servers="$(hostname)"   --db-servers="$(hostname)"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"

mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-${name}

cat ${HOME}/.config/julea/julea-${name}

export LD_LIBRARY_PATH=${thepath}/prefix-${builddir}/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-${name}
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-hdf-julea/lib
export LD_PRELOAD="$(locate libSegFault.so | tail -n 1)"
export SEGFAULT_SIGNALS="all"
export J_TIMER_DB="${HOME}/julea/slurm__Hydro_Hydro-3D_AgoraGalaxy_AgoraRestartenzo.sqlite"

sleep 0.5s

./build-hdf-julea/server/julea-server &

sleep 0.5s

cp -r ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/AgoraGalaxy/* $tmpdir
cd $tmpdir
echo $PWD
ls -la
time ${HOME}/enzo-dev/src/enzo/enzo.exe -d ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/AgoraGalaxy/AgoraRestart.enzo
du -sh *
du -sh .
