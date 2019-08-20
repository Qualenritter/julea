#!/bin/bash

# JULEA - Flexible storage framework
# Copyright (C) 2019 Benjamin Warnke
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#SBATCH -J benchmark
#SBATCH --partition=west
#SBATCH --ntasks=1
#SBATCH --nodes=1

scale=10
thepath=${PWD}
name="$(hostname)-$(date +%d-%m-%y-%H-%M-%S)"
builddir="hdf-julea"
tmpdir=$(mktemp -d)

rm -rf $tmpdir
mkdir -p $tmpdir

echo $scale
echo $tmpdir
echo $thepath
echo $name
echo $builddir

${thepath}/build-${builddir}/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --db-servers="$(hostname)" \
  --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object" \
  --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv" \
  --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"

mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-${name}

cat ${HOME}/.config/julea/julea-${name}

export LD_LIBRARY_PATH=${thepath}/prefix-${builddir}/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-${name}
export J_BENCHMARK_SCALE=${scale}
export J_BENCHMARK_TARGET=30;
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=/home/warnke/julea/prefix-hdf-julea/lib
export LD_PRELOAD="$(locate libSegFault.so | tail -n 1)"
export SEGFAULT_SIGNALS="all"
export J_TIMER_DB="/home/warnke/julea/slurm-enzo-hdd-julea.sqlite"

./build-hdf-julea/server/julea-server &
cp -r /home/warnke/enzo-dev/run/Hydro/Hydro-3D/CollapseTestNonCosmological/* $tmpdir
cd $tmpdir
echo $PWD
ls -la
time ./enzo.exe -d CollapseTestNonCosmological.enzo
