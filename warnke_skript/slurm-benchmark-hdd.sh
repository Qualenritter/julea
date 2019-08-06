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

scale=100
tmpdir=$(mktemp -d)
thepath=$PWD
name="${hostname}-$(date +%d-%m-%y)"
builddir="gcc-benchmark"

#SBATCH -J ${name}
#SBATCH --output=${thepath}/benchmark_values/${name}-slurm.out
#SBATCH --partition=west
#SBATCH --ntasks=1
#SBATCH --nodes=1

${thepath}/build-${builddir}/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --db-servers="$(hostname)" \
  --object-backend=posix --object-component=client --object-path="${tmpdir}/client-object${i}" \
  --kv-backend=sqlite --kv-component=client --kv-path="${tmpdir}/client-kv${i}" \
  --db-backend=sqlite --db-component=client --db-path="${tmpdir}/client-db${i}"

mv ~/.config/julea/julea ~/.config/julea/julea-${name}

export LD_LIBRARY_PATH=${thepath}/prefix-${builddir}/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=~/.config/julea/julea-${name}
export J_BENCHMARK_SCALE=${scale}
export J_BENCHMARK_TARGET=30;

./build-gcc-benchmark/server/julea-server &
./build-gcc-benchmark/benchmark/julea-benchmark
