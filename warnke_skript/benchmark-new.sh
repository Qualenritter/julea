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


echo "core" > /proc/sys/kernel/core_pattern
ulimit -c unlimited
#export LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libSegFault.so"
#export J_TRACE="combined"
#export G_MESSAGES_DEBUG=all

mountpoint=/mnt2
export J_BENCHMARK_SCALE=10

rm -rf build* prefix*
./warnke_skript/kill.sh

./waf.sh configure --out build-gcc-benchmark --prefix=prefix-gcc-benchmark --libdir=prefix-gcc-benchmark --bindir=prefix-gcc-benchmark --destdir=prefix-gcc-benchmark  --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
./waf.sh build
./waf.sh install
thepath=$(pwd)
mkdir -p log
rm -rf ${mountpoint}/julea/*
export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=~/.config/julea/julea-benchmark


./build-gcc-benchmark/tools/julea-config --user \
	  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
	  --db-servers="$(hostname)" \
	  --object-backend=posix --object-component=server --object-path=${mountpoint}/julea/object-benchmark \
	  --kv-backend=sqlite --kv-component=server --kv-path=${mountpoint}/julea/kv-benchmark \
	  --db-backend=sqlite --db-component=server --db-path=${mountpoint}/julea/db-benchmark

mv ~/.config/julea/julea ~/.config/julea/julea-benchmark
githash=$(git log --pretty=format:'%H' -n 1)

./warnke_skript/reset_mysql.sh ${mountpoint}/julea/mysql
./build-gcc-benchmark/server/julea-server >> server_log &
server_pid=$!

sleep 2

rm -rf benchmark_values/warnke-${githash}
mkdir -p benchmark_values/warnke-${githash}
cd benchmark_values/warnke-${githash}
export J_BENCHMARK_TARGET=30

../../example/benchmark-mpi >> benchmark_values
kill ${server_pid}
