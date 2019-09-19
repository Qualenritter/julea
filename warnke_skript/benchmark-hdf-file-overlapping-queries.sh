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


echo "core-%e-%p-%s" > /proc/sys/kernel/core_pattern
ulimit -c unlimited

#debugging-->>

#export G_MESSAGES_DEBUG=all
#export ASAN_OPTIONS=fast_unwind_on_malloc=0
#export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
#export G_SLICE=always-malloc

#<<--debugging

#export J_TRACE="combined"
export J_BENCHMARK_TARGET_LOW=10
export J_BENCHMARK_TARGET_HIGH=60

githash=$(git log --pretty=format:'%H' -n 1)
rm -rf benchmark_values/warnke-${githash}
mkdir -p benchmark_values/warnke-${githash}

rm -rf build* prefix*
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-gcc-benchmark/lib
./waf.sh configure --out build-gcc-benchmark --prefix=prefix-gcc-benchmark --libdir=prefix-gcc-benchmark --bindir=prefix-gcc-benchmark --destdir=prefix-gcc-benchmark  --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
./waf.sh build
./waf.sh install
. ./scripts/environment.sh
(
	cd example
	make clean
	make
)

function exec_tests()
{
db_backend=$1
db_component=$2
mountpoint=$3
mountmedium=$4
pretty_backend_name=$5

(
./warnke_skript/kill.sh

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
	  --db-backend=${db_backend} --db-component=${db_component} --db-path=${mountpoint}/julea/db-benchmark

mv ~/.config/julea/julea ~/.config/julea/julea-benchmark

./warnke_skript/reset_mysql.sh ${mountpoint}/julea/mysql

./build-gcc-benchmark/server/julea-server >> server_log &
server_pid=$!

sleep 2

mypwd=$(pwd)
cd ${mountpoint}/julea/
${mypwd}/example/benchmark-hdf >> ${mypwd}/benchmark_values/warnke-${githash}/benchmark_values_${pretty_backend_name}_${mountmedium} 2>&1
kill ${server_pid}
)
}

exec_tests mysql  client /mnt2 mem mysql
exec_tests sqlite server /mnt2 mem sqlite
exec_tests mysql  client /mnt  hdd mysql
exec_tests sqlite server /mnt  hdd sqlite
