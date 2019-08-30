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

githash=$(git log --pretty=format:'%H' -n 1)
rm -rf benchmark_values/warnke-${githash}
mkdir -p benchmark_values/warnke-${githash}
mkdir -p log
rm -rf build* prefix*
./warnke_skript/kill.sh
./waf.sh configure --out build-gcc-benchmark --prefix=prefix-gcc-benchmark --libdir=prefix-gcc-benchmark --bindir=prefix-gcc-benchmark --destdir=prefix-gcc-benchmark  --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
./waf.sh build
./waf.sh install
thepath=$(pwd)
export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark/lib/:$LD_LIBRARY_PATH
export J_BENCHMARK_TARGET=20

function exec_tests()
{
db_backend=$1
db_component=$2
use_vol=$3
mountpoint=$4
mountmedium=$5
pretty_backend_name=$6

(
rm -rf ${mountpoint}/julea/*

export J_BENCHMARK_VOL=${use_vol}
export JULEA_CONFIG=~/.config/julea/julea-benchmark
#export J_TRACE="combined"

./build-gcc-benchmark/tools/julea-config --user \
	  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
	  --db-servers="$(hostname)" \
	  --object-backend=posix --object-component=server --object-path=${mountpoint}/julea/object-benchmark \
	  --kv-backend=sqlite --kv-component=server --kv-path=${mountpoint}/julea/kv-benchmark \
	  --db-backend=${db_backend} --db-component=${db_component} --db-path=${mountpoint}/julea/db-benchmark

mv ~/.config/julea/julea ${JULEA_CONFIG}

./warnke_skript/reset_mysql.sh ${mountpoint}/julea/mysql
./build-gcc-benchmark/server/julea-server >> server_log 2>&1 &
server_pid=$!
sleep 0.1s
cd benchmark_values/warnke-${githash}
../../build-gcc-benchmark/benchmark/julea-benchmark >> benchmark_values_${pretty_backend_name}_${mountmedium} 2>&1
kill ${server_pid}
)
}

exec_tests mysql  client 1 /mnt2 mem mysql
#exec_tests sqlite server 1 /mnt2 mem sqlite
#exec_tests sqlite server 0 /mnt2 mem native
exec_tests mysql  client 1 /mnt  hdd mysql
#exec_tests sqlite server 1 /mnt  hdd sqlite
#exec_tests sqlite server 0 /mnt  hdd native
