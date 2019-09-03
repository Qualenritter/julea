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

function exec_tests()
{
db_backend=$1
db_component=$2
mountpoint=$3
mountmedium=$4
pretty_backend_name=$5
process_count=$6

(
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
	  --db-backend=${db_backend} --db-component=${db_component} --db-path=${mountpoint}/julea/db-benchmark

mv ~/.config/julea/julea ~/.config/julea/julea-benchmark

./warnke_skript/reset_mysql.sh ${mountpoint}/julea/mysql

#mysql --user='root' --password='1234' -e "SET GLOBAL log_output = 'TABLE';"
#mysql --user='root' --password='1234' -e "SET GLOBAL general_log = 'ON';"

./build-gcc-benchmark/server/julea-server >> server_log &
server_pid=$!

sleep 2

(
	cd example
	make clean
	make
)

cd benchmark_values/warnke-${githash}

mpirun --allow-run-as-root -np ${process_count} ../../example/benchmark-mpi >> benchmark_values_${pretty_backend_name}_${mountmedium}_${process_count} 2>&1
kill ${server_pid}
)
}

exec_tests mysql  client /mnt2 mem mysql 6
exec_tests sqlite server /mnt2 mem sqlite 6
exec_tests mysql  client /mnt2 mem mysql 1
exec_tests sqlite server /mnt2 mem sqlite 1
exec_tests mysql  client /mnt  hdd mysql 6
exec_tests sqlite server /mnt  hdd sqlite 6
exec_tests mysql  client /mnt  hdd mysql 1
exec_tests sqlite server /mnt  hdd sqlite 1
#mysql --user='root' --password='1234' -e "SET GLOBAL general_log = 'OFF';"
#mysql --user='root' --password='1234' -e "select * from mysql.general_log;"
