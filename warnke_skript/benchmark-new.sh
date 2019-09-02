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
export J_BENCHMARK_TARGET_LOW=0.01
export J_BENCHMARK_TARGET_HIGH=0.02

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
./build-gcc-benchmark/server/julea-server >> server_log &
server_pid=$!

sleep 2

(
	cd example
	make clean
	make
)

cd benchmark_values/warnke-${githash}

mpirun --allow-run-as-root -np ${process_count} \
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --error-exitcode=1 --track-origins=yes \
	--suppressions=/usr/share/openmpi/openmpi-valgrind.supp \
	--suppressions=/src/julea/example/openmpi.supp \
	--suppressions=/src/julea/dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/glib-2.56.3-z5nre6mqm5ofqploxeigak3xiuvp7mph/share/glib-2.0/valgrind/glib.supp \
	--gen-suppressions=all \
	../../example/benchmark-mpi >> benchmark_values_${pretty_backend_name}_${mountmedium}_${process_count} 2>&1
kill ${server_pid}
)
}

exec_tests mysql  client /mnt2 mem mysql 1
exec_tests sqlite server /mnt2 mem sqlite 1
exec_tests mysql  client /mnt2 mem mysql 6
exec_tests sqlite server /mnt2 mem sqlite 6
exec_tests mysql  client /mnt  hdd mysql 1
exec_tests sqlite server /mnt  hdd sqlite 1
exec_tests mysql  client /mnt  hdd mysql 6
exec_tests sqlite server /mnt  hdd sqlite 6

