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

mountpoint=/mnt
export J_BENCHMARK_SCALE=100

rm -rf build* prefix*
./warnke_skript/kill.sh
./warnke_skript/format.sh
./waf.sh configure --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf) --out build-gcc-benchmark --prefix=prefix-gcc-benchmark --libdir=prefix-gcc-benchmark --bindir=prefix-gcc-benchmark --destdir=prefix-gcc-benchmark && ./waf.sh build && ./waf.sh install
./waf.sh configure --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf) --debug --out build-gcc-benchmark-debug --prefix=prefix-gcc-benchmark-debug --libdir=prefix-gcc-benchmark-debug --bindir=prefix-gcc-benchmark-debug --destdir=prefix-gcc-benchmark-debug && ./waf.sh build && ./waf.sh install
./waf.sh configure --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf) --testmockup --debug --out build-gcc-benchmark-mock --prefix=prefix-gcc-benchmark-mock --libdir=prefix-gcc-benchmark-mock --bindir=prefix-gcc-benchmark-mock --destdir=prefix-gcc-benchmark-mock && ./waf.sh build && ./waf.sh install
thepath=$(pwd)
mkdir -p log
rm -rf ${mountpoint}/julea/*
(
	export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark/lib/:$LD_LIBRARY_PATH
	export JULEA_CONFIG=~/.config/julea/julea-benchmark
	./build-gcc-benchmark/tools/julea-config --user \
		  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
		  --db-servers="$(hostname)" \
		  --object-backend=posix --object-component=server --object-path=${mountpoint}/julea/object-benchmark \
		  --kv-backend=sqlite --kv-component=server --kv-path=${mountpoint}/julea/kv-benchmark \
		  --db-backend=mysql --db-component=client --db-path=${mountpoint}/julea/db-benchmark
)
mv ~/.config/julea/julea ~/.config/julea/julea-benchmark
(
	export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark/lib/:$LD_LIBRARY_PATH
	export JULEA_CONFIG=~/.config/julea/julea-benchmark
	./build-gcc-benchmark/tools/julea-config --user \
		  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
		  --db-servers="$(hostname)" \
		  --object-backend=posix --object-component=client --object-path=${mountpoint}/julea/object-benchmark \
		  --kv-backend=sqlite --kv-component=client --kv-path=${mountpoint}/julea/kv-benchmark \
		  --db-backend=mysql --db-component=client --db-path=:memory:
)
mv ~/.config/julea/julea ~/.config/julea/julea-benchmark-debug
githash=$(git log --pretty=format:'%H' -n 1)
(
	export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark/lib/:$LD_LIBRARY_PATH
	export JULEA_CONFIG=~/.config/julea/julea-benchmark
	./build-gcc-benchmark/server/julea-server
)&
server_pid=$!
sleep 2
(
	rm -rf benchmark_values/debug
	mkdir -p benchmark_values/debug
	cd benchmark_values/debug
	export G_MESSAGES_DEBUG=all
	export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
	export G_SLICE=always-malloc
	export ASAN_OPTIONS=fast_unwind_on_malloc=0
	export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark-debug/lib/:$LD_LIBRARY_PATH
	export JULEA_CONFIG=~/.config/julea/julea-benchmark-debug
	export J_BENCHMARK_TARGET=0.001
	../../warnke_skript/reset_mysql.sh
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --error-exitcode=1 --track-origins=yes \
		--suppressions=../../dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/glib-2.56.3-z5nre6mqm5ofqploxeigak3xiuvp7mph/share/glib-2.0/valgrind/glib.supp \
		../../build-gcc-benchmark-debug/benchmark/julea-benchmark > ../../log/x1 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		exit 1
	fi
)
r=$?
if [ $r -ne 0 ]; then
	exit 1
fi
sleep 2
(
	rm -rf benchmark_values/debug
	mkdir -p benchmark_values/debug
	cd benchmark_values/debug
	export G_MESSAGES_DEBUG=all
	export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
	export G_SLICE=always-malloc
	export ASAN_OPTIONS=fast_unwind_on_malloc=0
	export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark-mock/lib/:$LD_LIBRARY_PATH
	export JULEA_CONFIG=~/.config/julea/julea-benchmark-debug
	export J_BENCHMARK_TARGET=0.001
	../../warnke_skript/reset_mysql.sh
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --error-exitcode=1 --track-origins=yes \
		--suppressions=../../dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/glib-2.56.3-z5nre6mqm5ofqploxeigak3xiuvp7mph/share/glib-2.0/valgrind/glib.supp \
		../../build-gcc-benchmark-mock/benchmark/julea-benchmark > ../../log/x2 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		exit 1
	fi
)
r=$?
if [ $r -ne 0 ]; then
	exit 1
fi
sleep 2
(
	rm -rf benchmark_values/debug
	mkdir -p benchmark_values/debug
	cd benchmark_values/debug
	export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark-debug/lib/:$LD_LIBRARY_PATH
	export JULEA_CONFIG=~/.config/julea/julea-benchmark
	export J_BENCHMARK_TARGET=0.001
	../../warnke_skript/reset_mysql.sh
	../../build-gcc-benchmark-debug/benchmark/julea-benchmark > ../../log/x3
)
sleep 2
(
	rm -rf benchmark_values/warnke-${githash}
	mkdir -p benchmark_values/warnke-${githash}
	cd benchmark_values/warnke-${githash}
	export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark/lib/:$LD_LIBRARY_PATH
	export JULEA_CONFIG=~/.config/julea/julea-benchmark
	export J_BENCHMARK_TARGET=30;
	../../warnke_skript/reset_mysql.sh
	../../build-gcc-benchmark/benchmark/julea-benchmark >> benchmark_values
	kill -9 ${server_pid}
)
wait
