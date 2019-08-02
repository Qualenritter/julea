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

umount /mnt2
mount /mnt2
rm -rf build* prefix*
./warnke_skript/kill.sh
./warnke_skript/format.sh
./waf.sh configure --out build-gcc-benchmark --prefix=prefix-gcc-benchmark --libdir=prefix-gcc-benchmark --bindir=prefix-gcc-benchmark --destdir=prefix-gcc-benchmark && ./waf.sh build && ./waf.sh install
./waf.sh configure --debug --out build-gcc-benchmark-debug --prefix=prefix-gcc-benchmark-debug --libdir=prefix-gcc-benchmark-debug --bindir=prefix-gcc-benchmark-debug --destdir=prefix-gcc-benchmark-debug && ./waf.sh build && ./waf.sh install
./waf.sh configure --testmockup --debug --out build-gcc-benchmark-mock --prefix=prefix-gcc-benchmark-mock --libdir=prefix-gcc-benchmark-mock --bindir=prefix-gcc-benchmark-mock --destdir=prefix-gcc-benchmark-mock && ./waf.sh build && ./waf.sh install
thepath=$(pwd)
mkdir -p log
rm -rf /mnt2/julea/*
(
	export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark/lib/:$LD_LIBRARY_PATH
	export JULEA_CONFIG=~/.config/julea/julea-benchmark
	export J_TRACE=debug
	./build-gcc-benchmark/tools/julea-config --user \
		  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
		  --db-servers="$(hostname)" \
		  --object-backend=posix --object-component=client --object-path=/mnt2/julea/object-benchmark \
		  --kv-backend=sqlite --kv-component=client --kv-path=/mnt2/julea/kv-benchmark \
		  --db-backend=sqlite --db-component=client --db-path=memory
)
mv ~/.config/julea/julea ~/.config/julea/julea-benchmark
githash=$(git log --pretty=format:'%H' -n 1)
(
	rm -rf benchmark_values/warnke-${githash}
	mkdir -p benchmark_values/warnke-${githash}
	cd benchmark_values/warnke-${githash}
	export LD_LIBRARY_PATH=${thepath}/prefix-gcc-benchmark/lib/:$LD_LIBRARY_PATH
	export JULEA_CONFIG=~/.config/julea/julea-benchmark
	export J_BENCHMARK_TARGET=1
	export J_TRACE=sqltimer
	../../build-gcc-benchmark/benchmark/julea-benchmark >> benchmark_values
	./warnke_skript/kill.sh
)
wait
./warnke_skript/kill.sh
