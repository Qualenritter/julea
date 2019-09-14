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

#./warnke_skript/format.sh
echo "core-%e-%p-%s" > /proc/sys/kernel/core_pattern
ulimit -c unlimited

mkdir -p log
rm -rf /mnt2/julea/* *.tmp-file
(export CC=gcc;   export AFL_USE_ASAN=1; export ASAN_OPTIONS=abort_on_error=1,symbolize=0; ./waf configure --coverage --debug --out build-gcc-asan --prefix=prefix-gcc-asan --libdir=prefix-gcc-asan --bindir=prefix-gcc-asan --destdir=prefix-gcc-asan&& ./waf.sh build && ./waf.sh install)
(export CC=gcc;   export AFL_USE_ASAN=1; export ASAN_OPTIONS=abort_on_error=1,symbolize=0; ./waf configure --coverage --debug --testmockup --out build-gcc-asan-mockup --prefix=prefix-gcc-asan-mockup --libdir=prefix-gcc-asan-mockup --bindir=prefix-gcc-asan-mockup --destdir=prefix-gcc-asan-mockup&& ./waf.sh build && ./waf.sh install)
(export CC=clang; export AFL_USE_ASAN=1; export ASAN_OPTIONS=abort_on_error=1,symbolize=0; ./waf configure --coverage --debug --out build-clang-asan --prefix=prefix-clang-asan --libdir=prefix-clang-asan --bindir=prefix-clang-asan --destdir=prefix-clang-asan&& ./waf.sh build && ./waf.sh install)
(export CC=clang; export AFL_USE_ASAN=1; export ASAN_OPTIONS=abort_on_error=1,symbolize=0; ./waf configure --coverage --debug --testmockup --out build-clang-asan-mockup --prefix=prefix-clang-asan-mockup --libdir=prefix-clang-asan-mockup --bindir=prefix-clang-asan-mockup --destdir=prefix-clang-asan-mockup&& ./waf.sh build && ./waf.sh install)
i=300
(export LD_LIBRARY_PATH=prefix-gcc-asan/lib/:$LD_LIBRARY_PATH; ./build-gcc-asan/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --db-servers="$(hostname)" \
  --object-backend=posix --object-component=client --object-path="/mnt2/julea/client-object${i}" \
  --kv-backend=sqlite --kv-component=client --kv-path="/mnt2/julea/client-kv${i}" \
  --db-backend=sqlite --db-component=client --db-path="/mnt2/julea/client-db${i}")
mv ~/.config/julea/julea ~/.config/julea/julea${i}
i=301
(export LD_LIBRARY_PATH=prefix-gcc-asan/lib/:$LD_LIBRARY_PATH; ./build-gcc-asan/tools/julea-config --user \
  --object-servers="$(hostname):13000" --kv-servers="$(hostname):13000" \
  --db-servers="$(hostname):13000" \
  --object-backend=posix --object-component=server --object-path="/mnt2/julea/server-object${i}" \
  --kv-backend=sqlite --kv-component=server --kv-path="/mnt2/julea/server-kv${i}" \
  --db-backend=sqlite --db-component=server --db-path="/mnt2/julea/server-db${i}")
mv ~/.config/julea/julea ~/.config/julea/julea${i}

j=0

while true
do
files="$(ls afl/out/*/crashes/* | grep -v README | shuf)"
for f in ${files}
do

for g in gcc-asan-mockup gcc-asan clang-asan-mockup clang-asan
do
for programname in "julea-test-afl-db-backend" "julea-test-afl-db-client"
do
for i in 300 301
do

if [ "$g" == "gcc-asan-mockup" ]; then
	if [ "$i" == "301" ]; then
		continue
	fi
fi

	rm -rf /mnt2/julea/*
	(
		echo ${programname} > log/x
		echo $g >> log/x
		echo $i >> log/x
		cat ~/.config/julea/julea${i} >> log/x
		export LD_LIBRARY_PATH=prefix-${g}/lib/:$LD_LIBRARY_PATH
		export JULEA_CONFIG=~/.config/julea/julea${i}
		export ASAN_OPTIONS=fast_unwind_on_malloc=0
		export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
		export G_MESSAGES_DEBUG=all
		export G_SLICE=always-malloc
		./build-gcc-asan/server/julea-server --port=13000 >> log/x 2>&1 &
		server_pid=$!
		cat $f \
			| valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --error-exitcode=1 --track-origins=yes  \
			--suppressions=./dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/glib-2.56.3-z5nre6mqm5ofqploxeigak3xiuvp7mph/share/glib-2.0/valgrind/glib.supp \
			--gen-suppressions=yes \
			./build-${g}/test-afl/${programname}
		r=$?
		kill -9 ${server_pid}
		exit $r
	)  >> log/x 2>&1
	r=$?
	if [ $r -eq 0 ]; then
		echo "invalid $f $g $i $programname"
		mv log/x log/$j-${programname}-$g-$i.tmp-file
	else
		echo "valid $f $g $i $programname"
		mv log/x log/$j-${programname}-$g-$i.crash-file
	fi
done
done
done
	mv $f log/$j.input-file
	j=$(($j + 1))
	break
done
done
