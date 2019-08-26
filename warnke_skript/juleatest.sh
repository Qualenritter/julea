#!/bin/bash
./warnke_skript/kill.sh
rm -rf build
./waf.sh configure --debug --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
./waf.sh build
./waf.sh install
basepath="/mnt2/juleatest"
for db_backend in mysql sqlite
do
julea-config --user \
	--object-servers="$(hostname)" --kv-servers="$(hostname)" --db-servers="$(hostname)" \
	--object-backend=posix --object-component=server --object-path=${basepath}/object \
	--kv-backend=sqlite --kv-component=server --kv-path=${basepath}/kv \
	--db-backend=${db_backend} --db-component=client --db-path=${basepath}/db
rm -rf ${basepath}
mkdir -p ${basepath}
(
	export ASAN_OPTIONS=fast_unwind_on_malloc=0
	export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
	export G_MESSAGES_DEBUG=all
	export G_SLICE=always-malloc
	./build/server/julea-server &
	server_pid=$!
	sleep 0.5s
	gdb ./build/test/julea-test
	echo "kill ${server_pid}"
	kill -9 ${server_pid}
)
rm -rf ${basepath}
mkdir -p ${basepath}
(
	export ASAN_OPTIONS=fast_unwind_on_malloc=0
	export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
	export G_MESSAGES_DEBUG=
	export G_SLICE=always-malloc
	./scripts/test.sh
)
done
