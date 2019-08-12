#!/bin/bash
./warnke_skript/kill.sh
rm -rf build
./waf.sh configure --debug --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
./waf.sh build
./waf.sh install
basepath="/mnt2/juleatest"
julea-config --user \
	--object-servers="$(hostname)" --kv-servers="$(hostname)" --db-servers="$(hostname)" \
	--object-backend=posix --object-component=server --object-path=${basepath}/posix \
	--kv-backend=sqlite --kv-component=server --kv-path=${basepath}/lmdb \
	--db-backend=sqlite --db-component=server --db-path=memory
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
	./build/test/julea-test
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
