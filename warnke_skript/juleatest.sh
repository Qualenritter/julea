#!/bin/bash
./warnke_skript/kill.sh
rm -rf build
./waf.sh configure --debug --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
./waf.sh build
./waf.sh install
basepath="/mnt2/juleatest"

function exec_tests()
{
db_backend=$1
db_component=$2
echo ${db_backend} ${db_component}
julea-config --user \
	--object-servers="$(hostname)" --kv-servers="$(hostname)" --db-servers="$(hostname)" \
	--object-backend=posix --object-component=server --object-path=${basepath}/object \
	--kv-backend=sqlite --kv-component=server --kv-path=${basepath}/kv \
	--db-backend=${db_backend} --db-component=${db_component} --db-path=${basepath}/db
rm -rf ${basepath}
mkdir -p ${basepath}
(
	export ASAN_OPTIONS=fast_unwind_on_malloc=0
	export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
	export G_MESSAGES_DEBUG=all
	export G_SLICE=always-malloc
	./warnke_skript/reset_mysql.sh
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
	./warnke_skript/reset_mysql.sh
	./scripts/test.sh
)
}

exec_tests mysql client
exec_tests sqlite server
