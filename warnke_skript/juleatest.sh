#!/bin/bash
echo "core-%e-%p-%s" > /proc/sys/kernel/core_pattern
ulimit -c unlimited
./warnke_skript/kill.sh
rm -rf build log
mkdir -p log
./waf.sh configure --debug --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
./waf.sh build
rm -rf /usr/local/lib/libjulea*
rm -rf /usr/local/lib/julea
./waf.sh install
. ./scripts/environment.sh
(
	cat example/db-example-with-error-handling.c \
		| grep -v "success =\s(" \
		| sed "s/success = //g" \
		| grep -v "gboolean TRUE;" \
		| grep -v "success" \
		| grep -v "GError. error = NULL;" \
		| sed "s/, error);/, NULL);/g" \
		| sed "s/GError.. error/void/g" \
		| sed "s/&error//g" \
		> example/db-example.c
	cd example
	make clean
	make
)
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
(
	export ASAN_OPTIONS=fast_unwind_on_malloc=0
	export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
	export G_MESSAGES_DEBUG=all
	export G_SLICE=always-malloc
	rm -rf ${basepath}/db;mkdir -p ${basepath}/
	./warnke_skript/reset_mysql.sh ${basepath}/dbmysql
	./build/server/julea-server &
	server_pid=$!
	sleep 0.5s
	echo "./example/db-example-with-error-handling"
	./example/db-example-with-error-handling
	kill -9 ${server_pid}
	mkdir -p log/db-example-with-error-handling-${db_backend}-${db_component}.core
	mv core* log/db-example-with-error-handling-${db_backend}-${db_component}.core
) &> log/db-example-with-error-handling-${db_backend}-${db_component}.log
(
	export ASAN_OPTIONS=fast_unwind_on_malloc=0
	export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
	export G_MESSAGES_DEBUG=all
	export G_SLICE=always-malloc
	rm -rf ${basepath}/db;mkdir -p ${basepath}/
	./warnke_skript/reset_mysql.sh ${basepath}/dbmysql
	./build/server/julea-server &
	server_pid=$!
	sleep 0.5s
	echo "./build/test/julea-test"
#	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --error-exitcode=1 --track-origins=yes  \
#		--suppressions=./dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/glib-2.56.3-z5nre6mqm5ofqploxeigak3xiuvp7mph/share/glib-2.0/valgrind/glib.supp \
		./build/test/julea-test
	echo "kill ${server_pid}"
	kill -9 ${server_pid}
	mkdir -p log/julea-test-${db_backend}-${db_component}.core
	mv core* log/julea-test-${db_backend}-${db_component}.core
) &> log/julea-test-${db_backend}-${db_component}.log
rm -rf ${basepath}
mkdir -p ${basepath}
(
	export ASAN_OPTIONS=fast_unwind_on_malloc=0
	export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
	export G_MESSAGES_DEBUG=
	export G_SLICE=always-malloc
	rm -rf ${basepath}/db;mkdir -p ${basepath}/
	./warnke_skript/reset_mysql.sh ${basepath}/dbmysql
	echo "./scripts/test.sh"
	./scripts/test.sh
	mkdir -p log/test-script-${db_backend}-${db_component}.core
	mv core* log/test-script-${db_backend}-${db_component}.core
) &> log/test-script-${db_backend}-${db_component}.log
}

exec_tests sqlite client
exec_tests mysql client
exec_tests sqlite server
find log -type d -empty -delete
