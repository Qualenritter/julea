#!/bin/bash
echo "core-%e-%p-%s" > /proc/sys/kernel/core_pattern
ulimit -c unlimited
./warnke_skript/kill.sh
rm -rf build log
mkdir -p log
./waf.sh configure --debug
#./waf.sh configure --debug --hdf=./dependencies/opt/spack/linux-ubuntu19.10-skylake/gcc-9.2.1/hdf5-develop-74x32jyjg556bshs4gbayh5uis3hg37c/
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

export ASAN_OPTIONS=fast_unwind_on_malloc=0
export G_DEBUG=fatal-warnings,resident-modules,gc-friendly
export G_SLICE=always-malloc

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
	export G_MESSAGES_DEBUG=all
	rm -rf ${basepath}
	mkdir -p ${basepath}
	./warnke_skript/reset_mysql.sh ${basepath}/dbmysql
	echo "./build/test/julea-test"
	./build/server/julea-server &
	server_pid=$!
	sleep 1s
#	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --error-exitcode=1 --track-origins=yes  \
#		--suppressions=./dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/glib-2.56.3-z5nre6mqm5ofqploxeigak3xiuvp7mph/share/glib-2.0/valgrind/glib.supp \
	./build/test/julea-test
	echo "kill ${server_pid}"
	kill -9 ${server_pid}
	mkdir -p log/julea-test-${db_backend}-${db_component}.core
	mv core* log/julea-test-${db_backend}-${db_component}.core
) &> log/julea-test-${db_backend}-${db_component}.log
(
	export G_MESSAGES_DEBUG=
	rm -rf ${basepath}
	mkdir -p ${basepath}
	./warnke_skript/reset_mysql.sh ${basepath}/dbmysql
	echo "./scripts/test.sh"
	./scripts/test.sh
	mkdir -p log/test-script-${db_backend}-${db_component}.core
	mv core* log/test-script-${db_backend}-${db_component}.core
) &> log/test-script-${db_backend}-${db_component}.log
}

exec_tests mysql client
exec_tests sqlite server
find log -type d -empty -delete
