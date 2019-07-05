#!/bin/bash
cc_prefix=$1
afl_path="afl${first_index}"
tmp_path="/mnt2/julea"
log_path="log"
rm -rf prefix* build* ~/.config/julea/* log ${tmp_path}/*
./scripts/warnke_skript/kill.sh
./scripts/warnke_skript/format.sh
mkdir -p ${log_path}
function julea_compile(){
	(
		compiler=$1
		flags=$2
		asan=$3
		hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
		name=$(echo "${compiler}-${flags}" | sed "s/ /-/g" | sed "s/--/-/g" | sed "s/--/-/g")
		export CC=${cc_prefix}${compiler}
echo $CC
		if [ "${asan}" = "asan" ]; then
			export AFL_USE_ASAN=1
			export ASAN_OPTIONS=abort_on_error=1,symbolize=0
			flags="${flags} --debug"
		name="${name}-asan"
		fi
		./waf configure ${flags} --out build-${name} --prefix=prefix-${name} --libdir=prefix-${name} --bindir=prefix-${name} --destdir=prefix-${name} --hdf=${hdf}
		./waf.sh build -j12
		./waf.sh install -j12
		rc=$?; if [[ $rc != 0 ]]; then echo "compile build-${name} failed";exit $rc; fi
		lcov --zerocounters -d "build-${name}"
		mkdir -p ${afl_path}/cov
		lcov -c -i -d "build-${name}" -o "${afl_path}/cov/build-${name}.info"
	)
}

julea_compile "afl-gcc" "--gcov" "" > ${log_path}/compile1 2>&1
julea_compile "afl-gcc" "--gcov --debug" "" > ${log_path}/compile2 2>&1
julea_compile "afl-gcc" "" "asan" > ${log_path}/compile3 2>&1
julea_compile "afl-gcc" "--gcov --testmockup" "" > ${log_path}/compile4 2>&1
julea_compile "afl-gcc" "--gcov --testmockup --debug" "" > ${log_path}/compile5 2>&1
julea_compile "afl-clang-fast" "" "" > ${log_path}/compile6 2>&1
julea_compile "afl-clang-fast" "--debug" "" > ${log_path}/compile7 2>&1
julea_compile "afl-clang-fast" "--testmockup" "" > ${log_path}/compile8 2>&1
julea_compile "afl-clang-fast" "--testmockup --debug" "" > ${log_path}/compile9 2>&1

