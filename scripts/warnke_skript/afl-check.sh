files=""
files="${files} $(ls afl/out/*/crashes/* | grep -v README )"
files="${files} $(ls afl/start-files/* | grep -v README )"
./scripts/warnke_skript/format.sh
rm -rf /mnt2/julea/* b
mkdir b
(export AFL_USE_ASAN=1; export ASAN_OPTIONS=abort_on_error=1,symbolize=0; ./waf configure --debug --out build-gcc-asan --prefix=prefix-gcc-asan --libdir=prefix-gcc-asan --bindir=prefix-gcc-asan --destdir=prefix-gcc-asan&& ./waf.sh build && ./waf.sh install)
i=300
(export LD_LIBRARY_PATH=prefix-clang/lib/:$LD_LIBRARY_PATH; ./build-clang/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=client --object-path="/mnt2/julea/object${i}" \
  --kv-backend=sqlite --kv-component=client --kv-path="/mnt2/julea/kv${i}" \
  --smd-backend=sqlite --smd-component=client --smd-path=":memory:")
mv ~/.config/julea/julea ~/.config/julea/julea${i}


for g in gcc-asan gcc-gcov-debug-asan clang-gcov-debug clang gcc-gcov
do
echo "using binary : $g"
mkdir b/${g}
for f in ${files}
do

	(export G_DEBUG=resident-modules; export G_MESSAGES_DEBUG=all; export LD_LIBRARY_PATH=prefix-${g}/lib/:$LD_LIBRARY_PATH; export JULEA_CONFIG=~/.config/julea/julea${i}; export ASAN_OPTIONS=fast_unwind_on_malloc=0; cat $f | valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --error-exitcode=1 --track-origins=yes --suppressions=./dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/glib-2.56.3-y4kalfnkzahoclmqcqcpwvxzw4nepwsi/share/glib-2.0/valgrind/glib.supp ./build-${g}/test-afl/julea-test-afl > x 2>&1)
#	(export G_DEBUG=resident-modules; export G_MESSAGES_DEBUG=all; export LD_LIBRARY_PATH=prefix-${g}/lib/:$LD_LIBRARY_PATH; export JULEA_CONFIG=~/.config/julea/julea${i}; export ASAN_OPTIONS=fast_unwind_on_malloc=0; cat $f | ./build-${g}/test-afl/julea-test-afl > x 2>&1)
	r=$?
	if [ $r -eq 0 ]; then
		echo "invalid $f $g"
	else
		echo "valid $f $g"
		cp $f b/${g}/
		exit 1
	fi
done
done

exit

(export LD_LIBRARY_PATH=prefix-clang/lib/:$LD_LIBRARY_PATH; ./build-clang/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=server --object-path="/mnt2/julea/object${i}" \
  --kv-backend=sqlite --kv-component=server --kv-path="/mnt2/julea/kv${i}" \
  --smd-backend=sqlite --smd-component=server --smd-path=":memory:")
mv ~/.config/julea/julea ~/.config/julea/julea${i}

for g in gcc-gcov-debug-asan clang-gcov-debug clang gcc-gcov
do
	echo "using binary with server mode: $g"
rm -rf /mnt2/julea/*
for f in ${files}
do
	./scripts/warnke_skript/kill.sh
	sleep 0.1s
	(export G_DEBUG=resident-modules; export G_MESSAGES_DEBUG=all; export LD_LIBRARY_PATH=prefix-${g}/lib/:$LD_LIBRARY_PATH; export JULEA_CONFIG=~/.config/julea/julea${i}; export ASAN_OPTIONS=fast_unwind_on_malloc=0;  ./build-$g/server/julea-server) &
	sleep 0.1s
	(export G_DEBUG=resident-modules; export G_MESSAGES_DEBUG=all; export LD_LIBRARY_PATH=prefix-${g}/lib/:$LD_LIBRARY_PATH; export JULEA_CONFIG=~/.config/julea/julea${i}; export ASAN_OPTIONS=fast_unwind_on_malloc=0; cat $f | ./build-${g}/test-afl/julea-test-afl > x 2>&1)
	r=$?
	if [ $r -eq 0 ]; then
		echo "invalid $f $g"
	else
		echo "valid $f $g"
		cp $f b/${g}/
		exit 1
	fi
done
done
