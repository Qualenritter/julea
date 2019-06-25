files=$(ls afl/start-files/* | grep -v README )
files="${files} $(ls afl/out/*/crashes/* | grep -v README )"
rm -rf b
mkdir b

i=300
(export LD_LIBRARY_PATH=prefix-clang/lib/:$LD_LIBRARY_PATH; ./build-clang/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=client --object-path="/mnt2/julea/object${i}" \
  --kv-backend=sqlite --kv-component=client --kv-path="/mnt2/julea/kv${i}" \
  --smd-backend=sqlite --smd-component=client --smd-path=":memory:")
mv ~/.config/julea/julea ~/.config/julea/julea${i}


for g in gcc-gcov-debug-asan clang gcc-gcov
do
mkdir b/${g}
for f in ${files}
do
	(export export G_DEBUG=resident-modules; export G_MESSAGES_DEBUG=all; export LD_LIBRARY_PATH=prefix-${g}/lib/:$LD_LIBRARY_PATH; export JULEA_CONFIG=~/.config/julea/julea${i}; export AFL_USE_ASAN=1; export ASAN_OPTIONS=fast_unwind_on_malloc=0,abort_on_error=1,symbolize=0; cat $f | ./build-${g}/test-afl/julea-test-afl > x 2>&1)
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
