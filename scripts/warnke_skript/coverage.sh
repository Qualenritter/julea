cp -r build afl/cov
rm afl/cov/*.info
for i in {0..11}
do
	lcov --capture --directory afl/cov/gcc/fuzzer$i --base-directory afl --output-file afl/cov/fuzzer$i.info
done
lcov --capture --directory afl/cov/gcc/server0 --base-directory afl --output-file afl/cov/server0.info
#for i in {12..22}
#do
#	lcov --capture --directory afl/cov/clang/fuzzer$i --base-directory afl --gcov-tool /src/julea/julea/scripts/warnke_skript/llvm-gcov.sh --output-file afl/cov/fuzzer$i.info
#done
lcov --zerocounters -d build-gcc-gcov && lcov -c -i -d build-gcc-gcov -o afl/cov/build-gcc-gcov.info
lcov --zerocounters -d build-gcc-gcov-debug-asan && lcov -c -i -d build-gcc-gcov-debug-asan -o afl/cov/build-gcc-gcov-debug-asan.info
#lcov --zerocounters -d build-clang-gcov && lcov -c -i -d build-clang-gcov -o afl/cov/build-clang-gcov.info
#lcov --zerocounters -d build-clang-gcov-debug && lcov -c -i -d build-clang-gcov-debug -o afl/cov/build-clang-gcov-debug.info
(cd afl/cov
lcov \
	-a build-gcc-gcov.info \
	-a build-gcc-gcov-debug-asan.info \
	-a fuzzer0.info \
	-a fuzzer1.info \
	-a fuzzer2.info \
	-a fuzzer3.info \
	-a fuzzer4.info \
	-a fuzzer5.info \
	-a fuzzer6.info \
	-a fuzzer7.info \
	-a fuzzer8.info \
	-a fuzzer9.info \
	-a fuzzer10.info \
	-a fuzzer11.info \
	-a server0.info \
	-o coverage.info
genhtml coverage.info --output-directory html)
echo "finished code coverage"

#rm -rf afl/out/corpus afl/out/merged
#mkdir afl/out/merged afl/out/corpus test-afl/bin

#cp afl/start-files/* afl/out/merged/
#for f in $(ls afl/out/*/queue/*)
#do
#        g=$(echo $f | sed "s_/_,_g")
#        cp $f afl/out/merged/$g
#done
#afl-cmin -e -m none -i afl/out/merged -o afl/out/corpus ./afl/julea-test-afl

#i=$(ls -l test-afl/bin | wc -l)
#for f in $(find afl/out/cov/diff -type f)
#do
#	cp $f test-afl/bin/$i.bin
#	i=$(($i + 1))
#done
