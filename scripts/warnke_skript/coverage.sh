cp -r build afl/cov
rm afl/cov/*.info
for f in $(find afl/cov/ -maxdepth 1 -type d)
do
	if [ "$f" == "fuzzer1" ]
	then
		lcov --capture --directory $f --base-directory . --output-file ${f}.info
	elif [ "$f" == "fuzzer2" ]
	then
	lcov --capture --directory $f --base-directory . --output-file ${f}.info
	elif [ "$f" == "fuzzer3" ]
	then
	lcov --capture --directory $f --base-directory . --output-file ${f}.info
	else
	lcov --capture --directory $f --base-directory . --gcov-tool ./scripts/warnke_skript/llvm-gcov.sh --output-file ${f}.info
	fi
done
cd afl/cov
lcov \
	-a build-gcc-gcov.info \
	-a build-gcc-gcov-debug-asan.info \
	-a build-clang-gcov.info \
	-a build-clang-gcov-debug.info \
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
	-a fuzzer12.info \
	-a server0.info \
	-a server.info \
	-o coverage.info
genhtml coverage.info --output-directory html
echo "finished code coverage"
cd ../..

rm -rf afl/out/corpus afl/out/merged
mkdir afl/out/merged afl/out/corpus test-afl/bin

#cp afl/start-files/* afl/out/merged/
#for f in $(ls afl/out/*/queue/*)
#do
#        g=$(echo $f | sed "s_/_,_g")
#        cp $f afl/out/merged/$g
#done
#afl-cmin -e -m none -i afl/out/merged -o afl/out/corpus ./afl/julea-test-afl

i=$(ls -l test-afl/bin | wc -l)
for f in $(find afl/out/cov/diff -type f)
do
	cp $f test-afl/bin/$i.bin
	i=$(($i + 1))
done
