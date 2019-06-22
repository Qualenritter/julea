cp -r build afl/cov
cd afl
lcov --capture --directory cov --base-directory .. --output-file cov/test.info
cd cov
lcov -a initial.info -a test.info -o coverage.info
genhtml coverage.info --output-directory html
echo "finished code coverage"
cd ../..
rm -rf test-afl/bin afl/out/corpus
mkdir afl/out/merged afl/out/corpus test-afl/bin

#cp afl/start-files/* afl/out/merged/
#for f in $(ls afl/out/*/queue/*)
#do
#        g=$(echo $f | sed "s_/_,_g")
#        cp $f afl/out/merged/$g
#done
#afl-cmin -e -m none -i afl/out/merged -o afl/out/corpus ./afl/julea-test-afl

i=0
for f in $(find afl/out/cov/diff -type f)
do
	cp $f test-afl/bin/$i.bin
	i=$(($i + 1))
done
