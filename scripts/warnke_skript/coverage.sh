cp -r build afl/cov
cd afl
lcov --capture --directory cov --base-directory .. --output-file cov/test.info
cd cov
lcov -a initial.info -a test.info -o coverage.info
genhtml coverage.info --output-directory html
cd ../..
mkdir afl/out/merged afl/out/corpus
for f in $(ls afl/out/*/queue/*)
do
        g=$(echo $f | sed "s_/_,_g")
        cp $f afl/out/merged/$g
done
afl-cmin -m none -i afl/out/merged -o afl/out/corpus ./afl/julea-test-afl
