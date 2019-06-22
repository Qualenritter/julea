cp -r build afl/cov
cd afl
lcov --capture --directory cov --base-directory .. --output-file cov/test.info
cd cov
lcov -a initial.info -a test.info -o coverage.info
genhtml coverage.info --output-directory html
