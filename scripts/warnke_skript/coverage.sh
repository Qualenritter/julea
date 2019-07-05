rm afl/cov/coverage.info
touch afl/cov/coverage.info

for i in $(ls afl/cov/*.info)
do
	if [ -s "$i" ]
	then
		cp $i afl/cov/coverage.info
		break
	fi
done
for i in $(ls afl/cov/*.info)
do
	if [ -s "$i" ]
	then
		lcov -a afl/cov/coverage.info -a $i -o afl/cov/coverage2.info
		mv afl/cov/coverage2.info afl/cov/coverage.info
	fi
done
for i in $(ls afl/cov)
do
	echo afl/cov/$i
	lcov --capture --directory afl/cov/$i --base-directory afl --output-file afl/cov/$i.info
	if [ -s "afl/cov/$i.info" ]
	then
		lcov -a afl/cov/coverage.info -a afl/cov/$i.info -o afl/cov/coverage2.info
		mv afl/cov/coverage2.info afl/cov/coverage.info
	fi
	rm afl/cov/$i.info
done
genhtml afl/cov/coverage.info --output-directory afl/cov/html
