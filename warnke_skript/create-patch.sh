#!/bin/bash

rm -rf patch
mkdir -p patch

for f in $(git diff --ignore-all-space --name-only master ':!benchmark_values*' ':!enzo*' ':!warnke*' ':!benchmark' ':!lib/hdf5' ':!example' ':!.gitignore' ':!.clang-format')
do
	git diff --minimal --ignore-all-space master -- $f >> patch/$(echo $f | sed "sx/x-xg").patch
	if [ ! -s patch/$(echo $f | sed "sx/x-xg").patch ]
	then
		git checkout master $f
	fi
done
