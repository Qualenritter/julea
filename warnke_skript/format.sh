#!/bin/bash

# JULEA - Flexible storage framework
# Copyright (C) 2019 Benjamin Warnke
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

mkdir -p log/scan-build
rm -rf build
scan-build -o log/scan-build ./waf.sh configure --debug --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)
scan-build -o log/scan-build ./waf.sh build
rm -rf build
./waf.sh configure --debug --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf)

#for f in $(git diff --name-only HEAD | grep -e '\.h$' -e '\.c$' | grep -v not-formatted-header.h | grep -v prefix | grep -v spack);do
for f in $(git diff --name-only master | grep -e '\.h$' -e '\.c$' | grep -v not-formatted-header.h | grep -v prefix | grep -v spack);do
	echo $f
	cd build
	clang-tidy -header-filter='.*,-dependencies' -fix -checks='readability-braces-around-statements,readability-else-after-return,readability-isolate-declaration' -p=/src/julea/build ../$f
	cd ..
	clang-format -i $f
done

