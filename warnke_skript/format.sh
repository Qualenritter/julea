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

for f in $(git diff --name-only master | grep '\.c$' | grep -v prefix | grep -v spack);do
	echo $f
	cd build
	cat ../$f | sed "s/}/}\n/g" | sed "s/\sif/\nif/g" | sed "s/\sfor/\nfor/g" | sed "s/\swhile/\nwhile/g" | sed "s/\sdo/\ndo/g" | sed "s/J_TRACE_FUNCTION(NULL);/J_TRACE_FUNCTION(NULL);\n/g" | tr '\n' '\r' | sed "s/}[\r\s]*}/}}/g" | tr '\r' '\n'> ../$f.tmp
	mv ../$f.tmp ../$f
	clang-tidy -header-filter='.*,-dependencies' -fix -checks='readability-braces-around-statements,readability-else-after-return,readability-isolate-declaration' -p=/src/julea/build ../$f -- \
		-Iinclude \
		-I../include \
		-Iinclude/core \
		-I../include/core \
		-Itest \
		-I../test \
		-I../dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/glib-2.56.3-z5nre6mqm5ofqploxeigak3xiuvp7mph/include/glib-2.0 \
		-I../dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/glib-2.56.3-z5nre6mqm5ofqploxeigak3xiuvp7mph/lib/glib-2.0/include \
		-I../dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/pcre-8.42-yupgernpm6rywenufbupwypikx4b5xec/include \
		-I../dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/libmongoc-1.9.5-a37k6hbsbanjkqibnmcc3letw7wshirg/include/libbson-1.0 \
		-I../dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/hdf5-develop-4iami4kalqj7xgv2x2uv25dnzvz4xzwf/include \
		-I../dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/sqlite-3.28.0-h2xu54j2dy5spf2gbnaikdw4ci5aj3bj/include \
		-Ibenchmark \
		-I../benchmark \
		-Itest \
		-I../test \
		-Iexample \
		-I../example \
		-I/usr/lib/x86_64-linux-gnu/openmpi/include/ \
		-DJULEA_COMPILATION \
		-DJULEA_DB_COMPILATION \
		-DJULEA_HDF5_COMPILATION \
		-DJULEA_ITEM_COMPILATION \
		-DJULEA_KV_COMPILATION \
		-DJULEA_OBJECT_COMPILATION

	cd ..
	clang-format -i $f
	cat $f | sed "s/static /static\n/g" > $f.tmp
	mv $f.tmp $f
done

