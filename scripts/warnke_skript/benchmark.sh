umount /mnt2
mount /mnt2


./scripts/warnke_skript/kill.sh
./scripts/warnke_skript/format.sh
./waf.sh configure --out build-gcc-benchmark --prefix=prefix-gcc-benchmark --libdir=prefix-gcc-benchmark --bindir=prefix-gcc-benchmark --destdir=prefix-gcc-benchmark
# --debug --sanitize --hdf5=./dependencies/opt/spack/linux-ubuntu18.10-x86_64/gcc-8.3.0/hdf5-develop-qckzbb5gxnzeixlnhtgkq5mxvavegx4n
./waf.sh clean
./waf.sh build
./waf.sh install
rm -rf /mnt2/julea/*
export LD_LIBRARY_PATH=$(pwd)/prefix-gcc-benchmark/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=~/.config/julea/julea-benchmark
./build-gcc-benchmark/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=server --object-path=/mnt2/julea/object \
  --kv-backend=sqlite --kv-component=server --kv-path=/mnt2/julea/kv \
  --smd-backend=sqlite --smd-component=server --smd-path=/mnt2/julea/smd
mv ~/.config/julea/julea ~/.config/julea/julea-benchmark
julea-server &
sleep 5
githash=$(git log --pretty=format:'%H' -n 1)
rm -rf benchmark_values/warnke-${githash}
mkdir benchmark_values/warnke-${githash}
cd benchmark_values/warnke-${githash}
../../build-gcc-benchmark/benchmark/julea-benchmark >> benchmark_values
cd ../..
./scripts/warnke_skript/kill.sh
