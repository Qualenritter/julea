sudo mount -t tmpfs none /mnt2/

./julea2/build/tools/julea-config --user \
  --object-servers="$(hostname)" --kv-servers="$(hostname)" \
  --smd-servers="$(hostname)" \
  --object-backend=posix --object-component=server --object-path=/mnt2/julea/object \
  --kv-backend=sqlite --kv-component=server --kv-path=/mnt2/julea/kv \
  --smd-backend=sqlite --smd-component=server --smd-path=/mnt2/julea/smd

pkill julea-server

cd julea2
./waf.sh configure
./waf.sh clean
./waf.sh build
./waf.sh install
rm -rf /mnt2/julea/*
julea-server &
sleep 5
./build/benchmark/julea-benchmark >> ../benchmark_values_strassberger
pkill julea-server
cd ..


cd julea
./scripts/warnke_skript/format.sh
./waf.sh configure
# --debug --sanitize --hdf5=./dependencies/opt/spack/linux-ubuntu18.10-x86_64/gcc-8.3.0/hdf5-develop-qckzbb5gxnzeixlnhtgkq5mxvavegx4n
./waf.sh clean
./waf.sh build
./waf.sh install
rm -rf /mnt2/julea/*
julea-server &
sleep 5
./build/benchmark/julea-benchmark >> ../benchmark_values_warnke
pkill julea-server
cd ..
