#!/bin/bash
#SBATCH -J enzo
#SBATCH --partition=west
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --time=02:00:00

function benchmark(){
tmpdir=$1
use_julea=$2
iteration_limit=$3
db_backend=$4
db_component=$5
tmp_dir_type=$6
process_count=$7


rm -rf $tmpdir
mkdir -p $tmpdir

echo $(hostname)
echo benchmark.sh
echo $tmpdir

echo "core-%e-%p-%s" > /proc/sys/kernel/core_pattern
ulimit -c unlimited
export LD_LIBRARY_PATH=${HOME}/julea/prefix/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-$(hostname)
export HDF5_VOL_JULEA=$use_julea
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix/lib
export J_TIMER_DB_RUN="${HOME}/julea/enzo-specific/benchmark-${tmp_dir_type}-${use_julea}-${iteration_limit}-${db_backend}"
export J_TIMER_DB="$tmpdir/tmp.sqlite"
#export G_MESSAGES_DEBUG=all

${HOME}/julea/build/tools/julea-config --user --object-servers="benjamin0" --kv-servers="benjamin0" --db-servers="benjamin0" \
	--object-backend=posix --object-component=server --object-path="${tmpdir}/server-object" \
	--kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv" \
	--db-backend=${db_backend} --db-component=${db_component} --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${JULEA_CONFIG}

cat ${JULEA_CONFIG}

pkill julea-server

/src/julea/warnke_skript/reset_mysql.sh ${tmpdir}/mysql
${HOME}/julea/build/server/julea-server &
SERVER_PID=$!
sleep 1s

cp -r ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/CollapseTestNonCosmological/* $tmpdir
cp ${HOME}/julea/enzo-all/run-continue.sh $tmpdir
cd $tmpdir
echo $PWD
ls -la

cat ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/CollapseTestNonCosmological/CollapseTestNonCosmological.enzo | grep -v "ResubmitOn" | grep -v "StopCPUTime" | grep -v "ResubmitCommand" > ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/CollapseTestNonCosmological/CollapseTestNonCosmological.enzo.tmp
echo "ResubmitOn = 1" >> ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/CollapseTestNonCosmological/CollapseTestNonCosmological.enzo.tmp
echo "StopCPUTime = 1" >> ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/CollapseTestNonCosmological/CollapseTestNonCosmological.enzo.tmp
echo "ResubmitCommand = ./run-continue.sh" >> ${HOME}/enzo-dev/run/./Hydro/Hydro-3D/CollapseTestNonCosmological/CollapseTestNonCosmological.enzo.tmp

rm ${J_TIMER_DB}*

(
        cd ${HOME}/julea/example
	./hdf5-example
)

rm ${J_TIMER_DB_RUN}.out ${J_TIMER_DB_RUN}.sqlite ${J_TIMER_DB_RUN}.parameter
sqlite3 ${J_TIMER_DB_RUN}.sqlite "create table if not exists tmp (name TEXT primary key,count INTEGER,timer REAL)"

ENZO_START=$(date +%s.%N)
mpirun --allow-run-as-root -np 6 ${HOME}/enzo-dev/src/enzo/enzo.exe ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/ImplosionAMR/ImplosionAMR.enzo.tmp >> ${J_TIMER_DB_RUN}.out
mv core* /src/julea/enzo-specific/
while true
do
	ENZO_END=$(date +%s.%N)
	echo "going to restart"
	for f in $(find "$(dirname ${J_TIMER_DB})/" -maxdepth 1 -name "$(echo "${J_TIMER_DB}*" | sed "s-.*/--g")")
	do
		echo "$f"
		if [ ! -f ${J_TIMER_DB_RUN}.sqlite ]
		then
			mv $f ${J_TIMER_DB_RUN}.sqlite
		else
			for r in $(sqlite3 ${f} "select * from tmp;" | sed "s/|/,/g")
			do
				a=$(cut -d',' -f1 <<<"$r")
				b=$(cut -d',' -f2 <<<"$r")
				c=$(cut -d',' -f3 <<<"$r")
				sqlite3 ${J_TIMER_DB_RUN}.sqlite "insert into tmp (name,count,timer) values('$a',$b,$c) on conflict(name) do update set count=count+$b, timer=timer+$c where name='$a'"
			done
			rm ${f}
		fi
	done
	sqlite3 ${J_TIMER_DB_RUN}.sqlite "insert into tmp (name,count,timer) values('bash_time',1,${ENZO_END} - ${ENZO_START}) on conflict(name) do update set count=count + 1, timer=timer + ${ENZO_END} - ${ENZO_START} where name='bash_time'"
	echo "merged timers"
	ENZO_TOTAL_TIME=$(echo $(sqlite3 ${J_TIMER_DB_RUN}.sqlite "select timer from tmp where name='bash_time'") | sed "s/\..*//g")
	ENZO_TOTAL_COUNT=$(echo $(sqlite3 ${J_TIMER_DB_RUN}.sqlite "select count from tmp where name='bash_time'") | sed "s/\..*//g")
	if [ "${ENZO_TOTAL_TIME}" -gt "120" ]
	then
		break
	fi
	if [ "${ENZO_TOTAL_COUNT}" -gt "${iteration_limit}" ]
	then
		break
	fi
	parameter=$(cat ${J_TIMER_DB_RUN}.parameter | head -n 1)
	rm ${J_TIMER_DB_RUN}.parameter
	if [ -z "$parameter" ]
	then
		break
	fi
	echo "continue with ${parameter}"
	ENZO_START=$(date +%s.%N)
	mpirun --allow-run-as-root -np 6 ${HOME}/enzo-dev/src/enzo/enzo.exe -r ${parameter} >> ${J_TIMER_DB_RUN}.out
	mv core* /src/julea/enzo-specific/
done
kill -9 ${SERVER_PID}
echo "done"
}

cd /src/julea/enzo-specific
(
	cd ..
	rm -rf build prefix
	./waf.sh configure  --out build --prefix=prefix --libdir=prefix --bindir=prefix --destdir=prefix --hdf=$(echo $CMAKE_PREFIX_PATH | sed -e 's/:/\n/g' | grep hdf) --debug
	./waf.sh build
	./waf.sh install
)
(
        cd ${HOME}/julea/example
        make clean
        make
)

sudo chown -R benjamin:benjamin /home/benjamin/enzo-dev/run
sudo chown -R benjamin:benjamin /mnt/julea
sudo chown -R benjamin:benjamin /mnt2
sudo chown -R benjamin:benjamin /src/julea
sudo chown -R benjamin:benjamin /root/enzo-dev
sudo chown -R benjamin:benjamin /root/enzo-dev/src/enzo/enzo.exe

benchmark /dev/shm/warnke/julea	1 100000 mysql  client mem 1
benchmark /mnt/julea		1 100000 mysql  client hdd 1
benchmark /dev/shm/warnke/julea	0 100000 sqlite server mem 1
benchmark /mnt/julea		0 100000 sqlite server hdd 1
benchmark /dev/shm/warnke/julea	1 100000 mysql  client mem 6
benchmark /mnt/julea		1 100000 mysql  client hdd 6
benchmark /dev/shm/warnke/julea	0 100000 sqlite server mem 6
benchmark /mnt/julea		0 100000 sqlite server hdd 6

benchmark /dev/shm/warnke/julea	1 100000 sqlite server mem 6
benchmark /mnt/julea		1 100000 sqlite server hdd 6
benchmark /dev/shm/warnke/julea	1 100000 sqlite server mem 1
benchmark /mnt/julea		1 100000 sqlite server hdd 1
