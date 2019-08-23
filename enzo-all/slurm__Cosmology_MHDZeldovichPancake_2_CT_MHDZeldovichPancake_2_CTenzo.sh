#!/bin/bash
#SBATCH -J enzo
#SBATCH --partition=west
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --time=01:30:00

tmpdir=/dev/shm/warnke/julea

rm -rf $tmpdir
mkdir -p $tmpdir

echo $(hostname)
echo slurm__Cosmology_MHDZeldovichPancake_2_CT_MHDZeldovichPancake_2_CTenzo.sh
echo $tmpdir

export LD_LIBRARY_PATH=${HOME}/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=${HOME}/.config/julea/julea-$(hostname)
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-hdf-julea/lib
export J_TIMER_DB_RUN="${HOME}/julea/slurm__Cosmology_MHDZeldovichPancake_2_CT_MHDZeldovichPancake_2_CTenzo"
export J_TIMER_DB="$tmpdir/tmp.sqlite"
export G_MESSAGES_DEBUG=all

cat ${HOME}/.config/julea/julea-$(hostname)

pkill julea-server
${HOME}/julea/build-hdf-julea/server/julea-server &

sleep 1s

cp -r ${HOME}/enzo-dev/run/./Cosmology/MHDZeldovichPancake_2_CT/* $tmpdir
cp ${HOME}/julea/enzo-all/run-continue.sh $tmpdir
cd $tmpdir
echo $PWD
ls -la

rm $J_TIMER_DB ${J_TIMER_DB_RUN}.out

cat ${HOME}/enzo-dev/run/./Cosmology/MHDZeldovichPancake_2_CT/MHDZeldovichPancake_2_CT.enzo | grep -v "ResubmitOn" | grep -v "StopCPUTime" | grep -v "ResubmitCommand" > ${HOME}/enzo-dev/run/./Cosmology/MHDZeldovichPancake_2_CT/MHDZeldovichPancake_2_CT.enzo.tmp
echo "ResubmitOn = 1" >> ${HOME}/enzo-dev/run/./Cosmology/MHDZeldovichPancake_2_CT/MHDZeldovichPancake_2_CT.enzo.tmp
echo "StopCPUTime = 1" >> ${HOME}/enzo-dev/run/./Cosmology/MHDZeldovichPancake_2_CT/MHDZeldovichPancake_2_CT.enzo.tmp
echo "ResubmitCommand = ./run-continue.sh" >> ${HOME}/enzo-dev/run/./Cosmology/MHDZeldovichPancake_2_CT/MHDZeldovichPancake_2_CT.enzo.tmp

${HOME}/julea/example/a.out

truncate -s0 ${J_TIMER_DB_RUN}.parameter
(mpirun -np 6 ${HOME}/enzo-dev/src/enzo/enzo.exe ${HOME}/enzo-dev/run/./Hydro/Hydro-2D/ImplosionAMR/ImplosionAMR.enzo.tmp >> ${J_TIMER_DB_RUN}.out) &
ENZO_PID=$!
while true
do
	echo "wait for $ENZO_PID"
	wait $ENZO_PID
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
				echo "sqlite3 ${J_TIMER_DB_RUN}.sqlite \"insert into tmp (name,count,timer) values('$a',$b,$c) on conflict(name) do update set count=count+$b, timer=timer+$c where name='$a'\""
				sqlite3 ${J_TIMER_DB_RUN}.sqlite "insert into tmp (name,count,timer) values('$a',$b,$c) on conflict(name) do update set count=count+$b, timer=timer+$c where name='$a'"
			done
			rm ${f}
		fi
	done
	echo "merged timers"
	parameter=$(cat ${J_TIMER_DB_RUN}.parameter | head -n 1)
	truncate -s0 ${J_TIMER_DB_RUN}.parameter
	if [ -z "$parameter" ]
	then
		break
	fi
	echo "continue with ${parameter}"
	(mpirun -np 6 ${HOME}/enzo-dev/src/enzo/enzo.exe -r ${parameter} >> ${J_TIMER_DB_RUN}.out) &
	ENZO_PID=$!
done
echo "done"


du -sh *
du -sh .
