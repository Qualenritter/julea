#!/bin/bash
#https://buildmedia.readthedocs.org/media/pdf/enzo/latest/enzo.pdf

n_cpus=$1
parameterfile=${PWD}/$2

(
sleep 0.5s

for f in $(find -name "${J_TIMER_DB}")
do
	for r in $(sqlite3 ${f} "select * from tmp;" | sed "s/|/,/g")
	do
		a=$(cut -d',' -f1 <<<"$r")
		b=$(cut -d',' -f2 <<<"$r")
		c=$(cut -d',' -f3 <<<"$r")
		echo "sqlite3 ${J_TIMER_DB_RUN}.sqlite \"insert into tmp (name,count,timer) values('$a',$b,$c) on conflict(name) do update set count=count+$b, timer=timer+$c where name='$a'\""
		sqlite3 ${J_TIMER_DB_RUN}.sqlite "insert into tmp (name,count,timer) values('$a',$b,$c) on conflict(name) do update set count=count+$b, timer=timer+$c where name='$a'"
	done
	rm ${f}
done

export LD_LIBRARY_PATH=${HOME}/julea/prefix-hdf-julea/lib/:${LD_LIBRARY_PATH}
export JULEA_CONFIG=${HOME}/.config/julea/julea-$(hostname)
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=${HOME}/julea/prefix-hdf-julea/lib
export J_TIMER_DB="${PWD}.sqlite"
export G_MESSAGES_DEBUG=all

echo ${PWD} >> ${J_TIMER_DB_RUN}.out
echo n_cpus $n_cpus >> ${J_TIMER_DB_RUN}.out
echo parameterfile $parameterfile >> ${J_TIMER_DB_RUN}.out

mpirun -np ${n_cpus} ${HOME}/enzo-dev/src/enzo/enzo.exe -r $parameterfile >> ${J_TIMER_DB_RUN}.out
#${HOME}/enzo-dev/src/enzo/enzo.exe -r $parameterfile >> ${J_TIMER_DB_RUN}.out
) &
