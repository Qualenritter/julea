#!/bin/bash
#https://buildmedia.readthedocs.org/media/pdf/enzo/latest/enzo.pdf

n_cpus=$1
parameterfile=$PWD/$2

(
sleep 5s

if [ "${J_TIMER_DB}" != "${J_TIMER_DB_RUN}.sqlite" ]; then
	for r in $(sqlite3 ${J_TIMER_DB} "select * from tmp;" | sed "s/|/,/g")
	do
		a=$(cut -d',' -f1 <<<"$r")
		b=$(cut -d',' -f2 <<<"$r")
		c=$(cut -d',' -f3 <<<"$r")
		echo "sqlite3 ${J_TIMER_DB_RUN}.sqlite \"insert into tmp (name,count,timer) values('$a',$b,$c) on conflict(name) do update set count=count+$b, timer=timer+$c where name='$a'\""
		sqlite3 ${J_TIMER_DB_RUN}.sqlite "insert into tmp (name,count,timer) values('$a',$b,$c) on conflict(name) do update set count=count+$b, timer=timer+$c where name='$a'"
	done
	rm ${J_TIMER_DB}
fi

export LD_LIBRARY_PATH=/src/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=/root/.config/julea/julea_enzo
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=/src/julea/prefix-hdf-julea/lib
export J_TIMER_DB="${parameterfile}.sqlite"
#export G_MESSAGES_DEBUG=all

echo n_cpus $n_cpus
echo parameterfile $parameterfile

rm $J_TIMER_DB
/src/applications_using_hdf5/enzo/enzo-dev/src/enzo/enzo.exe -r $parameterfile >> ${J_TIMER_DB_RUN}.out
) &
