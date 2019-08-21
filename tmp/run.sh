#!/bin/bash
export LD_LIBRARY_PATH=/src/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=/root/.config/julea/julea_enzo
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=/src/julea/prefix-hdf-julea/lib
#export LD_PRELOAD="$(locate libSegFault.so | tail -n 1)"
#export SEGFAULT_SIGNALS="all"
export J_TIMER_DB="/src/julea/slurm__MHD_3D_ShearingBox_ShearingBoxenzo.sqlite"
export G_MESSAGES_DEBUG=all

j="XXXX"
for i in $(seq 10)
do
	if [ "1" == "$i" ]; then
		cat FreeExpansionAMR.enzo | sed "s/StopTime\s*= 60/StopTime = $i/g" > FreeExpansionAMR.tmp.enzo
		/src/applications_using_hdf5/enzo/enzo-dev/src/enzo/enzo.exe FreeExpansionAMR.tmp.enzo
	else
		cat DD${j}/output_${j} | sed "s/StopTime\s*=.*/StopTime = $i/g" > DD${j}/output_${j}.tmp
		mv DD${j}/output_${j}.tmp DD${j}/output_${j}
		/src/applications_using_hdf5/enzo/enzo-dev/src/enzo/enzo.exe -r DD${j}/output_${j}
		echo "Both Strings are not Equal."
		break;
	fi
	printf -v j "%04d" $i
	echo "i=$i, j=$j"
done
