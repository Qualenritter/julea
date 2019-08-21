#!/bin/bash

n_cpus=$1
parameterfile=$PWD/$2

export LD_LIBRARY_PATH=/src/julea/prefix-hdf-julea/lib/:$LD_LIBRARY_PATH
export JULEA_CONFIG=/root/.config/julea/julea_enzo
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=/src/julea/prefix-hdf-julea/lib
export J_TIMER_DB="/src/julea/slurm__MHD_3D_ShearingBox_ShearingBoxenzo.sqlite$2"
export G_MESSAGES_DEBUG=all

echo n_cpus $n_cpus
echo parameterfile $parameterfile

rm $J_TIMER_DB
nohup /src/applications_using_hdf5/enzo/enzo-dev/src/enzo/enzo.exe $parameterfile &

exit

j="XXXX"
for i in $(seq 3)
do
	if [ "1" == "$i" ]; then
		cat FreeExpansionAMR.enzo | sed "s/StopTime\s*= 60/StopTime = $i/g" > FreeExpansionAMR.tmp.enzo
		/src/applications_using_hdf5/enzo/enzo-dev/src/enzo/enzo.exe FreeExpansionAMR.tmp.enzo
	else
		cp -r DD${j} DD${j}.bak
		cat DD${j}/output_${j} | sed "s/StopTime\s*=.*/StopTime = $i/g" > DD${j}/output_${j}.tmp
		mv DD${j}/output_${j}.tmp DD${j}/output_${j}
		/src/applications_using_hdf5/enzo/enzo-dev/src/enzo/enzo.exe -r DD${j}/output_${j}
	fi
	printf -v j "%04d" $i
	echo "i=$i, j=$j"
done
