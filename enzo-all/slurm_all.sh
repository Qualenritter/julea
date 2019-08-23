rm ${HOME}/.config/julea/*
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west1" --kv-servers="west1"   --db-servers="west1"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west1
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west2" --kv-servers="west2"   --db-servers="west2"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west2
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west3" --kv-servers="west3"   --db-servers="west3"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west3
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west4" --kv-servers="west4"   --db-servers="west4"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west4
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west5" --kv-servers="west5"   --db-servers="west5"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west5
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west6" --kv-servers="west6"   --db-servers="west6"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west6
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west7" --kv-servers="west7"   --db-servers="west7"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west7
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west8" --kv-servers="west8"   --db-servers="west8"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west8
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west9" --kv-servers="west9"   --db-servers="west9"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west9
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west10" --kv-servers="west10"   --db-servers="west10"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west10
sleep 0.1s
tmpdir=/dev/shm/warnke/julea
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="benjamin0" --kv-servers="benjamin0"   --db-servers="benjamin0"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="${tmpdir}/server-db"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-benjamin0
sleep 0.1s
sbatch ${HOME}/julea/enzo-all/slurm__Cosmology_MHDZeldovichPancake_2_CT_MHDZeldovichPancake_2_CTenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Cosmology_MHDZeldovichPancake_2_CT_MHDZeldovichPancake_2_CTenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__DrivenTurbulence3D_DrivenTurbulence3Denzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__DrivenTurbulence3D_DrivenTurbulence3Denzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_FreeExpansionAMR_FreeExpansionAMRenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_FreeExpansionAMR_FreeExpansionAMRenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_ImplosionAMR_ImplosionAMRenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_ImplosionAMR_ImplosionAMRenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_RampedKelvinHelmholtz2D_RampedKelvinHelmholtz2Denzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_RampedKelvinHelmholtz2D_RampedKelvinHelmholtz2Denzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_ValidatedNonlinearKelvinHelmholtz_2D-LongKH-AMRenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_ValidatedNonlinearKelvinHelmholtz_2D-LongKH-AMRenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_Athena-RayleighTaylor_Athena-RayleighTaylorenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_Athena-RayleighTaylor_Athena-RayleighTaylorenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_SedovBlast_SedovBlastenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_SedovBlast_SedovBlastenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_DoubleMachReflection_DoubleMachReflectionenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_DoubleMachReflection_DoubleMachReflectionenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_CollapseTestNonCosmological_CollapseTestNonCosmologicalenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_CollapseTestNonCosmological_CollapseTestNonCosmologicalenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_RotatingCylinder_RotatingCylinderenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_RotatingCylinder_RotatingCylinderenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_StripTest_StripTestenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_StripTest_StripTestenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_NFWCoolCoreCluster_NFWCoolCoreClusterenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_NFWCoolCoreCluster_NFWCoolCoreClusterenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_NohProblem3D_NohProblem3Denzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_NohProblem3D_NohProblem3Denzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__StarParticle_StarParticleSingleTest_TestStarParticleSingleenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__StarParticle_StarParticleSingleTest_TestStarParticleSingleenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__MHD_3D_StochasticForcing_StochasticForcingenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__MHD_3D_StochasticForcing_StochasticForcingenzo-1.sh
sbatch ${HOME}/julea/enzo-all/slurm__MHD_2D_SedovBlast-MHD-2D-Fryxell_SedovBlast-MHD-2D-Fryxellenzo-0.sh
sbatch ${HOME}/julea/enzo-all/slurm__MHD_2D_SedovBlast-MHD-2D-Fryxell_SedovBlast-MHD-2D-Fryxellenzo-1.sh
