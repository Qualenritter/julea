rm ${HOME}/.config/julea/*
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west1" --kv-servers="west1"   --db-servers="west1"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-1
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west2" --kv-servers="west2"   --db-servers="west2"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-2
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west3" --kv-servers="west3"   --db-servers="west3"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-3
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west4" --kv-servers="west4"   --db-servers="west4"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-4
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west5" --kv-servers="west5"   --db-servers="west5"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-5
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west6" --kv-servers="west6"   --db-servers="west6"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-6
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west7" --kv-servers="west7"   --db-servers="west7"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-7
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west8" --kv-servers="west8"   --db-servers="west8"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-8
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west9" --kv-servers="west9"   --db-servers="west9"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-9
${HOME}/julea/build-hdf-julea/tools/julea-config --user   --object-servers="west10" --kv-servers="west10"   --db-servers="west10"   --object-backend=posix --object-component=server --object-path="${tmpdir}/server-object"   --kv-backend=sqlite --kv-component=server --kv-path="${tmpdir}/server-kv"   --db-backend=sqlite --db-component=server --db-path="memory"
mv ${HOME}/.config/julea/julea ${HOME}/.config/julea/julea-west-10
sbatch ${HOME}/julea/enzo-all/slurm__Cosmology_MHDZeldovichPancake_2_CT_MHDZeldovichPancake_2_CTenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__DrivenTurbulence3D_DrivenTurbulence3Denzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_FreeExpansionAMR_FreeExpansionAMRenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_ImplosionAMR_ImplosionAMRenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_RampedKelvinHelmholtz2D_RampedKelvinHelmholtz2Denzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_ValidatedNonlinearKelvinHelmholtz_2D-LongKH-AMRenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_Athena-RayleighTaylor_Athena-RayleighTaylorenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_SedovBlast_SedovBlastenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-2D_DoubleMachReflection_DoubleMachReflectionenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_CollapseTestNonCosmological_CollapseTestNonCosmologicalenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_NohProblem3DAMR_NohProblem3DAMRenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_RotatingCylinder_RotatingCylinderenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_StripTest_StripTestenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_NFWCoolCoreCluster_NFWCoolCoreClusterenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_NohProblem3D_NohProblem3Denzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__Hydro_Hydro-3D_Athena-RayleighTaylor3D_Athena-RayleighTaylor3Denzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__StarParticle_StarParticleSingleTest_TestStarParticleSingleenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__MHD_3D_ShearingBox_ShearingBoxenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__MHD_3D_StochasticForcing_StochasticForcingenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__MHD_2D_SedovBlast-MHD-2D-Fryxell_SedovBlast-MHD-2D-Fryxellenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__GravitySolver_BinaryCollapse_BinaryCollapseenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__GravitySolver_BinaryCollapseMHDCT_BinaryCollapseenzo.sh
sbatch ${HOME}/julea/enzo-all/slurm__GravitySolver_MaximumGravityRefinementTest_MaximumGravityRefinementTestenzo.sh
