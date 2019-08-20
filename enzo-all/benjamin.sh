rm slurm_*.sh
echo "rm \${HOME}/.config/julea/*" >> slurm_all.sh
for i in $(seq 10)
do
cat >> slurm_all.sh << EOF
\${HOME}/julea/build-hdf-julea/tools/julea-config --user \
  --object-servers="west${i}" --kv-servers="west${i}" \
  --db-servers="west${i}" \
  --object-backend=posix --object-component=server --object-path="\${tmpdir}/server-object" \
  --kv-backend=sqlite --kv-component=server --kv-path="\${tmpdir}/server-kv" \
  --db-backend=sqlite --db-component=server --db-path="memory"
mv \${HOME}/.config/julea/julea \${HOME}/.config/julea/julea-west-${i}
EOF
done
for f in $(find -name *.enzo \
	 | grep "\.enzo" \
	)
do
	config_folder=$(echo $f | sed "s-/[^/]*\$-/-g")
	config=$f
	slurm_name=slurm_$(echo $config | sed "s-/-_-g" | sed "s/\.//g")

#TOO SLOW
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_ValidatedNonlinearKelvinHelmholtz_2D-LongKHenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_Implosion_Implosionenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_SedovBlastAMR_SedovBlastAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-3D_ShockPool3D_ShockPool3Denzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-3D_GalaxySimulation_GalaxySimulationenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-3D_RotatingSphere_RotatingSphereenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_2D_Wengen2-CollidingFlow_Wengen2-CollidingFlowenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__GravitySolver_GravityStripTest_GravityStripTestenzo" ]; then continue;fi
#TOO FAST
if [ "$slurm_name" == "slurm__FuzzyDarkMatter_FDMTestenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cosmology_MHDZeldovichPancake_MHDZeldovichPancakeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cosmology_SphericalInfall_SphericalInfallenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cosmology_ZeldovichPancake_ZeldovichPancakeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cosmology_AdiabaticExpansion_AdiabaticExpansionenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cosmology_MHDZeldovichPancake_2_Dedner_MHDZeldovichPancake_2_Dednerenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cosmology_MHDAdiabaticExpansion_CT_MHDAdiabaticExpansion_CTenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cooling_OneZoneFreefallTest_OneZoneFreefallTestenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cooling_CoolingTest_Cloudy_CoolingTest_Cloudyenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cooling_CoolingTest_JHW_CoolingTest_JHWenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_KelvinHelmholtzAMR_KelvinHelmholtzAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_NohProblem2DAMR_NohProblem2DAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_KelvinHelmholtz_KelvinHelmholtzenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_ShockPool2D_ShockPool2Denzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_NohProblem2D_NohProblem2Denzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cosmology_AMRZeldovichPancake_Streaming_AMRZeldovichPancake_Streamingenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cosmology_MHDAdiabaticExpansion_Dedner_MHDAdiabaticExpansion_Dednerenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Cosmology_AMRZeldovichPancake_AMRZeldovichPancakeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_AMRShockPool2D_AMRShockPool2Denzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_RadiatingShockWave_RadiatingShockWaveenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-2D_HDMHD2DCheckOddEvenCouplingOfRiemannSolver_HDMHD2DCheckOddEvenCouplingOfRiemannSolverenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-3D_CollideTest_CollideTestenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-3D_ExtremeAdvectionTest_ExtremeAdvectionTestenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-4-ShockTube_Toro-4-ShockTubeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-6-ShockTube_Toro-6-ShockTubeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_WavePool_WavePoolenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_PressurelessCollapse_PressurelessCollapseenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-5-ShockTubeAMR_Toro-5-ShockTubeAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-1-ShockTubeAMR_Toro-1-ShockTubeAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-3-ShockTubeAMR_Toro-3-ShockTubeAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-2-ShockTubeAMR_Toro-2-ShockTubeAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-1-ShockTube_Toro-1-ShockTubeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-7-ShockTube_Toro-7-ShockTubeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-3-ShockTube_Toro-3-ShockTubeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-2-ShockTube_Toro-2-ShockTubeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-4-ShockTubeAMR_Toro-4-ShockTubeAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_Toro-5-ShockTube_Toro-5-ShockTubeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_ShockInABox_input_shockenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_ShockInABox_ShockInABoxenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_SodShockTube_SodShockTubeAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_SodShockTube_SodShockTubeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_FreeExpansion_FreeExpansionenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-1D_InteractingBlastWaves_InteractingBlastWavesenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransport_PhotonTestAMR_PhotonTestAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransport_PhotonTest_PhotonTestenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransport_PhotonShadowing_PhotonShadowingenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_1D_BrioWu-MHD-1D-MHDCT_BrioWu-MHD-1Denzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_1D_BrioWu-MHD-1D_BrioWu-MHD-1Denzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_1D_MHD_Metal_Advection_Dedner_MHD_Metal_Advection_Dednerenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_1D_MHD_Metal_Advection_CT_MHD_Metal_Advection_CTenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_1D_CR-ShockTube_CRShockTubeenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_2D_MHD2DRotorTest_MHD2DRotorTestenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_2D_MHDCTOrszagTang_MHDCTOrszagTangenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_2D_MHDCTOrszagTangAMR_MHDCTOrszagTangAMRenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_2D_LoopAdvection_CT_LoopAdvection_CTenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_2D_LoopAdvection_Dedner_LoopAdvection_Dednerenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_2D_SedovBlast-MHD-2D-Gardiner_SedovBlast-MHD-2D-Gardinerenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_2D_RayleighTaylor_CT_Suppressed_RayleighTaylor_CT_Suppressedenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__MHD_2D_MHDDednerOrszagTang_MHDDednerOrszagTangenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__GravitySolver_TestOrbit_TestOrbitenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__GravitySolver_TestOrbit_TestOrbitPotentialenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__GravitySolver_GravityTestSphere_GravityTestSphereenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__GravitySolver_GravityTest_GravityTestenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-3D_ProtostellarCollapse_Std_ProtostellarCollapse_Stdenzo" ]; then continue;fi
#FAIL read required hdf-input files
if [ "$slurm_name" == "slurm__FuzzyDarkMatter_FDMCollapseenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__FuzzyDarkMatter_FDMCosmologyenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_CosmologyFLD_RT_CosmologyFLD_RTenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__CosmologySimulation_ReionizationRadHydro_ReionizationRadHydroenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__CosmologySimulation_dm_only_dm_onlyenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__CosmologySimulation_ReionizationHydro_ReionizationHydroenzo" ]; then continue;fi
#FAIL cannot use RadiativeTransferFLD without HYPRE
if [ "$slurm_name" == "slurm__FLD_FLDPhotonTestenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RadiationStreamY0_sp_RadiationStreamY0_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RadiationStreamZ1_RadiationStreamZ1enzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RadiationStreamY0_RadiationStreamY0enzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RadiationStreamX1_sp_RadiationStreamX1_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_RHIonization2_sp_RHIonization2_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_CosmoIonization_q05z10_sp_CosmoIonization_q05z10_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_RadiatingShockLab_sp_RadiatingShockLab_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_TurnerStoneEquil1_sp_TurnerStoneEquil1_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_TurnerStoneEquil2_sp_TurnerStoneEquil2_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_CosmoIonization_q5z10_sp_CosmoIonization_q5z10_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_CosmoIonization_q05z4_sp_CosmoIonization_q05z4_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_RadiationStreamX0_sp_RadiationStreamX0_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_RadiationStreamZ1_sp_RadiationStreamZ1_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_RHIonization1_sp_RHIonization1_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Split_CosmoIonization_q5z4_sp_CosmoIonization_q5z4_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RadiationStream1D_RadiationStream1Denzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RadiationStream1D_sp_RadiationStream1D_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RadiatingShockLab1D_RadiatingShockLab1Denzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RadiationStreamZ0_sp_RadiationStreamZ0_spenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_CosmoIonization_q05z10_CosmoIonization_q05z10enzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_TurnerStoneEquil1_TurnerStoneEquil1enzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RHIonization1_RHIonization1enzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Enzochem_CosmoIonization_q05z10_enzochem_CosmoIonization_q05z10_enzochemenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Enzochem_RHIonization2_enzochem_RHIonization2_enzochemenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Enzochem_RHIonization1_enzochem_RHIonization1_enzochemenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Enzochem_CosmoIonization_q5z4_enzochem_CosmoIonization_q5z4_enzochemenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Enzochem_CosmoIonization_q05z4_enzochem_CosmoIonization_q05z4_enzochemenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_Grey_Enzochem_CosmoIonization_q5z10_enzochem_CosmoIonization_q5z10_enzochemenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_CosmoIonization_q05z4_CosmoIonization_q05z4enzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransportFLD_RadiatingShockLab_RadiatingShockLabenzo" ]; then continue;fi
#FAIL Error: Enzo must be compiled with 'make grackle-yes' to run with use_grackle = 1
if [ "$slurm_name" == "slurm__Cooling_CoolingTest_Grackle_CoolingTest_Grackleenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__Hydro_Hydro-3D_AgoraGalaxy_AgoraRestartenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransport_PhotonTestMultiFrequency_PhotonTestMultiFrequencyenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__RadiationTransport_PhotonTestMultiFrequency_OT_PhotonTestMultiFrequencyenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__CosmologySimulation_amr_nested_cosmology_amr_nested_cosmologyenzo" ]; then continue;fi
if [ "$slurm_name" == "slurm__CosmologySimulation_amr_cosmology_amr_cosmologyenzo" ]; then continue;fi
#FAIL Parameter mismatch: TopGridGravityBoundary = 1 only works with UnigridTranspose = 0
if [ "$slurm_name" == "slurm__GravitySolver_TestOrbitMRP_TestOrbitMRPenzo" ]; then continue;fi
#FAIL TopGridRank = -99999 ill defined
if [ "$slurm_name" == "slurm__FLD_FLD_LWRadParametersenzo" ]; then continue;fi

cat > ${slurm_name}.sh << EOF
#!/bin/bash
#SBATCH -J enzo
#SBATCH --partition=west
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --time=01:30:00

tmpdir=/dev/shm/warnke/julea

rm -rf \$tmpdir
mkdir -p \$tmpdir

echo ${slurm_name}.sh
echo \$tmpdir

export LD_LIBRARY_PATH=\${HOME}/julea/prefix-hdf-julea/lib/:\$LD_LIBRARY_PATH
export JULEA_CONFIG=\${HOME}/.config/julea/julea-west-${i}
export HDF5_VOL_JULEA=1
export HDF5_PLUGIN_PATH=\${HOME}/julea/prefix-hdf-julea/lib
export LD_PRELOAD="\$(locate libSegFault.so | tail -n 1)"
export SEGFAULT_SIGNALS="all"
export J_TIMER_DB="\${HOME}/julea/${slurm_name}.sqlite"
export G_MESSAGES_DEBUG=all

sleep 10s

cat \${HOME}/.config/julea/julea-${slurm_name}

\${HOME}/julea/build-hdf-julea/server/julea-server &

sleep 10s

cp -r \${HOME}/enzo-dev/run/${config_folder}* \$tmpdir
cd \$tmpdir
echo \$PWD
ls -la
time \${HOME}/enzo-dev/src/enzo/enzo.exe -d \${HOME}/enzo-dev/run/${config}
du -sh *
du -sh .
EOF
chmod +x ${slurm_name}.sh
echo "sbatch \${HOME}/julea/enzo-all/${slurm_name}.sh" >> slurm_all.sh
done
chmod +x slurm_all.sh
