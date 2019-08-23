#!/bin/bash
#https://buildmedia.readthedocs.org/media/pdf/enzo/latest/enzo.pdf

n_cpus=$1
parameterfile=${PWD}/$2

echo $parameterfile > ${J_TIMER_DB_RUN}.parameter
