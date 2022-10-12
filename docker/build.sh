#!/bin/bash

cp Dockerfile.in Dockerfile
python scripts/cmd2label.py dicom_qc_cmd.json >> Dockerfile
cp ../config/ukrin_conf.xlsx .

tag=`cat version.txt`
docker build -t martincraig/xnat-dicomqc .
docker tag martincraig/xnat-dicomqc martincraig/xnat-dicomqc:$tag 
docker push martincraig/xnat-dicomqc:$tag
docker push martincraig/xnat-dicomqc:latest
