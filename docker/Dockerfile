# Dockerfile to install UKAT
FROM python:3.7

# Install Dependencies
RUN apt-get update && apt-get upgrade -y && \
	apt-get install -y build-essential pkg-config cmake git pigz && \
	apt-get clean -y && apt-get autoclean -y && apt-get autoremove -y

# Get dcm2niix from github and compile
RUN cd /tmp && \
	git clone https://github.com/rordenlab/dcm2niix.git && \
	cd dcm2niix && mkdir build && cd build && \
	cmake -DBATCH_VERSION=ON -DUSE_OPENJPEG=ON .. && \
	make && make install

RUN pip install pydicom

ADD dicom_qc.py .
ADD dicomqc_conf.tsv .


LABEL org.nrg.commands="[{\"name\": \"cmore-preproc\", \"command-line\": \"python cmore_preproc.py /input /output \\"[DCM2NIIX_FLAGS]\\" [METHOD]\", \"image\": \"martincraig/cmore\", \"label\": \"cmore\", \"version\": \"0.0.1\", \"schema-version\": \"1.0\", \"info-url\": \"\", \"type\": \"docker\", \"description\": \"Runs preprocessing on a CMORE session\", \"inputs\": [{\"name\": \"dcm2niix-flags\", \"replacement-key\": \"[DCM2NIIX_FLAGS]\", \"required\": false, \"type\": \"string\", \"default-value\": \"-m n -f %n_%p_%q -z y\", \"description\": \"Flags for DCM2NIIX\"}, {\"name\": \"t2star-method\", \"replacement-key\": \"[METHOD]\", \"required\": false, \"type\": \"string\", \"default-value\": \"all\", \"description\": \"Method for calculating T2* - loglin or 2p_exp or all\"}], \"outputs\": [{\"name\": \"t2star\", \"mount\": \"cmore-out\", \"path\": \"t2star\", \"required\": \"false\", \"description\": \"T2* map\"}, {\"name\": \"b0map\", \"mount\": \"cmore-out\", \"path\": \"b0map\", \"required\": \"false\", \"description\": \"B0 map\"}, {\"name\": \"nifti\", \"mount\": \"cmore-out\", \"path\": \"nifti\", \"glob\": \"*.nii.gz\", \"required\": \"true\", \"description\": \"NIFTI images\"}], \"mounts\": [{\"writable\": \"false\", \"path\": \"/input\", \"name\": \"dicom-in\"}, {\"writable\": \"true\", \"path\": \"/output\", \"name\": \"cmore-out\"}], \"xnat\": [{\"name\": \"cmore-preproc\", \"contexts\": [\"xnat:imageScanData\"], \"description\": \"Run CMORE preprocessing\", \"label\": \"cmore-preproc\", \"external-inputs\": [{\"name\": \"scan\", \"type\": \"Scan\", \"required\": true, \"description\": \"Input scan\"}], \"derived-inputs\": [{\"name\": \"scan-dicoms\", \"type\": \"Resource\", \"derived-from-wrapper-input\": \"scan\", \"matcher\": \"@.label == 'DICOM'\", \"provides-files-for-command-mount\": \"dicom-in\", \"description\": \"The DICOM resource on the scan\"}], \"output-handlers\": [{\"name\": \"nifti-resource\", \"accepts-command-output\": \"nifti\", \"type\": \"Resource\", \"label\": \"NIFTI\", \"as-a-child-of-wrapper-input\": \"scan\"}, {\"name\": \"t2star-resource\", \"accepts-command-output\": \"t2star\", \"type\": \"Resource\", \"label\": \"T2STAR\", \"as-a-child-of-wrapper-input\": \"scan\"}, {\"name\": \"b0map-resource\", \"accepts-command-output\": \"b0map\", \"type\": \"Resource\", \"label\": \"B0MAP\", \"as-a-child-of-wrapper-input\": \"scan\"}]}]}]"
