Docker container to run DICOM tag based QC command as an XNAT container service
===============================================================================

Prerequisites
-------------

 - XNAT 1.7 or 1.8
 - Container service plugin installed (this is done by default in XNAT 1.8)
 - Docker installed on XNAT server

Installation instructions
-------------------------

1. Building the data type plugin

    cd plugin
    ./gradlew jar

2. Copy the plugin to the XNAT plugin directory

    cp build/libs/xnat-dicomqc-plugin-0.0.1.jar $XNAT_HOME/plugins

3. Restart the XNAT server

For example on Redhat/Centos `sudo systemctl restart tomcat`

4. Install the data type

 - Log in to XNAT as administrator. From the menu select `Administer->Data Types`
 - Select `Set up additional data type`
 - Select `xnat_dicomqc:DICOMQCData`
 - Enter `DICOMQCData` for the singular and plural names, otherwise just click `Next` leaving other options unchanged
 - `DICOMQCData` should now be listed in the data types list

5. Install the Docker image 

 - From the menu select `Administer->Plugin Settings`
 - Select `Images and commands`
 - Select `Add new image`
 - For `Image Name` enter `martincraig/xnat-dicomqc`. Leave version blank
 - Select `Pull image`

6. Add the command definition if required

Note that there is a bug in some versions of XNAT that means the command definition is not correctly extracted
from the Docker image. Under `Administer->Plugin Settings`, look for DICOMQC under `Command Configurations`. If
it is *not* present you will need to do the following:

 - Under `Images and Commands` expand hidden images
 - Find `martincraig/xnat-dicomqc` and click `Add Command`
 - Delete any text, and paste the contents of `docker/dicom_qc_cmd.json` into the window
 - Click `Save command`

7. Enable the command for the XNAT server

This can be done under `Images and Commands` on the `Plugin Settings` page

8. Enable the command for a project

Select a project and click `Project Settings` from the menu. The DICOMQC command should be listed and can 
be enabled. Default settings can also be added

9. Upload project QC definition

This is an Excel document describing the tests to be run.

10. Run the command

Select an MR session, click `Run Container` and select DICOMQC

