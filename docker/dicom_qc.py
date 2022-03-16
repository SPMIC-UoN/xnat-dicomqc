import os
import sys
import csv
import types
import datetime
import requests
import json

import pydicom

FLOAT_TOLERANCE = 0.001
KNOWN_VENDORS = ["philips", "siemens", "ge"]

def check_float(parameter, value, operator, expected):
    value = float(value)
    if operator == "==":
        # Compare floats to the number of decimal places given in the expected value
        if "." in expected:
            num_dps = len(expected[expected.index(".")+1:].strip())
        else:
            num_dps = 0
        return abs(round(value, num_dps) - round(float(expected), num_dps)) < FLOAT_TOLERANCE
    elif operator == "range":
        expected = [float(v) for v in expected.strip("[]").split(",")]
        return value >= expected[0] and value <= expected[1]

def check_int(parameter, value, operator, expected):
    value = int(value)
    if operator == "==":
        return value == int(expected)
    elif operator == "range":
        expected = [int(v) for v in expected.strip("[]").split(",")]
        return value >= expected[0] and value <= expected[1]

def check_str(parameter, value, operator, expected):
    if operator == "==":
        return str(value) == expected

def check_list(parameter, value, operator, expected):
    expected = [int(v) for v in expected.strip("[]").split(",")]
    if operator == "==":
        return value == expected

def check_multival(parameter, value, operator, expected):
    pass

TYPE_HANDLERS = {
    pydicom.valuerep.DSfloat : check_float,
    pydicom.valuerep.IS : check_int,
    list : check_list,
    pydicom.multival.MultiValue : check_multival,
    int : check_int,
    float : check_float,
    str: check_str,
}

def check_value(parameter, actual, operator, expected, scan_results):
    """
    Check if the value of a parameter matches the specified test
    """
    t = type(actual)
    check = f"{parameter} {actual} {operator} {expected}"

    if t in TYPE_HANDLERS:
        if operator == "or":
            possibles = [v for v in expected.strip("[]").split(",")]
            result = any([TYPE_HANDLERS[t](parameter, actual, "==", possible) for possible in possibles])
        else:
            result = TYPE_HANDLERS[t](parameter, actual, operator, expected)
       
        if result is None:
            print(f"   - {check}: NO RESULT")
            scan_results["warnings"].add(f"No result for {check}")
        elif result:
            print(f"   - {check}: PASS")
            scan_results["passes"].add(check)
        else:
            print(f"   - {check}: FAIL")
            scan_results["fails"].add(check)
    else:
        scan_results["warnings"].add(f"No handler for data type {t} parameter {parameter}")

def tag_from_text(txt):
    ids = txt.strip("(").strip(")").split(",")
    if len(ids) != 2:
        print("WARN: Invalid tag: %s" % txt)
        return None
    return (int(ids[0], 16), int(ids[1], 16))

def find_tag(ds, tag):
    """
    Find a tag in the data set, allowing for
    nested tags
    """
    for elem in ds:
        if elem.VR == 'SQ':
            for sub_ds in elem.value:
                sub_elem = find_tag(sub_ds, tag)
                if sub_elem:
                    return sub_elem
        else:
            if elem.tag == tag:
                return elem

def get_known_vendor(vendor_str):
    """
    Get the vendor name in standard form. Returns
    None if no matching vendor
    """
    vendor_str = vendor_str.strip().lower()
    for v in KNOWN_VENDORS:
        if v in vendor_str:
            return v

def series_matches(series_desc, series_names):
    """
    See if the series description matches any of a list of series substrings
    """
    for name in series_names:
        return name in series_desc

def check_file(dcm, qc_conf, scan_results):
    """
    Check a DICOM file against the configuration
    """
    series_desc = dcm[(0x0008, 0x103e)].value.lower()
    print(f"   - Series description: {series_desc}")
    scan_results["type"] = series_desc.upper()
    matches = 0
    for conf in qc_conf:
        if not series_matches(series_desc, conf.series_names):
            continue
        matches += 1
        found = False
        for key in conf.tags:
            if not key:
                continue
            actual = find_tag(dcm, key)
            if not actual:
                continue
            found = True
            if actual.value is None:
                scan_results["warnings"].add(f"'None' value for parameter: {conf.parameter}, tag: {key} in {fname}")
                continue
            check_value(conf.parameter, actual.value, conf.operator, conf.expected, scan_results)
        if not found:
            scan_results["warnings"].add(f"No matching value to check for {conf.parameter}")
    if matches == 0:
        scan_results["warnings"].add(f"No matching checks for series type {series_desc}")

def check_session(sessiondir, qc_conf):
    """
    Check a scan session against configuration
    """
    scan_results = []
    print(f"Checking session from {sessiondir}")
    scansdir = [d for d in os.listdir(sessiondir) if d.lower() == "scans"]
    if len(scansdir) != 1:
        raise RuntimeError(f"ERROR: Expected single scan dir, got {scansdir}")
    scansdir = os.path.join(sessiondir, scansdir[0])

    for scan in os.listdir(scansdir):
        scandir = os.path.join(scansdir, scan, "DICOM")
        if not os.path.isdir(scandir):
            print(f" - WARN: No DICOMs for scan {scan}")
            continue

        for fname in os.listdir(scandir):
            fpath = os.path.join(scandir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with pydicom.dcmread(fpath) as dcm:
                    vendor_str = dcm[(0x0008, 0x0070)].value
                    vendor = get_known_vendor(vendor_str)
                    if vendor not in qc_conf:
                        print(f" - WARN: Vendor {vendor} not found in QC config for {fname}")
                    else:
                        print(f" - Checking DICOM file: {fname} for vendor {vendor}")
                        scan_checks = {"id" : scan, "passes" : set(), "fails" : set(), "warnings" : set()}
                        check_file(dcm, qc_conf[vendor], scan_checks)
                        scan_results.append(scan_checks)
            except pydicom.errors.InvalidDicomError:
                print(f" - WARN: {fname} for scan {scan} was not a DICOM file")
    return scan_results

XML_HEADER = """<?xml version="1.0" encoding="UTF-8"?>
<DICOMQCData xmlns="http://github.com/spmic-uon/xnat-dicomqc" xmlns:xnat="http://nrg.wustl.edu/xnat" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <xnat:label>DICOMQC</xnat:label>
  <dicomqcVersion>0.0.1</dicomqcVersion>
"""

XML_FOOTER = """
</DICOMQCData>
"""

def make_xml(scan_results):
    """
    Create XML assessor document
    """
    xml = XML_HEADER
    xml += "  <xnat:date>%s</xnat:date>\n" % datetime.datetime.today().strftime('%Y-%m-%d')
    overall_pass = not any([scan["fails"] for scan in scan_results])
    if overall_pass:
        xml += "  <overall_status>PASS</overall_status>\n"
    else:
        xml += "  <overall_status>FAIL</overall_status>\n"

    for scan in scan_results:
        xml += "  <scan>\n"
        xml += f"    <scan_id>{scan['id']}</scan_id>\n"
        xml += f"    <scan_type>{scan['type']}</scan_type>\n"
        for passed_test in scan["passes"]:
            text = passed_test.replace("<", "[").replace(">", "]")
            xml += f"    <passed_test>{text}</passed_test>\n"
        for warning in scan["warnings"]:
            text = warning.replace("<", "&lt;")
            xml += f"    <warning>{text}</warning>\n"
        for failed_test in scan["fails"]:
            text = failed_test.replace("<", "&lt;")
            xml += f"    <failed_test>{text}</failed_test>\n"
        xml += "  </scan>\n"
    xml += XML_FOOTER
    return xml

def upload_xml(xml):
    """
    Upload new assessor to XNAT

    FIXME delete if already exists
    """
    host, user, password = os.environ["XNAT_HOST"], os.environ["XNAT_USER"], os.environ["XNAT_PASS"]
    print(f"Uploading XML to {host}")
    print(xml)
    proj, subj, exp = sys.argv[3:]
    #host = host.replace("http://", "https://") # FIXME hack
    os.environ["CURL_CA_BUNDLE"] = "" # FIXME Hack for cert validation disable
    with open("temp.xml", "w") as f:
        f.write(xml)
        
    with open("temp.xml", "r") as f:
        files = {'file': f}
        r = requests.post("%s/data/projects/%s/subjects/%s/experiments/%s/assessors/" % (host, proj, subj, exp), files=files, auth=(user, password))
        if r.status_code != 200:
            sys.stderr.write(xml)
            raise RuntimeError(f"Failed to create assessor: {r.text}")

def get_alias():
    """
    Get user alias token FIXME not necessary and not currently used?
    """
    r = requests.get("%s/data/services/tokens/issue" % os.environ["XNAT_HOST"], auth=(os.environ["XNAT_USER"], os.environ["XNAT_PASS"]))
    if r.status_code != 200:
        print("Error getting alias: ", r.text)
        sys.exit(1)
    else:
        result = json.loads(r.text)
        print(result)
        return result["alias"], result["secret"]

def read_config(fname):
    """
    Read TSV configuration file
    """
    qc_conf = {}
    with open(fname, "r") as f:
        qc_conf_tsv = csv.reader(f,delimiter="\t")
        next(qc_conf_tsv) # Skip header row
        for row in qc_conf_tsv:
            conf = types.SimpleNamespace()
            conf.tags = [tag_from_text(t) for t in row[3].split("/")]
            conf.series_names = [n.strip().lower() for n in row[0].split(",")]
            conf.parameter = row[4]
            conf.operator = row[5]
            conf.expected = row[6]
            conf.read = row[7]

            vendors = [v.strip().lower() for v in row[1].split(",")]
            if len(vendors) == 1 and vendors[0] =="":
                # Applies to all vendors
                vendors = KNOWN_VENDORS
            for vendor_str in vendors:
                vendor = get_known_vendor(vendor_str)
                if vendor:
                    if vendor not in qc_conf:
                        qc_conf[vendor] = []
                    qc_conf[vendor].append(conf)
                else:
                    print(f"WARN: Unrecognized vendor in configuration file: {vendor_str}")

    print(qc_conf.keys())
    return qc_conf

def main():
    if len(sys.argv) != 6:
        sys.stderr.write("Usage: dicom_qc.py <indir> <conf_fname> <project id> <subject id> <session id>\n")
        sys.exit(1)
    indir = sys.argv[1]
    config_fname = sys.argv[2]
    qc_conf = read_config(config_fname)

    found_session = False
    for path, dirs, files in os.walk(indir):
        if "scans" in [d.lower() for d in dirs]:
            if not found_session:
                found_session = True
                session_results = check_session(path, qc_conf)
                xml = make_xml(session_results)
                upload_xml(xml)
            else:
                print("WARN: Found another session: {path} - ignoring")

if __name__ == "__main__":
    main()
