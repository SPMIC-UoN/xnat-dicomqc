import os
import sys
import csv
import types

import pydicom

FLOAT_TOLERANCE = 0.001
VENDORS = ["philips", "siemens", "ge"]

def tag_from_text(txt):
    ids = txt.strip("(").strip(")").split(",")
    if len(ids) != 2:
        print("WARN: Invalid tag: %s" % txt)
        return None
    return (int(ids[0], 16), int(ids[1], 16))

def check_float(parameter, value, operator, expected):
    value = float(value)
    if operator == "==":
        return abs(value - float(expected)) < FLOAT_TOLERANCE
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
    print(" - checking multival")

def series_matches(dcm, series_names):
    series_desc = dcm[(0x0008, 0x103e)].value.lower()
    for name in series_names:
        return name in series_desc

def find_tag(ds, tag):
    #print("looking for ", tag)
    for elem in ds:
        #print(elem, type(elem), dir(elem))
        #print(elem.tag)
        if elem.VR == 'SQ':
            #print("seq", type(elem))
            for sub_ds in elem.value:
                sub_elem = find_tag(sub_ds, tag)
                if sub_elem:
                    return sub_elem
        else:
            #print(elem.tag, elem.value)
            if elem.tag == tag:
                return elem

def check_file(dcm, vendor, qc_conf, scan_results):
    #print(dcm)
    print(f" - Series description: {dcm[(0x0008, 0x103e)].value}")
    matches = 0
    for conf in qc_conf[vendor]:
        if not series_matches(dcm, conf.series_names):
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
                print(f" - WARN: 'None' value for parameter: {conf.parameter}, tag: {key} in {fname}")
                continue
            t = type(actual.value)
            check = f"{conf.parameter} {actual.value} {conf.operator} {conf.expected}"
            if t in TYPE_HANDLERS:
                if TYPE_HANDLERS[t](conf.parameter, actual.value, conf.operator, conf.expected):
                    print(check, "PASS")
                    scan_results["passes"].add(check)
                else:
                    print(check, "FAIL")
                    scan_results["fails"].add(check)
            else:
                print(f" - WARN: No handler for {t} (parameter: {conf.parameter}, tag: {key}")
        if not found:
            print(f" - WARN: No matching value to check for {conf.parameter}")
    if matches == 0:
        print(" - WARN: No matching checks for this series type")

def read_config(fname):
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
            for vendor in vendors:
                if vendor not in qc_conf:
                    qc_conf[vendor] = []
                qc_conf[vendor].append(conf)
    return qc_conf

def read_series_config(fname):
    series_regexes = {}
    with open(fname, "r") as f:
        series_conf = csv.reader(f,delimiter="\t")
        next(series_conf) # Skip header row
        for row in series_conf:
            vendors = [v.strip().lower() for v in row[1].split(",")]
            for vendor in vendors:
                if vendor not in series_regexes:
                    series_regexes[vendor] = []

            #print(row)

def get_vendor(dcm):
    vendor = dcm[(0x0008, 0x0070)].value.strip().lower()
    for v in VENDORS:
        if v in vendor:
            return v

TYPE_HANDLERS = {
    pydicom.valuerep.DSfloat : check_float,
    pydicom.valuerep.IS : check_int,
    list : check_list,
    pydicom.multival.MultiValue : check_multival,
    int : check_int,
    float : check_float,
    str: check_str,
}

def check_session(sessiondir, qc_conf):
    scan_results = []
    scansdir = [d for d in os.listdir(sessiondir) if d.lower() == "scans"]
    if len(scansdir) != 1:
        sys.stderr.write(f"ERROR: Expected single scan dir, got {scansdir}\n")
        sys.exit(1)
    scansdir = os.path.join(sessiondir, scansdir[0])

    for scan in os.listdir(scansdir):
        scan_checks = {"id" : scan, "passes" : set(), "fails" : set()}
        scandir = os.path.join(scansdir, scan, "DICOM")
        print(scandir, os.listdir(scandir))
        for fname in os.listdir(scandir):
            fpath = os.path.join(scandir, fname)
            if not os.path.isfile(fpath):
                continue
            print(fname)
            try:
                with pydicom.dcmread(fpath) as dcm:
                    vendor = get_vendor(dcm)
                    if vendor not in qc_conf:
                        print(f"WARN: Vendor {vendor} not found in QC config")
                    else:
                        print(f"Checking file: {fname} for vendor {vendor}")
                        check_file(dcm, vendor, qc_conf, scan_checks)
            except pydicom.errors.InvalidDicomError:
                print(f"WARN: File {fname} for scan {scan} was not a DICOM file")
        scan_results.append(scan_checks)
    return scan_results

XML_HEADER = """
<DICOMQCData xmlns="http://github.com/spmic-uon/xnat-hpc" xmlns:xnat="http://nrg.wustl.edu/xnat" xsi:schemaLocation="http://github.com/spmic-uon/xnat-hpc schema.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <xnat:label>DICOMQC</xnat:label>
  <dicomqcVersion>0.0.1</dicomqcVersion>
"""

XML_FOOTER = """
</DICOMQCData>
"""

def make_xml(scan_results):
    xml = XML_HEADER
    overall_pass = not any([scan["fails"] for scan in scan_results])
    if overall_pass:
        xml += "  <overall_status>PASS</overall_status>\n"
    else:
        xml += "  <overall_status>FAIL</overall_status>\n"

    for scan in scan_results:
        xml += "  <scan>\n"
        xml += f"    <scan_id>{scan['id']}</scan_id>\n"
        for passed_test in scan["passes"]:
            xml += f"    <passed_test>{passed_test}</passed_test>\n"
        for failed_test in scan["fails"]:
            xml += f"    <failed_test>{failed_test}</failed_test>\n"
        xml += "  </scan>\n"
    xml += XML_FOOTER
    return xml

def upload_xml(xml):
    proj, subj, exp = sys.argv[3:]
    #host = os.environ.get("XNAT_HOST").replace("http://", "https://") # hack
    #os.environ["CURL_CA_BUNDLE"] = "" # FIXME Hack for cert validation disable
    with open("temp.xml", "w") as f:
        f.write(xml)
    print('curl -u %s:%s -X POST "%s/data/projects/%s/subjects/%s/experiments/%s/assessors/" -F "file=@%s" -k' % (
        os.environ["XNAT_USER"], os.environ["XNAT_PASS"], os.environ["XNAT_HOST"], 
        proj, subj, exp, "temp.xml")
    )

def main():
    if len(sys.argv) != 6:
        sys.stderr.write("Usage: dicom_qc.py <indir> <conf_fname> <project id> <subject id> <session id>\n")
    indir = sys.argv[1]
    config_fname = sys.argv[2]
    #os.system(f"find {indir}")
    
    qc_conf = read_config(config_fname)
    sessions = os.listdir(indir)
    if len(sessions) != 1:
        sys.stderr.write(f"ERROR: Expected single session input, got {sessions}\n")
        sys.exit(1)
    sessiondir = os.path.join(indir, sessions[0])

    session_results = check_session(sessiondir, qc_conf)
    xml = make_xml(session_results)
    upload_xml(xml)

if __name__ == "__main__":
    main()
