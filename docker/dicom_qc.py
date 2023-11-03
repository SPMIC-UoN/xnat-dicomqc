"""
DICOM_QC: Simple DICOM based quality control for XNAT MR sessions
"""
import argparse
from collections import OrderedDict
import csv
import types
import datetime
import logging
import os
import sys
import traceback

LOG = logging.getLogger(__name__)

import pandas as pd
import pydicom
import xnat_nott

FLOAT_TOLERANCE = 0.001
KNOWN_VENDORS = ["philips", "siemens", "ge"]
IGNORE_SCAN = 0

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        argparse.ArgumentParser.__init__(self, prog="dicomqc", add_help=False, **kwargs)
        self.add_argument("--input", help="Input directory")
        self.add_argument("--config", help="Config file name")
        self.add_argument("--session", help="XNAT session")

def expected_num_sf(floatstr):
    """
    :return: Number of significant figures specified by a floating point
             number in a string, e.g. '1.43' would return 3
    """
    return len(floatstr.strip().replace(".", "").replace("-", "").lstrip("0"))

def float_matches(f1, f2, num_sf):
    """
    :return: True if f1 and f2 are the same to within num_sf significant figures
    """
    f1 = float(('%.' + str(num_sf) + 'g') % f1)
    f2 = float(('%.' + str(num_sf) + 'g') % f2)
    return abs(f1 - f2) < FLOAT_TOLERANCE

def check_float(value, operator, expected):
    """
    Check if a floating point parameter passes a check

    :param value: Floating point number
    :param operator: Type of test, == for equality to within a number of SF to be determined,
                     range for within a certain max/min range, and contain for values within
                     an arithmetic progression
    :param expected: Expected value(s) as a string. Either a float whose number of SF 
                     determines the number of SF we will test to, or a sequence of two
                     numbers for contain and range

    :return: True if value passes the test, False otherwise
    """
    if operator == "==":
        # Compare floats to the number of decimal places given in the expected value
        num_sf = expected_num_sf(expected)
        return float_matches(value, float(expected), num_sf)
    elif operator == "range":
        expected = [float(v) for v in expected.strip("[]").split(",")]
        return value >= expected[0] and value <= expected[1]
    elif operator == "contain":
        # Tricky when values are in separate files. Define sequence from expected and 
        # see if value is in sequence
        expected = [v for v in expected.strip("[]").split(",")]
        num_sf = max([expected_num_sf(v) for v in expected])
        expected = [float(v) for v in expected]
        s0 = expected[0]
        sd = expected[1] - expected[0]
        n = round((value - s0) / sd)
        if float_matches(value, s0+n*sd, num_sf):
            return True
        else:
            return False

def check_int(value, operator, expected):
    """
    Check if an integer parameter passes a test

    :param value: Integer
    :param operator: Type of test, == for equality, range for within a certain max/min range
    :param expected: Expected value(s) as a string. Either an integer or a sequence of two
                     integers for range

    :return: True if value passes the test, False otherwise
    """
    if operator == "==":
        return value == int(expected)
    elif operator == "range":
        expected = [int(v) for v in expected.strip("[]").split(",")]
        return value >= expected[0] and value <= expected[1]

def check_str(value, operator, expected):
    """
    Check if a string passes a test

    :param value: Integer
    :param operator: Type of test, currently only == for equality is supported
    :param expected: Expected value

    :return: True if value passes the test, False otherwise
    """
    if operator == "==":
        return value == expected

def check_list(value, operator, expected):
    """
    Check if a list passes a test

    :param value: List of floating point numbers
    :param operator: Type of test, == for equality to within a number of SF to be determined,
                     range for within a certain max/min range, and contain for values within
                     an arithmetic progression
    :param expected: Expected value(s) as a string. Either a float whose number of SF 
                     determines the number of SF we will test to, or a sequence of two
                     numbers for contain and range

    :return: True if value passes the test, False otherwise
    """
    expected = expected.strip("[]").split(",")
    num_sf = max([expected_num_sf(v) for v in expected])
    expected = [float(v) for v in expected]
    if operator == "==":
        for v1, v2 in zip(value, expected):
            if not float_matches(v1, v2, num_sf):
                return False
        return True
    elif operator == "range":
        for v in value:
            # We will ignore zeros as this seems common for this type of check
            if v >= FLOAT_TOLERANCE and v < expected[0] or v > expected[1]:
                return False
        return True
    elif operator == "contain":
        # Look for the specified values in the series
        for v in expected:
            if all([not float_matches(v, v2, num_sf) for v2 in value]):
                return False
        return True

TYPE_HANDLERS = {
    list : check_list,
    int : check_int,
    float : check_float,
    str: check_str,
}

def check_value(parameter, actual, operator, expected, scan_results, is_warning):
    """
    Check if the value of a parameter matches the specified test

    :param parameter: Name of parameter
    :param actual: Actual value in native Python type (int, float, list etc)
    :param operator: Operator (==, contain, range)
    :param expected: Expected value(s) expressed as a string (possibly containing a sequence)
    :param scan_results: Scan results dictionary to be updated with result of test
    :param is_warning: If True, failure is to be treated as a warning
    """
    t = type(actual)
    check = f"{parameter} {actual} {operator} {expected}"

    if t in TYPE_HANDLERS:
        if operator == "or":
            possibles = [v for v in expected.strip("[]").split(",")]
            result = any([TYPE_HANDLERS[t](actual, "==", possible) for possible in possibles])
        else:
            result = TYPE_HANDLERS[t](actual, operator, expected)

        if result is None:
            scan_warning(f"No result for {check} type {t}", scan_results)
        elif result:
            scan_pass(check, scan_results)
        elif is_warning:
            scan_warning(check, scan_results)
        else:
            scan_fail(check, scan_results)
    else:
        LOG.warning(f"No handler for data type {t} parameter {parameter} '{actual}'".replace("<", "[").replace(">", "]"))
        scan_results["warnings"].add(f"No handler for data type {t} parameter {parameter}")

def scan_pass(check, scan_results):
    if check not in scan_results["passes"]:
        LOG.info(f"   - PASS: {check}")
        scan_results["passes"].add(check)

def scan_fail(check, scan_results):
    if check not in scan_results["fails"]:
        LOG.info(f"   - FAIL: {check}")
        scan_results["fails"].add(check)

def scan_warning(warning, scan_results):
    if warning not in scan_results["warnings"]:
        LOG.info(f"   - WARN: {warning}")
        scan_results["warnings"].add(warning)

def tag_from_text(txt):
    """
    Turn text representing a DICOM tag into a tuple of integers 
    for matching against pydicom structure
    """
    txt = txt.lower().strip()
    if txt == "ignore":
        # 'ignore' is a special key which means matching scans should not be checked
        return (IGNORE_SCAN, IGNORE_SCAN)
    ids = txt.strip("(").strip(")").split(",")
    if len(ids) != 2:
        LOG.warning("Invalid tag: %s" % txt)
        return None
    return (int(ids[0], 16), int(ids[1], 16))

def find_tag(ds, tag):
    """
    Find a tag in the data set, allowing for nested tags
    """
    vals = []
    for elem in ds:
        if elem.VR == 'SQ':
            for sub_ds in elem.value:
                sub_elem = find_tag(sub_ds, tag)
                if sub_elem:
                    vals.append(sub_elem)
        else:
            if elem.tag == tag:
                vals.append(elem)
    if len(vals) == 0:
        return None
    elif len(vals) == 1: return vals[0]
    elif all([i == vals[0] for i in vals]): return vals[0]
    else:
        ret = types.SimpleNamespace()
        ret.value = list(set([i.value for i in vals]))
        ret.VR = vals[0].VR
        return ret

def get_known_vendor(vendor_str):
    """
    Get the vendor name in standard form. Returns
    None if no matching vendor
    """
    vendor_str = vendor_str.strip().lower()
    for v in KNOWN_VENDORS:
        if v in vendor_str:
            return v

def series_matches(series_desc, series_match, series_exclude):
    """
    See if the series description matches any of a list of series substrings
    """
    match = False
    for substr in series_match:
        if substr and substr in series_desc:
            match = True
            break
    for substr in series_exclude:
        if substr and substr in series_desc:
            match = False
            break
    return match

def convert_value(dcm_value, vr):
    """
    Convert a dicom string value into a native Python
    type depending on the DICOM VR (Value Representation)
    """
    if vr in ("DS", "FL", "FD"):
        return float(dcm_value)
    elif vr in ("IS", "LO", "SH", "US"):
        return int(dcm_value)
    elif vr == "UN":
        # tricky
        import struct
        try:
            return struct.unpack('f', dcm_value)[0]
        except:
            return int(dcm_value)
    else:
        LOG.warning("Unrecognized DICOM type", vr, dcm_value, type(dcm_value))

def convert_type(elem):
    """
    Convert a dicom string value into a native Python
    type depending on both its given type and the Value Representation value
    """
    try:
        dcm_type = type(elem.value)
        if elem.value is None:
            return None
        elif dcm_type in (int, float, str):
            return elem.value
        elif dcm_type == list:
            return [convert_value(v, elem.VR) for v in elem.value]
        elif dcm_type == pydicom.valuerep.DSfloat:
            return float(elem.value)
        elif dcm_type == pydicom.valuerep.IS:
            return int(elem.value)
        elif dcm_type == pydicom.multival.MultiValue:
            return [convert_value(v, elem.VR) for v in elem.value]
        else:
            return convert_value(elem.value, elem.VR)
    except Exception as exc:
        LOG.warning(f"Failed to convert DCM value: {dcm_type} {elem.value} {elem.VR} {exc}")
        return None

def check_file(dcm, std_name, checks, scan_results):
    """
    Check a DICOM file against the configuration
    """
    matched_checks = 0
    for check in checks:
        if not series_matches(std_name, check.series_match, check.series_exclude):
            continue
        matched_checks += 1
        found_tag = False
        for key in check.tags:
            if not key:
                continue
            tag_value = find_tag(dcm, key)
            if not tag_value:
                continue
            found_tag = True
            value = convert_type(tag_value)
            if value is None:
                scan_warning(f"'None' value for parameter: {check.parameter}, tag: {key}", scan_results)
                continue
            check_value(check.parameter, value, check.operator, check.expected, scan_results, check.is_warning)
        if not found_tag:
            scan_warning(f"No matching DICOM tag found for {check.parameter}", scan_results)
    if matched_checks == 0:
        scan_warning(f"No matching checks", scan_results)
    return True

def check_session(sessiondir, vendor_series_mapping, vendor_checks):
    """
    Check a scan session against configuration
    """
    session_results = OrderedDict()
    LOG.info(f"Checking session from {sessiondir}")
    scansdir = [d for d in os.listdir(sessiondir) if d.lower() == "scans"]
    if len(scansdir) != 1:
        raise RuntimeError(f"ERROR: Expected single scan dir, got {scansdir}")
    scansdir = os.path.join(sessiondir, scansdir[0])

    for scan in os.listdir(scansdir):
        LOG.info(f" - Checking {scan}")

        scandir = os.path.join(scansdir, scan, "DICOM")
        if not os.path.isdir(scandir):
            LOG.warning(f"   - No DICOMs")
            continue

        scan_results = {"id" : scan, "passes" : set(), "fails" : set(), "warnings" : set()}
        vendor, std_name = None, None
        ignore_scan = False

        for fname in os.listdir(scandir):
            fpath = os.path.join(scandir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with pydicom.dcmread(fpath) as dcm:
                    if not vendor:
                        vendor_str = dcm[(0x0008, 0x0070)].value
                        vendor = get_known_vendor(vendor_str)
                        series_mappings = vendor_series_mapping[vendor]
                        checks = vendor_checks[vendor]
                        if vendor not in vendor_series_mapping or vendor not in vendor_checks:
                            LOG.warning(f" - WARN: Vendor {vendor} not found in config for {fname}")
                            ignore_scan = True
                            break

                    if not std_name:
                        series_desc = "_".join(dcm[(0x0008, 0x103e)].value.lower().split())
                        LOG.info(f"   - Series description: {series_desc}")
                        scan_results["type"] = series_desc.upper()
                        for mapping in series_mappings:
                            if series_matches(series_desc, [mapping.series_match], [mapping.series_exclude]):
                                std_name = mapping.std_name
                                break
                        if std_name is None:
                            scan_warning("No standardized name found for scan - ignoring", scan_results)
                            ignore_scan = True
                            break
                        if std_name == "":
                            LOG.info("   - Scan explicitly ignored in config")
                            ignore_scan = True
                            break
                        LOG.info(f"   - Standardized name: {std_name}")
                        scan_results["std_name"] = std_name

                    LOG.info(f"   - Checking DICOM: {fname} for vendor {vendor}")
                    check_file(dcm, std_name, checks, scan_results)
            except pydicom.errors.InvalidDicomError:
                LOG.warning(f"   - {fname} for scan {scan} was not a DICOM file")

        if not ignore_scan:
            session_results[scan] = scan_results
    return session_results

def normalise_session(session_results):
    """
    Remove failed scans from session results if there is a passing scan of the same standard name
    """
    passing_scan_types = set([r["std_name"] for r in session_results.values() if not r["fails"]])
    LOG.info(" - Scan types with passes: %s" % ",".join(passing_scan_types))
    normed_results = {}
    for scan_id, scan_results in session_results.items():
        std_name = scan_results["std_name"]
        LOG.info(" - Scan %s has %i fails and std name %s" % (scan_id, len(scan_results["fails"]), std_name))
        if scan_results["fails"] and std_name in passing_scan_types:
            LOG.info(f" - Ignoring scan {scan_id} as we already have a pass for standardized type {std_name}")
            continue
        normed_results[scan_id] = scan_results
    return normed_results

XML_HEADER = """<?xml version="1.0" encoding="UTF-8"?>
<DICOMQCData xmlns="http://github.com/spmic-uon/xnat-dicomqc" xmlns:xnat="http://nrg.wustl.edu/xnat" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dicomqcVersion>0.0.1</dicomqcVersion>
"""

XML_FOOTER = """
</DICOMQCData>
"""

def make_xml(session_results, args):
    """
    Create XML assessor document
    """
    xml = XML_HEADER
    xml += "  <xnat:label>DICOMQC_%s</xnat:label>" % args.session
    xml += "  <xnat:date>%s</xnat:date>\n" % datetime.datetime.today().strftime('%Y-%m-%d')
    overall_pass = not any([scan["fails"] for scan in session_results.values()])
    if overall_pass:
        xml += "  <overall_status>PASS</overall_status>\n"
    else:
        xml += "  <overall_status>FAIL</overall_status>\n"

    for scan in session_results.values():
        xml += "  <scan>\n"
        xml += f"    <scan_id>{scan['id']}</scan_id>\n"
        xml += f"    <scan_type>{scan['type']}</scan_type>\n"
        #xml += f"    <std_name>{scan['std_name']}</std_name>\n"
        for passed_test in scan["passes"]:
            text = passed_test.replace("<", "[").replace(">", "]")[:200]
            xml += f"    <passed_test>{text}</passed_test>\n"
        for warning in scan["warnings"]:
            text = warning.replace("<", "&lt;").replace(">", "]")[:200]
            xml += f"    <warning>{text}</warning>\n"
        for failed_test in scan["fails"]:
            text = failed_test.replace("<", "&lt;").replace(">", "]")[:200]
            xml += f"    <failed_test>{text}</failed_test>\n"
        xml += "  </scan>\n"
    xml += XML_FOOTER
    return xml

def upload_xml(xml, args):
    """
    Upload new assessor to XNAT
    """
    with open("temp.xml", "w") as f:
        f.write(xml)
    LOG.info(f"Uploading XML to {args.host}")
    LOG.info(xml)
    url = "data/projects/%s/subjects/%s/experiments/%s/assessors/" % (args.project, args.subject, args.session)
    xnat_nott.xnat_upload(args, url, "temp.xml", replace_assessor=f"DICOMQC_{args.session}")

def _get_vendor_list(vendors_str):
    vendors =  [v.strip().lower() for v in vendors_str.split(",")]
    vendor_list = []
    if len(vendors) == 1 and vendors[0] =="":
        # Applies to all vendors
        vendors = KNOWN_VENDORS
    for vendor_str in vendors:
            vendor = get_known_vendor(vendor_str)
            if vendor:
                vendor_list.append(vendor)
            else:
                LOG.warning(f"Unrecognized vendor in configuration file: {vendor_str}")
    return vendor_list

def read_excel_config(fname):
    sheets = pd.read_excel(fname, sheet_name=[0, 1], dtype=str)
        
    # Read series name mapping
    #
    # There is a configuration for each vendor. The configuration
    # is a dictionary from substring series description matcher
    # to 'standard' name. The checks worksheet is then specified
    # in terms of 'standard' names to get around different naming
    # conventions for different vendors
    series_name_config = sheets[0].fillna('')
    vendor_series_mapping = {}
    std_names = set()
    LOG.info(series_name_config)
    for index, row in series_name_config.iterrows():
        LOG.info(row)
        series_match = "_".join(row[0].strip().lower().split())
        series_exclude = "_".join(row[1].strip().lower().split())
        vendors = _get_vendor_list(row[2])
        std_name = row[3].strip().lower()
        std_names.add(std_name)

        for vendor in vendors:
            if vendor not in vendor_series_mapping:
                vendor_series_mapping[vendor] = []
            mapping = types.SimpleNamespace()
            mapping.series_match = series_match
            mapping.series_exclude = series_exclude
            mapping.std_name = std_name
            vendor_series_mapping[vendor].append(mapping)

    LOG.info(vendor_series_mapping.keys())

    # Read list of checks
    #
    # There is a list of checks for each vendor. Each check is an
    # object with attributes series_match, series_exclude,
    # version, tags, parameter, operator, expected, read
    checks_config = sheets[1].fillna('')
    vendor_checks = {}
    for index, row in checks_config.iterrows():
        check = types.SimpleNamespace()
        check.series_match = [n.strip().lower() for n in row[0].split(",") if n.strip() != ""]
        check.series_exclude = [n.strip().lower() for n in row[1].split(",") if n.strip() != ""]
        vendors = _get_vendor_list(row[2])
        check.version = row[3].strip().lower()
        check.tags = [tag_from_text(t) for t in row[4].split("/")]
        check.parameter = row[5]
        check.operator = row[6]
        check.expected = row[7]
        check.read = row[8]
        check.is_warning = row[9].strip().upper() == "WARNING"
    
        for vendor in vendors:
            if vendor not in vendor_checks:
                vendor_checks[vendor] = []
            vendor_checks[vendor].append(check)

        for name in check.series_match + check.series_exclude:
            if all([name not in std_name for std_name in std_names]):
                LOG.warning(f"Unmatched series name in checks: {name}")

    return vendor_series_mapping, vendor_checks
        
def get_qc_conf(args):
    local_fname = args.config
    if not local_fname:
        LOG.info("Downloading config from XNAT")
        url = "data/projects/%s/resources/dicomqc/files/dicomqc_conf.xlsx" % args.project
        local_fname = "downloaded_config.xlsx"
        xnat_nott.xnat_download(args, url, local_fname=local_fname)

    return read_excel_config(local_fname)

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
            conf.series_names = [n.strip().lower() for n in row[0].split(",") if n.strip() != ""]
            conf.series_exclusions = [n.strip().lower() for n in row[1].split(",") if n.strip() != ""]
            vendors = [v.strip().lower() for v in row[2].split(",")]
            conf.version = row[3].strip().lower()
            conf.tags = [tag_from_text(t) for t in row[4].split("/")]
            conf.parameter = row[5]
            conf.operator = row[6]
            conf.expected = row[7]
            conf.read = row[8]
            # Handle vendor list
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
                    LOG.warning(f"Unrecognized vendor in configuration file: {vendor_str}")

    return qc_conf

def main():
    """
    Main script entry poin
    """
    args = ArgumentParser().parse_args()
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    
    if not os.path.isdir(args.input):
        LOG.error(f"Input directory {args.input} not specified or does not exist")
        sys.exit(1)

    try:
        with open("version.txt") as f:
            version = f.read()
    except IOError:
        version = "(unknown)"

    LOG.info(f"DICOMQC v{version}")

    xnat_nott.get_host_url(args)
    xnat_nott.get_credentials(args)
    xnat_nott.xnat_login(args)
    proj, subj, _sess = xnat_nott.get_all_from_session_id(args, args.session)
    args.project = proj['ID']
    args.subject = subj['ID']
    print(f" - Session: {args.session}")
    print(f" - Subject: {args.subject}")
    print(f" - Project: {args.project}")

    vendor_series_mapping, vendor_checks = get_qc_conf(args)

    found_session = False
    for path, dirs, files in os.walk(args.input):
        if "scans" in [d.lower() for d in dirs]:
            if not found_session:
                found_session = True
                session_results = check_session(path, vendor_series_mapping, vendor_checks)
                session_results = normalise_session(session_results)
                xml = make_xml(session_results, args)
                try:
                    upload_xml(xml, args)
                except:
                    LOG.error("Failed to upload XML")
                    LOG.error(xml)
                    traceback.print_exc()
            else:
                LOG.warning("Found another session: {path} - ignoring")

if __name__ == "__main__":
    main()
