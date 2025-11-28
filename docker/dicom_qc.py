"""
DICOM_QC: Simple DICOM based quality control for XNAT MR sessions
"""
import argparse
from collections import OrderedDict
import types
import datetime
import logging
import os
import sys
import re

LOG = logging.getLogger(__name__)

import pandas as pd
import pydicom
import xnat_nott

FLOAT_TOLERANCE = 0.001
KNOWN_VENDORS = ["philips", "siemens", "ge"]
IGNORE_SCAN = 0

XML_HEADER = """<?xml version="1.0" encoding="UTF-8"?>
<DICOMQCData xmlns="http://github.com/spmic-uon/xnat-dicomqc" xmlns:xnat="http://nrg.wustl.edu/xnat" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dicomqcVersion>0.0.1</dicomqcVersion>
"""

XML_FOOTER = """
</DICOMQCData>
"""

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        argparse.ArgumentParser.__init__(self, prog="dicomqc", add_help=True, **kwargs)
        self.add_argument("--input", help="Input directory. If not already populated, data will be downloaded from XNAT", required=True)
        self.add_argument("--config", help="Config file name")
        self.add_argument("--upload", help="Upload XML file to XNAT", action="store_true", default=False)
        self.add_argument("--project", help="XNAT project identifier")
        self.add_argument("--subject", help="XNAT subject identifier")
        self.add_argument("--session", help="XNAT session ID. If specified, project and subject IDs are not required")
        self.add_argument('--xnat', dest="host", help='xnat host URL. If not specified will use $XNAT_HOST environment variable')
        self.add_argument('--user', help='XNAT user name. If not specified will use credentials from $HOME.netrc or prompt for username')
        self.add_argument('--password', help='XNAT password. If not specified will use credentials from $HOME.netrc or prompt for password')


def main():
    """
    Main script entry poin
    """
    args = ArgumentParser().parse_args()
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    try:
        with open("version.txt") as f:
            version = f.read()
    except IOError:
        version = "(unknown)"

    LOG.info(f"DICOMQC v{version}")

    # Connect to XNAT and retrieve session info
    xnat_nott.get_host_url(args)
    xnat_nott.get_credentials(args)
    xnat_nott.xnat_login(args)
    if args.session and not args.project:
        proj, subj, sess = xnat_nott.get_all_from_session_id(args, args.session)
    else:
        proj = xnat_nott.get_project(args, args.project)
        subj = xnat_nott.get_subject(args, proj, args.subject)
        sess = xnat_nott.get_session(args, proj, subj, args.session)
    args.project = proj['ID']
    args.subject = subj['ID']
    LOG.info(f" - Session: {args.session}")
    LOG.info(f" - Subject: {args.subject}")
    LOG.info(f" - Project: {args.project}")

    # Read Excel configuration file
    vendor_series_mapping, vendor_checks = load_config(args)

    # Get DICOM data from XNAT if not already present
    if not args.input or not os.path.isdir(args.input) or not os.listdir(args.input):
        LOG.info("Input directory is empty or does not exist - downloading data from XNAT")
        xnat_nott.get_session_dicoms(args, sess["ID"], args.input)

    # Process the session scans
    found_session = False
    for path, dirs, files in os.walk(args.input):
        if "scans" in [d.lower() for d in dirs]:
            if not found_session:
                found_session = True
                session_results = check_session(path, vendor_series_mapping, vendor_checks)
                session_results = normalise_session(session_results)
                xml = make_xml(session_results, args)
                if args.upload:
                    try:
                        upload_xml(xml, args)
                    except:
                        LOG.error("Failed to upload XML")
                        LOG.error(xml)
            else:
                LOG.warning("Found another session: {path} - ignoring")


def load_config(args):
    local_fname = args.config
    if not local_fname:
        LOG.info("Downloading config file from XNAT")
        url = "data/projects/%s/resources/dicomqc/files/dicomqc_conf.xlsx" % args.project
        local_fname = "downloaded_config.xlsx"
        xnat_nott.xnat_download(args, url, local_fname=local_fname)

    vendor_series_name_mapping = parse_excel_config(local_fname, sheet=0)
    vendor_checks = parse_excel_config(local_fname, sheet=1)
    return vendor_series_name_mapping, vendor_checks


def parse_excel_config(fname, sheet=0):
    sheets = pd.read_excel(fname, sheet_name=[0, 1], dtype=str)

    # Read series name mapping
    #
    # There is a configuration for each vendor. The configuration
    # is a dictionary from substring series description matcher
    # to 'standard' name. The checks worksheet is then specified
    # in terms of 'standard' names to get around different naming
    # conventions for different vendors
    config = sheets[sheet].fillna('')
    vendor_series_mapping = {}

    LOG.debug(config)
    cols = {}
    for idx, colname in enumerate(config.columns):
        colname = colname.strip().lower()
        if "series" in colname and "exclude" not in colname and "exclusion" not in colname:
            cols["include"] = idx
            cols[idx] = "include"
        elif "series" in colname:
            cols["exclude"] = idx
            cols[idx] = "exclude"
        elif "vendor" in colname:
            cols["vendor"] = idx
            cols[idx] = "vendor"
        elif "tag" in colname:
            cols["tag"] = idx
            cols[idx] = "tag"
        elif "operator" in colname:
            cols["operator"] = idx
            cols[idx] = "operator"
        elif "expected" in colname:
            cols["expected"] = idx
            cols[idx] = "expected"
        elif "read" in colname:
            cols["read"] = idx
            cols[idx] = "read"
        elif "param" in colname:
            cols["parameter"] = idx
            cols[idx] = "parameter"
        elif "standard" in colname or "name" in colname:
            cols["name"] = idx
            cols[idx] = "name"
        elif "warn" in colname:
            cols["warn"] = idx
            cols[idx] = "warn"
        elif "index" in colname:
            cols["index"] = idx
            cols[idx] = "index"
        elif "if" in colname:
            cols["filter"] = idx
            cols[idx] = "filter"
        else:
            cols[idx] = None

    LOG.debug("Columns:")
    for col_idx in range(len(config.columns)):
        LOG.debug(f"  - {col_idx}: {cols[col_idx]}")

    for index, row in config.iterrows():
        if "vendor" in cols:
            vendors = [v.strip().lower() for v in row[cols["vendor"]].split(",")]
        else:
            vendors = [""]

        mapping = types.SimpleNamespace()
        # Comma separated list
        for col in ("include", "exclude"):
            if col in cols:
                setattr(mapping, col, [v.strip().lower() for v in row[cols[col]].split(",")])
            else:
                setattr(mapping, col, [])

        # Slash separated list
        for col in ("tag", "operator"):
            if col in cols:
                setattr(mapping, col, [v.strip().lower() for v in re.split(r"[\\/]", row[cols[col]])])
            else:
                setattr(mapping, col, [])

        # Single value
        for col in ("operator", "read", "parameter", "name", "filter", "expected", "warn", "index"):
            if col in cols:
                setattr(mapping, col,  row[cols[col]].strip().lower())
            else:
                setattr(mapping, col, "")

        for vendor in vendors:
            if vendor not in vendor_series_mapping:
                vendor_series_mapping[vendor] = []
            vendor_series_mapping[vendor].append(mapping)

    LOG.info(vendor_series_mapping.keys())
    return vendor_series_mapping

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
            scandir = os.path.join(scansdir, scan, "resources", "DICOM", "files")
            if not os.path.isdir(scandir):
                LOG.warning(f"   - No DICOMs")
                continue

        scan_results = {"id" : scan, "passes" : set(), "fails" : set(), "warnings" : set()}
        vendor, std_name = None, None
        ignore_scan = ""

        for fname in os.listdir(scandir):
            fpath = os.path.join(scandir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with pydicom.dcmread(fpath) as dcm:
                    if not vendor:
                        # Take vendor from first DICOM file
                        vendor_str = dcm[(0x0008, 0x0070)].value
                        vendor = get_known_vendor(vendor_str)
                        if vendor:
                            series_mappings = vendor_series_mapping.get(vendor, [])
                            checks = vendor_checks.get(vendor, [])
                        # Checks/mappings with no vendor specified apply to all vendors
                        series_mappings += vendor_series_mapping.get("", [])
                        checks += vendor_checks.get("", [])
                        if not checks or not series_mappings:
                            LOG.warning(f"   - No checks/mappings for vendor {vendor} ({vendor_str})")
                            ignore_scan = f"No checks found for vendor {vendor_str}"
                            break

                    if not std_name:
                        # Determine standardized name from series description of first DICOM file
                        series_desc = "_".join(dcm[(0x0008, 0x103e)].value.lower().split())
                        LOG.info(f"   - Series description: {series_desc}")
                        scan_results["type"] = series_desc.upper()
                        for mapping in series_mappings:
                            if series_matches(series_desc, mapping.include, mapping.exclude):
                                std_name = mapping.name
                                break
                        if not std_name:
                            ignore_scan = f"No standardized name found for {series_desc}"
                            break
                        LOG.info(f"   - Standardized name: {std_name}")
                        scan_results["std_name"] = std_name

                    LOG.debug(f"   - Checking DICOM: {fname} for vendor {vendor}")
                    check_file(dcm, std_name, checks, scan_results)
            except pydicom.errors.InvalidDicomError:
                LOG.warning(f"   - {fname} for scan {scan} was not a DICOM file")

        if not ignore_scan:
            LOG.info(f"   - {len(scan_results['passes'])} passes, {len(scan_results['fails'])} fails, {len(scan_results['warnings'])} warnings")
            session_results[scan] = scan_results
        else:
            LOG.info(f"   - Ignored ({ignore_scan})")
    return session_results

def check_file(dcm, name, checks, scan_results):
    """
    Check a DICOM file against the configuration
    """
    matched_checks = 0
    for check in checks:
        if not series_matches(name, check.include, check.exclude, exact=True):
            continue
        if not filter_matches(dcm, check.filter):
            continue

        matched_checks += 1
        found_tag = False
        for key in check.tag:
            if not key:
                LOG.warn(f"No tag for parameter check {check.parameter}")
                continue
            tag_value = find_tag(dcm, tag_from_text(key))
            if not tag_value:
                LOG.warn(f"Invalid tag for parameter {check.parameter}: {key}")
                continue
            found_tag = True
            value = convert_type(tag_value)
            if value is None:
                _scan_warning(f"'None' value for parameter: {check.parameter}, tag: {key}", scan_results)
                continue
            check_value(value, check, scan_results)
        if not found_tag:
            _scan_warning(f"No matching DICOM tag found for {check.parameter}", scan_results)
    if matched_checks == 0:
        _scan_warning(f"No matching checks", scan_results)
    return True


def check_value(actual, check, scan_results):
    """
    Check if the value of a parameter matches the specified test

    :param parameter: Name of parameter
    :param actual: Actual value in native Python type (int, float, list etc)
    :param operator: Operator (==, contain, range)
    :param expected: Expected value(s) expressed as a string (possibly containing a sequence)
    :param scan_results: Scan results dictionary to be updated with result of test
    :param is_warning: If True, failure is to be treated as a warning
    """    
    TYPE_HANDLERS = {
        list : _check_list,
        int : _check_int,
        float : _check_float,
        str: _check_str,
    }

    t = type(actual)
    check_txt = f"{check.parameter} {actual} {check.operator} {check.expected}"
    LOG.info(f"   - Checking: {check_txt}")
    if t in TYPE_HANDLERS:
        if check.operator == "or":
            possibles = [v for v in check.expected.strip("[]").split(",")]
            result = any([TYPE_HANDLERS[t](actual, "==", possible) for possible in possibles])
        else:
            result = TYPE_HANDLERS[t](actual, check.operator, check.expected, check.index)

        if result is None:
            _scan_warning(f"No result for {check_txt} type {t}", scan_results)
        elif result:
            _scan_pass(check_txt, scan_results)
        elif check.warn:
            _scan_warning(check_txt, scan_results)
        else:
            _scan_fail(check_txt, scan_results)
    else:
        LOG.warning(f"No handler for data type {t} parameter {check.parameter} '{actual}'".replace("<", "[").replace(">", "]"))
        scan_results["warnings"].add(f"No handler for data type {t} parameter {check.parameter}")


def normalise_session(session_results):
    """
    Remove failed scans from session results if there is a passing scan of the same standard name
    """
    LOG.info("Normalising session results")
    passing_scan_types = set([r["std_name"] for r in session_results.values() if not r["fails"]])
    #LOG.info(" - Scan types with all passes: %s" % ",".join(passing_scan_types))
    normed_results = {}
    for scan_id, scan_results in session_results.items():
        std_name = scan_results["std_name"]
        LOG.info(f" - {scan_id} ({std_name}): Pass {len(scan_results['passes'])}, Fail {len(scan_results['fails'])}")
        if scan_results["fails"] and std_name in passing_scan_types:
            LOG.info(f" - Ignoring as we already have a pass for same standardized type {std_name}")
            continue
        normed_results[scan_id] = scan_results
    return normed_results

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
    xnat_nott.xnat_upload(args, url, "temp.xml", replace_name=f"DICOMQC_{args.session}")


def _expected_num_sf(floatstr):
    """
    :return: Number of significant figures specified by a floating point
             number in a string, e.g. '1.43' would return 3
    """
    return len(floatstr.strip().replace(".", "").replace("-", "").lstrip("0"))


def _float_matches(f1, f2, num_sf):
    """
    :return: True if f1 and f2 are the same to within num_sf significant figures
    """
    f1 = float(('%.' + str(num_sf) + 'g') % f1)
    f2 = float(('%.' + str(num_sf) + 'g') % f2)
    return abs(f1 - f2) < FLOAT_TOLERANCE

def _check_float(value, operator, expected, index=0):
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
    # Compare floats to the number of decimal places given in the expected value
    if operator == "==":
        num_sf = _expected_num_sf(expected)
        return _float_matches(value, float(expected), num_sf)
    elif operator == "range":
        expected = [v for v in expected.strip("[]").split(",")]
        expected_sf = [_expected_num_sf(v) for v in expected]
        expected = [float(v) for v in expected]
        if len(expected) == 1:
            expected = [expected[0], expected[0]]
            expected_sf = [expected_sf[0], expected_sf[0]]
        return (
            value >= expected[0] and value <= expected[1] 
            or _float_matches(value, expected[0], expected_sf[0]) 
            or _float_matches(value, expected[1], expected_sf[1])
        )
    elif operator == "contain":
        # Tricky when values are in separate files. Define sequence from expected and 
        # see if value is in sequence
        expected = [v for v in expected.strip("[]").split(",")]
        num_sf = max([_expected_num_sf(v) for v in expected])
        expected = [float(v) for v in expected]
        s0 = expected[0]
        sd = expected[1] - expected[0]
        n = round((value - s0) / sd)
        if _float_matches(value, s0+n*sd, num_sf):
            return True
        else:
            return False

def _check_int(value, operator, expected, index=0):
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

def _check_str(value, operator, expected, index=0):
    """
    Check if a string passes a test

    :param value: Integer
    :param operator: Type of test, currently only == for equality is supported
    :param expected: Expected value

    :return: True if value passes the test, False otherwise
    """
    expected = expected.strip("[]")
    if operator == "==":
        return value.lower().strip() == expected.lower().strip()
    elif operator in ("contains", "contain"):
        return expected.lower().strip() in value.lower().strip()
    else:
        LOG.warning("Only == and contains supported for string checks: ", value, operator, expected)
        return False

def _check_list(value, operator, expected, index=None):
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
    if len(expected) == 1:
        expected = expected[0].split("\\")
    try:
        num_sf = max([_expected_num_sf(v) for v in expected])
        expected = [float(v) for v in expected]
        if operator == "==":
            for v1, v2 in zip(value, expected):
                if not _float_matches(v1, v2, num_sf):
                    return False
            return True
        elif operator == "range":
            if index:
                print("index:", index)
                value = [value[int(index)]]
            if len(expected) == 1:
                expected = [expected[0], expected[0]]
            for v in value:
                # We will ignore zeros as this seems common for this type of check
                if v >= FLOAT_TOLERANCE and (
                    v < expected[0] 
                    or v > expected[1]
                ) and not _float_matches(v, expected[0], num_sf) and not _float_matches(v, expected[1], num_sf):
                    return False
            return True
        elif operator in ("contain", "contains"):
            # Look for the specified values in the series
            for v in expected:
                if all([not _float_matches(v, v2, num_sf) for v2 in value]):
                    return False
            return True
    except ValueError:
        if operator == "==":
            for v1, v2 in zip(value, expected):
                if str(v1).lower() != str(v2).lower():
                    return False
            return True
        else:
            LOG.warning("Only == supported for non-numeric lists: ", value, operator, expected)
            return False

def _scan_pass(check, scan_results):
    if check not in scan_results["passes"]:
        LOG.debug(f"   - PASS: {check}")
        scan_results["passes"].add(check)

def _scan_fail(check, scan_results):
    if check not in scan_results["fails"]:
        LOG.info(f"   - FAIL: {check}")
        scan_results["fails"].add(check)

def _scan_warning(warning, scan_results):
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
    return ""

def series_matches(series_desc, include, exclude, exact=False):
    """
    See if the series description matches any of a list of series substrings
    """
    match = False
    for substr in include:
        if substr and (substr == "all" or (exact and substr == series_desc) or (not exact and substr in series_desc)):
            match = True
            break
    for substr in exclude:
        if substr and (substr == "all" or (exact and substr == series_desc) or (not exact and substr in series_desc)):
            match = False
            break
    return match

def filter_matches(dcm, filter_str):
    """
    See if a DICOM file matches a filter expression

    A filter expression is of the form:

    (1234, 5678) Explanatory text == value
    """
    if not filter_str:
        return True
    LOG.info(f"   - Filter checking: {filter_str}")
    pattern = re.compile(r'^\s*(\([0-9A-Fa-f]{4},\s*[0-9A-Fa-f]{4}\))\s*.*?=\s*(\S+)\s*$')
    m = pattern.match(filter_str)
    if not m:
        LOG.warning(f"Invalid filter expression: {filter_str}")
        return False
    tag = tag_from_text(m.group(1))
    expected = m.group(2)
    tag_value = find_tag(dcm, tag)
    if not tag_value:
        LOG.warning(f"No value for tag in filter expression: {filter_str}")
        return False
    value = convert_type(tag_value)
    LOG.info(f"   - Checking {value} == {expected}")
    if str(value).lower() == expected.lower():
        LOG.info("   - Filter matched")
        return True
    return False

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
    elif vr in ("PN",):
        return str(dcm_value)
    elif isinstance(dcm_value, str):
        return dcm_value
    else:
        LOG.warning(f"Unrecognized DICOM type: {vr} {dcm_value} {type(dcm_value)}")
        return str(dcm_value)

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


if __name__ == "__main__":
    main()
