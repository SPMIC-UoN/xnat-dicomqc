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

def check_file(dcm, vendor):
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
            sys.stdout.write(f" - Checking: {conf.parameter} {actual.value} {conf.operator} {conf.expected}".ljust(70))
            if t in TYPE_HANDLERS:
                if TYPE_HANDLERS[t](conf.parameter, actual.value, conf.operator, conf.expected):
                    sys.stdout.write("PASS\n")
                else:
                    sys.stdout.write("FAIL\n")
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
    list : check_list,
    pydicom.multival.MultiValue : check_multival,
    int : check_int,
    float : check_float,
    str: check_str,
}

indir = sys.argv[1]
#outdir = sys.argv[2]
if len(sys.argv) > 2:
    config_fname = sys.argv[2]
else:
    config_fname = "dicomqc_conf.tsv"
qc_conf = read_config(config_fname)

for fname in os.listdir(indir):
    try:
        with pydicom.dcmread(os.path.join(indir, fname)) as dcm:
            vendor = get_vendor(dcm)
            if vendor not in qc_conf:
                print(f"WARN: Vendor {vendor} not found in QC config")
            else:
                print(f"Checking file: {fname} for vendor {vendor}")
                check_file(dcm, vendor)

    except pydicom.errors.InvalidDicomError:
        print(f"WARN: File {fname} was not a DICOM file" % fname)
