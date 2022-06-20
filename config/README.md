XNAT_DICOMQC configuration
==========================

This folder contains an example configuration document for DICOMQC.

The format of the Excel is as follows:

Sheet 1 (Series Names)
----------------------

This worksheet defines matching of scans to standardized names using the
SERIES_DESCRIPTION DICOM tag. The purpose of this is to account for different
scan descriptions for different vendors and to allow some flexibility with
matching different scans having similar descriptions (e.g. T1_map and T1_map_flipped)

 - First column: text substring to match the SERIES_DESCRIPTION DICOM tag
 - Second column: Exclusion substring - if this is found in SERIES_DESCRIPTION the match will not apply
 - Third column: Vendors to use this rule for (comma separated, blank=all vendors)
 - Fourth columnb: Standardized name for use in check definition worksheet
 - Notes: Free-text explanation, not used by code

Sheet 2 (Checks)

This worksheet defines the checks that will be run on each scan. Scans are
identified only by the standardized names defined in the first worksheet.

 - Column 1: Comma separated text substrings to match standardized scan names
 - Column 2: Exclusions - comma separated text substrings to match standardized scan names - if the name matches
   the check will not apply to this scan type.
 - Column 3: Vendors to use this check for (comma separated, blank=all vendors)
 - Column 4: Not currently used
 - Column 5: DICOM tags to extract information from. If more than one give, first one with value is used
 - Column 6: Name of the parameter, used only for reporting outcome of the check
 - Column 7: Type of check to perform: `==` for equality check, `range` for max/min value check, `contain` 
   where value must be in an arithmetic sequence, `or` where value may take any of a set of values
 - Column 8: Expected value. For `==` a single number or string. If a floating point number is given, equality
   will be checked to the same number of significant figures. For parameters which contain a sequence of values
   (e.g. pixel spacing), expected value is given as comma separated list enclosed in square brackets. For 
   `range` check, expected value given as `[min, max]`. For `contain`, sequence of allowed values is given
   as `[value1, value2]`. For `or`, allowed values are given as `[value1, value2, value3, ...]`.
 - Column 9: Not currently used
 - Column 10: If this contains the text `WARNING`, check failure will be treated as a warning only and will
   not fail the whole scan
 - Column 11: Free text for explanation, not used in code

