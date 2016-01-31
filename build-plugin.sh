#!/bin/bash

# This just inlines all the .py files so you don't have to manually
# add a modules directory in Burp

cat \
    csp_parser.py \
    burp_scanner_issues.py \
    burp_csp_bypass.py \
> csp-bypass-plugin.py

echo "done."
