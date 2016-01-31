CSP Bypass
============

This Burp plugin is designed to passively scan and parse CSP headers and automatically detect possibly bypasses and weaknesses.


## Installation

#### Jython Setup
 1. Download the latest [Jython 2.7.x](http://www.jython.org/) .jar file
 1. In Burp select `Extender` and then the `Options` tab, under _Python Environment_ heading click `Select File ...` and browse to the Jython .jar file

#### CSP Bypass Plugin Setup
 1. Execute the `build-plugin.sh` script, you should see a `csp-bypass-plugin.py` file appear
 1. In Burp select `Extender` and then the `Extensions` tab
 1. Click `Add` in the window that appears, select `Python` from the `Extension Type` dropdown menu
 1. Click `Select File ...` next to `Extension File` and select the generated `csp-bypass-plugin.py` file
 1. Click `Next` and you're done!
