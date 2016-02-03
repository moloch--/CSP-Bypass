CSP Bypass
============

This is a Burp plugin that is designed to passively scan for CSP headers that contain known bypasses as well as other potential weaknesses.

![CSP Bypass](/images/csp_bypass.png?raw=true)

## Installation

#### Jython Setup
 1. Download the latest standalone [Jython 2.7.x](http://www.jython.org/downloads.html) .jar file
 1. In Burp select `Extender` and then the `Options` tab, under the _Python Environment_ heading click `Select File ...` and browse to the Jython .jar file

#### CSP Bypass Plugin Setup
 1. Execute the `build-plugin.sh` script, you should see a `csp-bypass-plugin.py` file appear
 1. In Burp select `Extender` and then the `Extensions` tab
 1. Click `Add` in the window that appears, select `Python` from the `Extension Type` dropdown menu
 1. Click `Select File ...` next to `Extension File` and select the generated `csp-bypass-plugin.py` file
 1. Click `Next` and you're done!

## Report Bypasses in Common Domains

To add bypasses simply edit [csp_known_bypasses.py](https://github.com/moloch--/CSP-Bypass/blob/master/csp_known_bypasses.py) with a domain, and an example payload or description of the bypass. Be sure to use the full domain, the plugin will match wildcards (e.g. if a policy allows `*.googleapis.com` it will match against `ajax.googleapis.com`). Submit a pull request to get your bypass in the main repository!
