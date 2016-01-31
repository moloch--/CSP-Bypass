"""
@author: moloch

This is a Burp plugin to parse Content-Security-Policy headers and detect
possibly weaknesses and bypasses in the policy.
"""
# pylint: disable=E0602,C0103


from burp import IBurpExtender
from burp import IScannerCheck

from httplib import HTTPResponse
from StringIO import StringIO


class HttpDummySocket(object):

    """ A dummy socket object so we can use httplib to parse the bytearray """

    def __init__(self, byteResponse):
        self._file = StringIO(byteResponse)

    def makefile(self, *args, **kwargs):
        return self._file


class ContentSecurityPolicyScan(IScannerCheck):

    """ Implements the actual passive scan """

    CSP_HEADERS = ["content-security-policy",
                   "x-content-security-policy",
                   "x-webkit-csp"]

    def doPassiveScan(self, httpMessage):
        """ This callback method is called by Burp """
        if len(httpMessage.getResponse()):
            return self.proccessHttpResponse(httpMessage.getResponse())
        else:
            return []

    def proccessHttpResponse(self, byteResponse):
        """ Processes only the HTTP repsonses with a CSP header """
        httpSocket = HttpDummySocket(bytearray(byteResponse))
        response = HTTPResponse(httpSocket)
        response.begin()
        issues = []
        for header in response.getheaders():
            if header[0].lower() in self.CSP_HEADERS:
                issues.extend(self.parseContentSecurityPolicy(header))
        return issues

    def parseContentSecurityPolicy(self, cspHeader):
        csp = ContentSecurityPolicy(cspHeader[0], cspHeader[1])
        print csp[SCRIPT_SRC]


class BurpExtender(IBurpExtender):

    """ Burp extension object """

    NAME = "CSP Bypass"

    def	registerExtenderCallbacks(self, callbacks):
        """ Entrypoint and setup """
        callbacks.setExtensionName(self.NAME)
        callbacks.registerScannerCheck(ContentSecurityPolicyScan())

    def extensionUnloaded(self):
        """ Cleanup when the extension is unloaded """
        print "CSP Bypass extension was unloaded"
