"""
@author: moloch

This is a Burp plugin to parse Content-Security-Policy headers and detect
possibly weaknesses and bypasses in the policy.
"""

from burp import IBurpExtender
from burp import IHttpListener
from burp import IExtensionStateListener
from java.io import PrintWriter

from datetime import datetime
from httplib import HTTPResponse
from StringIO import StringIO


class HttpDummySocket(object):

    """ A dummy socket object so we can use httplib to parse the string """

    def __init__(self, byteResponse):
        self._file = StringIO(byteResponse)

    def makefile(self, *args, **kwargs):
        return self._file


class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):

    """ Burp extension object """

    NAME = "CSP Bypass"
    CSP_HEADERS = ["content-security-policy",
                   "x-content-security-policy",
                   "x-webkit-csp"]

    def log(self, message):
        """ Helper method for logging messages """
        self._stdout.println("[%s] %s" % (datetime.now(), message))

    def	registerExtenderCallbacks(self, callbacks):
        """ Entrypoint and setup """
        self._callbacks = callbacks
        callbacks.setExtensionName(self.NAME)
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        # register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """ This callback method is called by Burp """
        if not messageIsRequest:
            self.proccessHttpResponse(messageInfo.getResponse())

    def proccessHttpResponse(self, byteResponse):
        """ Processes only the HTTP repsonses with a CSP header """
        httpSocket = HttpDummySocket(bytearray(byteResponse))
        response = HTTPResponse(httpSocket)
        response.begin()
        for header in response.getheaders():
            if header[0].lower() in self.CSP_HEADERS:
                self.parseContentSecurityPolicy(header)

    def parseContentSecurityPolicy(self, cspHeader):
        csp = ContentSecurityPolicy(cspHeader[0], cspHeader[1])


    def extensionUnloaded(self):
        """ Cleanup when the extension is unloaded """
        self.log("Extension was unloaded")
