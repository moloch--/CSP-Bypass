"""
@author: moloch

Scanner issues reported by the plugin.
"""
# pylint: disable=E0602,C0103,W0621,R0201


from burp import IScanIssue


class BaseCSPIssue(IScanIssue):

    """
    Just a base class with some helpful docstrings and a slightly modified
    constructor so we can track what directive we're reporting about.
    """

    # pylint: disable=R0913
    def __init__(self, httpService, url, httpMessages, severity, confidence,
                 directive=None):
        """
        Setters for all the getters, `directive' is optional
        """
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._severity = severity
        self._confidence = confidence
        self._directive = directive

    def getUrl(self):
        """
        This method returns the URL for which the issue was generated.
        @return The URL for which the issue was generated.
        """
        return self._url

    def getIssueName(self):
        """
        This method returns the name of the issue type.
        @return The name of the issue type (e.g. "SQL injection").
        """
        raise NotImplementedError()

    def getIssueType(self):
        """
        This method returns a numeric identifier of the issue type. See the Burp
        Scanner help documentation for a listing of all the issue types.
        @return A numeric identifier of the issue type.
        """
        return 0  # https://portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        """
        This method returns the issue severity level.
        @return The issue severity level. Expected values are "High", "Medium",
        "Low", "Information" or "False positive".
        """
        return self._severity

    def getConfidence(self):
        """
        This method returns the issue confidence level.
        @return The issue confidence level. Expected values are "Certain", "Firm"
        or "Tentative".
        """
        return self._confidence

    def getIssueBackground(self):
        """
        This method returns a background description for this type of issue.
        @return A background description for this type of issue, or
        <code>null</code> if none applies.
        """
        raise NotImplementedError()

    def getRemediationBackground(self):
        """
        This method returns a background description of the remediation for this
        type of issue.
        @return A background description of the remediation for this type of
        issue, or
        <code>null</code> if none applies.
        """
        raise NotImplementedError()

    def getIssueDetail(self):
        """
        This method returns detailed information about this specific instance of
        the issue.
        @return Detailed information about this specific instance of the issue,
        or
        <code>null</code> if none applies.
        """
        raise NotImplementedError()

    def getRemediationDetail(self):
        """
        This method returns detailed information about the remediation for this
        specific instance of the issue.
        @return Detailed information about the remediation for this specific
        instance of the issue, or
        <code>null</code> if none applies.
        """
        raise NotImplementedError()

    def getHttpMessages(self):
        """
        This method returns the HTTP messages on the basis of which the issue was
        generated.
        @return The HTTP messages on the basis of which the issue was generated.
        Note: The items in this array should be instances of
        <code>IHttpRequestResponseWithMarkers</code> if applicable, so that
        details of the relevant portions of the request and response messages are
        available.
        """
        if isinstance(self._httpMessages, list):
            return self._httpMessages
        else:
            return [self._httpMessages]

    def getHttpService(self):
        """
        This method returns the HTTP service for which the issue was generated.
        @return The HTTP service for which the issue was generated.
        """
        return self._httpService


class WildcardContentSource(BaseCSPIssue):

    """
    Wildcard content sources. Note: this does not flag wildcard subdomains
    """

    def getIssueName(self):
        return "Wildcard Content Source: %s" % self._directive

    def getIssueBackground(self):
        return "Background description goes here!"

    def getRemediationBackground(self):
        return "Remediation background"

    def getIssueDetail(self):
        return "Issue details"

    def getRemediationDetail(self):
        return "Remediation details"


class UnsafeContentSource(BaseCSPIssue):

    """ Any directive that allows unsafe content (e.g. 'unsafe-eval') """

    def getIssueName(self):
        return "Unsafe Content Source: %s" % self._directive

    def getIssueBackground(self):
        return "Issue background"

    def getRemediationBackground(self):
        return "Remediation background"

    def getIssueDetail(self):
        return "Issue details"

    def getRemediationDetail(self):
        return "Remediation details"


class InsecureContentDirective(BaseCSPIssue):

    """
    Any directive that allows insecure network protocols (e.g. ws: or http:)
    """

    def getIssueName(self):
        return "Insecure Content Source: %s" % self._directive

    def getIssueBackground(self):
        return "Issue background"

    def getRemediationBackground(self):
        return "Remediation background"

    def getIssueDetail(self):
        return "Issue details"

    def getRemediationDetail(self):
        return "Remediation details"


class MissingDirective(BaseCSPIssue):

    """
    Directives that 'fail open', that is to say they are not restricted by the
    CSP and do not fallback to `default-src'.
    """

    def getIssueName(self):
        return "Missing CSP Directive: %s" % self._directive

    def getIssueBackground(self):
        return "Issue background"

    def getRemediationBackground(self):
        return "Remediation background"

    def getIssueDetail(self):
        return "Issue details"

    def getRemediationDetail(self):
        return "Remediation details"


class WeakDefaultSource(BaseCSPIssue):

    """ Any `default-src' that is not 'none' 'self' or 'https:' """

    def getIssueName(self):
        return "Weak default-src Directive"

    def getIssueBackground(self):
        return "Issue background"

    def getRemediationBackground(self):
        return "Remediation background"

    def getIssueDetail(self):
        return "Issue details"

    def getRemediationDetail(self):
        return "Remediation details"



class DeprecatedHeader(BaseCSPIssue):

    """ Flags use of X-WebKit-CSP and X-Content-Security-Policy """

    def getIssueName(self):
        return "Deprecated Header"

    def getIssueBackground(self):
        return "Issue background"

    def getRemediationBackground(self):
        return "Remediation background"

    def getIssueDetail(self):
        return "Issue details"

    def getRemediationDetail(self):
        return "Remediation details"


class KnownCSPBypass(BaseCSPIssue):

    """ Reports a known bypass in a domain whitelisted by a CSP """

    # pylint: disable=W0231,R0913
    def __init__(self, httpService, url, httpMessages, severity, confidence,
                 directive=None, bypass=None):
        """
        Burp uses old style classes so we can't use super()
        """
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._severity = severity
        self._confidence = confidence
        self._directive = directive
        self._bypass = bypass

    def getIssueName(self):
        return "Known CSP Bypass: %s" % self._directive

    def getIssueBackground(self):
        return "Issue background"

    def getRemediationBackground(self):
        return "Remediation background"

    def getIssueDetail(self):
        return """
A known bypass exists in the '%s' directive for the domain '%s'.
%s
""" % (self._directive, self._bypass[0], self._bypass[1])

    def getRemediationDetail(self):
        return """
Remove the content source '%s' domain from your '%s' CSP directive.
""" % (self._bypass[0], self._directive)
