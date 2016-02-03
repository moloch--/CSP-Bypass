"""
@author: moloch

A basic Content Security Policy parser.
"""
# pylint: disable=C0103,C0111,R0201

from collections import defaultdict
from urlparse import urlparse


### Constants
BASE_URI = "base-uri"
FORM_ACTION = "form-action"
FRAME_ANCESTORS = "frame-ancestors"
PLUGIN_TYPES = "plugin-types"
REPORT_URI = "report-uri"
SANDBOX = "sandbox"
UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests"

DEFAULT_SRC = "default-src"
SCRIPT_SRC = "script-src"
CHILD_SRC = "child-src"
FRAME_SRC = "frame-src"
CONNECT_SRC = "connect-src"
FONT_SRC = "font-src"
IMG_SRC = "img-src"
MEDIA_SRC = "media-src"
OBJECT_SRC = "object-src"
STYLE_SRC = "style-src"

SELF = "'self'"
NONE = "'none'"
UNSAFE_INLINE = "'unsafe-inline'"
UNSAFE_EVAL = "'unsafe-eval'"
HTTP = "http:"
HTTPS = "https:"


def csp_match_domains(content_src, domain):
    """ Is `domain' allowed by `content_src' """
    # Isolate just the domain incase there is a scheme/etc.
    if urlparse(content_src).netloc != '':
        content_src = urlparse(content_src).netloc

    srcParts = content_src.split(".")[::-1]  # Reverse the domains
    domainParts = domain.split(".")[::-1]
    for index, srcPart in enumerate(srcParts):
        if srcPart == "*":
            return True
        if srcPart == domainParts[index]:
            continue
        else:
            return False
    return len(srcParts) == len(domainParts)


class ContentSecurityPolicy(object):

    """
    A simple Content-Security-Policy object, it resembles a dictionary but has
    logic to return `default-src' when approiate, etc.
    """

    HEADERS = ["content-security-policy",
               "x-content-security-policy",
               "x-webkit-csp"]

    CONTENT_TYPES = [
        DEFAULT_SRC, SCRIPT_SRC, BASE_URI, CHILD_SRC, FRAME_SRC,
        CONNECT_SRC, FONT_SRC, FORM_ACTION, FRAME_ANCESTORS, IMG_SRC,
        MEDIA_SRC, OBJECT_SRC, PLUGIN_TYPES, REPORT_URI, STYLE_SRC,
        SANDBOX, UPGRADE_INSECURE_REQUESTS]

    # These directives do not fallback to default-src
    NO_FALLBACK = [BASE_URI, FORM_ACTION, FRAME_ANCESTORS, PLUGIN_TYPES,
                   REPORT_URI, SANDBOX]

    def __init__(self, header_name, header_value):
        self._content_policies = defaultdict(list)
        self._header_name = None
        self._header_value = None
        self.header_name = header_name
        self.header_value = header_value

    @property
    def header_name(self):
        return self._header_name

    @header_name.setter
    def header_name(self, value):
        """ Setter for the header name """
        if value.lower() not in self.HEADERS:
            raise ValueError("Unknown header name: '%s'" % value)
        else:
            self._header_name = value.lower()

    @property
    def header_value(self):
        return self._header_value

    @header_value.setter
    def header_value(self, value):
        """ Sets the header value and parses it """
        self._header_value = value
        self._parse_header()

    def _parse_header(self):
        """ Splits the header on ';' then subsequently on whitespace """
        for policy in self._header_value.split(";"):
            if not len(policy):
                continue  # Skip blanks
            directive, sources = self._unpack_policy(*policy.strip().split(" "))
            self[directive] = sources

    def _unpack_policy(self, directive, *content_sources):
        """ Used to unpack the directive name and directives """
        return directive, [src.strip() for src in content_sources]

    def is_deprecated_header(self):
        """ Check for X-WebKit-CSP or X-Content-Security-Policy """
        return self.header_name.startswith('x')

    def iteritems(self):
        """ Similar to a dictionary, iterates tuples of key/value pairs """
        for key in self.CONTENT_TYPES:
            yield (key, self[key],)

    def __setitem__(self, key, value):
        if key not in self.CONTENT_TYPES:
            raise ValueError("Unknown directive '%s'" % key)
        if isinstance(value, list):
            self._content_policies[key].extend(value)
        elif isinstance(value, basestring):
            self._content_policies[key].append(value)
        else:
            raise ValueError("Expected list or basestring")

    def __getitem__(self, key):
        """
        Get the policy or return default-src if the policy isn't in NO_FALLBACK
        """
        if key not in self.CONTENT_TYPES:
            raise ValueError("Unknown directive '%s'" % key)
        if key in self._content_policies:
            return self._content_policies[key]
        elif key not in self.NO_FALLBACK:
            return self._content_policies[DEFAULT_SRC]

    def __contains__(self, item):
        if item not in self.NO_FALLBACK and item in self.CONTENT_TYPES:
            return True
        else:
            return item in self._content_policies

    def __iter__(self):
        for key in self.CONTENT_TYPES:
            yield self[key]
