#!/usr/bin/env python
"""
@author: moloch

Unit tests for the CSP parser, the parser is written in "pure" Python so  we
don't need Jython to run the unit tests.
"""

import unittest

from csp_parser import *


# Constants
CSP_HEADER_NAME = "Content-Security-Policy"

# Test cases
CSP_TEST_PARSER_1 = (
    CSP_HEADER_NAME,
    "default-src 'self' https://cdn.example.net; child-src 'none'; object-src 'none'")

CSP_TEST_PARSER_2 = (
    CSP_HEADER_NAME,
    "default-src 'self' https:; connect-src 'self' https: http:; font-src 'self' https:; frame-src *; img-src 'self' https: http: data:; media-src 'self' https:; object-src 'self' https:; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' http:; style-src 'self' https: 'unsafe-inline' http:; report-uri /tracking/csp;")  # pylint: disable=C0301

CSP_TEST_INVALID_TYPES = (
    CSP_HEADER_NAME,
    "default-src 'self' https://cdn.example.net; foobar-src 'none';")


class TestContentSecurityPolicy(unittest.TestCase):

    def test_parser_1(self):
        csp = ContentSecurityPolicy(*CSP_TEST_PARSER_1)
        self.assertTrue(SCRIPT_SRC in csp)
        self.assertTrue(SELF in csp[SCRIPT_SRC])

    def test_parser_2(self):
        csp = ContentSecurityPolicy(*CSP_TEST_PARSER_2)
        self.assertTrue(SCRIPT_SRC in csp)
        self.assertTrue(SELF in csp[SCRIPT_SRC])
        self.assertTrue(UNSAFE_EVAL in csp[SCRIPT_SRC])

    def test_invalid_types(self):
        with self.assertRaises(ValueError):
            ContentSecurityPolicy(*CSP_TEST_INVALID_TYPES)


if __name__ == '__main__':
    unittest.main()
