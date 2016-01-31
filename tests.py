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
CSP_TEST_PARSER = (CSP_HEADER_NAME,
    "default-src 'self' https://cdn.example.net; child-src 'none'; object-src 'none'")

CSP_TEST_INVALID_TYPES = (CSP_HEADER_NAME,
    "default-src 'self' https://cdn.example.net; foobar-src 'none';")


class TestContentSecurityPolicy(unittest.TestCase):

    def test_parser(self):
        csp = ContentSecurityPolicy(*CSP_TEST_PARSER)
        self.assertTrue(SCRIPT_SRC in csp)
        self.assertTrue(SELF in csp[SCRIPT_SRC])

    def test_invalid_types(self):
        with self.assertRaises(ValueError):
            ContentSecurityPolicy(*CSP_TEST_INVALID_TYPES)


if __name__ == '__main__':
    unittest.main()
