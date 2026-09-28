"""Tailwind и HTMX отдаются самим приложением: вёрстка не зависит от интернета."""
from __future__ import annotations

import re


def test_scripts_are_local_and_served(admin_client):
    html = admin_client.get('/servers/').get_data(as_text=True)
    srcs = re.findall(r'<script[^>]*\ssrc="([^"]+)"', html)

    assert not [s for s in srcs if s.startswith(('http:', 'https:', '//'))]
    assert any('tailwindcss' in s for s in srcs)
    assert any('htmx' in s for s in srcs)
    for src in srcs:
        resp = admin_client.get(src)
        assert resp.status_code == 200, src
        assert len(resp.data) > 1000, src
        resp.close()
