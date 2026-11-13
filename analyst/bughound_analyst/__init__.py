"""bughound-analyst — triase + SPK (SAW) + what-if atas temuan BugHound.

App TERPISAH dari core BugHound. Baca-saja: hanya GET /api/v1/findings.
Tak pernah memicu scan/submit. AI = penasihat; eksekusi di Burp = manusia.
Lihat docs/BH-DESIGN-analyst-spk.md untuk desain.
"""

__version__ = "0.1.0"
