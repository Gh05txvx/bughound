"""bughound-analyst, triage + decision support (SAW) + what-if over BugHound findings.

A SEPARATE app from the BugHound core. Read-only: just GET /api/v1/findings.
Never triggers a scan/submit. AI = advisor; execution in Burp = a human.
See docs/BH-DESIGN-analyst-spk.md for the design.
"""

__version__ = "0.1.0"
