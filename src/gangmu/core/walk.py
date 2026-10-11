"""Directories no tree walker looks inside.

Every walker (component discovery, licences, declarations, binaries, CBOM, AIBOM)
skips these: version control, package-manager caches and Python environments are
never firmware content. A walker adds what is out of scope for its own purpose
(``build/`` holds outputs, not sources), but a directory of third-party code that
is compiled into the image -- ESP-IDF's ``managed_components/`` -- is never skipped.
"""

NOT_CONTENT_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})
