"""The part of gangmu every bill of materials shares.

``gangmu.core`` is what an SBOM, a CBOM and an AIBOM engine all stand on:
entry-point plug-ins (:mod:`.plugins`), rule packs and their manifests
(:mod:`.packs`), evidence (:mod:`.evidence`), path globbing, firmware container
unpacking and Ed25519 signing. It is the seed of the ``gangmu-core`` distribution.

The boundary is enforced by ``tests/test_architecture.py``: nothing in here may
import another gangmu module, so the package can be split out without a rewrite.
The old import paths (``gangmu.plugins``, ``gangmu.signing``, ``gangmu.globbing``,
``gangmu.unpack``, ``gangmu.rules.packs``) remain as aliases of the same modules.
"""
