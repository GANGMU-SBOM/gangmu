"""gangmu-sbom: build-time SBOM for embedded C/C++.

The package is deliberately split so that each layer can be reasoned about on
its own:

* :mod:`gangmu.rules`   -- the community rule base (data) and how it is loaded.
* :mod:`gangmu.match`   -- the three-tier identification engine.
* :mod:`gangmu.build`   -- facts harvested from a real build (what actually
                           got compiled and linked).
* :mod:`gangmu.sbom`    -- serialisation to CycloneDX 1.6 / SPDX 2.3.
"""

__version__ = "0.7.0"
