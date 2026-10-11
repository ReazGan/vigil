"""Make the package importable in tests without an install step.

The detection core depends only on the standard library, so the tests run
without scapy/click/rich. Putting the project root on the path lets
``import vigil`` resolve to the in-tree package.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
