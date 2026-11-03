"""Put tools/ on the path so the test files import the exporters directly.

The scripts are run as programs, not installed as a package, so there is no
import root to inherit. Each one adds its own directory to sys.path at runtime
to reach nerdgraph; the tests do the same thing here, once.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
