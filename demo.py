import sys
import os

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from tripwire.__main__ import main
    sys.argv = ["tripwire", "serve"]
    sys.exit(main())
