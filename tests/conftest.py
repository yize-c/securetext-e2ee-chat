import os
import sys

# securetext.py refuses to start without a challenge key, so set one for tests.
os.environ.setdefault("SECURETEXT_CHALLENGE_KEY", "test-only-challenge-key")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
