import sys
import traceback

try:
    import app
except Exception as e:
    with open("err.log", "w") as f:
        traceback.print_exc(file=f)
