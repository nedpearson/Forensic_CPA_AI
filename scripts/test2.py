import traceback

try:
    pass
except Exception:
    with open("err.log", "w") as f:
        traceback.print_exc(file=f)
