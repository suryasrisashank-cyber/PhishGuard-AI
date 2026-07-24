import importlib, sys, traceback
try:
    importlib.import_module('backend.app.main')
    print('IMPORT_OK')
except Exception:
    traceback.print_exc()
    sys.exit(1)
