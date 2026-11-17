import importlib, sys
mod = importlib.import_module(sys.argv[1])
mod.main()
