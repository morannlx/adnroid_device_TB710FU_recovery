#!/system/bin/sh
   export ROOT=$HOME/python_env
   export PATH=$ROOT:$PATH
   export LD_LIBRARY_PATH=$ROOT:$LD_LIBRARY_PATH
   export PYTHONHOME=$ROOT
   exec $ROOT/python "$@"