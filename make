################################################################################
# A simple make script.
#
# The intent of this script is to provide the simplest possible way to get this
# ECCSI/ SAKKE demonstration code up and running. From there you can look at
# the code, see how it works and play with it. If you make changes that break 
# something, reverting to a working version should be simple.
#
# Please feed back any bugs, or comments back to the author, so that we can 
# make this the best if can be for everybody.
#
# In order to run the demo program you will need to make the libraries 
# location accessible. The easiest way to do this on linux systems is to 
# add the libraries location to LD_LIBRART_PATH as follows:
#
#     export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./lib
#
# Other ways would be to copy the library to a 'usual' libraries location, or, 
# add the path to the lib directory in this directory, to /etc/ld.so.conf, and
# run ldconfig, although you will need to be root to do this.
#
# Once made the demo program can be run with:
#
#     ./es-demo-1
#
# Other useful notes:
#
#   o If you want to turn DEBUG output off, comment out the following line:
#         #define ES_OUTPUT_DEBUG
#     from src/utils/log.h
#   o If you want to change where data (community and user key data) you will
#     need to modify STORAGE_ROOT in inc/globals.h
#
################################################################################

################################################################################
# Key Material Storage Library.
################################################################################
#  Create PIC data storage object.
gcc -c -O3 --pedantic -Wall -Wno-variadic-macros -Werror -fpic \
    -I./4u2change/ \
    4u2change/msdb.c 
mv ./msdb.o ./bin
#  Create data storage shared library.
gcc -shared -o ./lib/libesdata.so ./bin/msdb.o 

###############################################################################
# PRNG.
################################################################################
#  Create PIC data storage object.
gcc -c -O3 --pedantic -Wall -Wno-variadic-macros -Werror -fpic \
    -I./4u2change/ \
    4u2change/esprng.c
mv ./esprng.o ./bin
#  Create prng shared library.
gcc -shared -o ./lib/libesprng.so ./bin/esprng.o

################################################################################
# ECCSI/ SAKKE Crypto Library.
################################################################################
#  Create ECCSI/ SAKKE storage objects.
gcc -c -O3 --pedantic -Wall -Wno-variadic-macros -Werror -fpic \
    -I./inc -I./4u2change -I./src/utils -I./src/sakke -I./src/eccsi -I./src/data \
    -L/usr/lib64 \
    -L/usr/lib32 \
    -lssl -lcrypto \
    src/utils/utils.c \
    src/data/userParameters.c \
    src/data/communityParameters.c \
    src/data/mikeySakkeParameters.c \
    src/sakke/sakke.c \
    src/eccsi/eccsi.c 
mv ./*.o ./bin
# Create ECCSI/ SAKKE shared library.
gcc -shared -o ./lib/libescrypt.so \
    ./bin/utils.o \
    ./bin/userParameters.o \
    ./bin/communityParameters.o \
    ./bin/mikeySakkeParameters.o \
    ./bin/sakke.o \
    ./bin/eccsi.o 

################################################################################
# Demo code.
################################################################################
gcc -Wall -O3 --pedantic -Wno-variadic-macros \
    -I./inc -I./4u2change -I./src/utils -I./src/sakke -I./src/eccsi -I./src/data \
    -L/usr/lib64 -L/usr/lib32 -L./lib \
    -lssl -lcrypto \
    -lesprng -lesdata -lescrypt \
    es-demo-1.c -o es-demo-1
