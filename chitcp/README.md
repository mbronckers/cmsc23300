chiTCP - A simple, testable TCP stack
=====================================

The chiTCP documentation is available at http://chi.cs.uchicago.edu/chitcp/

# Running & Testing:

$ ./chitcpd -vv

$ LOG=TRACE ./test-tcp --filter "conn_init/3way_states"

$ export CHITCPD_PORT=30280  # Substitute for a different number
$ export CHITCPD_SOCK=/tmp/chitcpd.socket.$USER
$ ./chitcpd -vvv

# GDB

Replace TEST with the test you want to debug, and substitute PORT with a random port number. By default, the tests will use 1234 but, if you are on a machine with multiple users, other users may be trying to use that port.

$ make && ./test-tcp --debug=gdb --debug-transport=tcp:1111 --filter "conn_init/3way_states"

and run in another terminal:

$ gdb ./test-tcp

On the GDB prompt, run this:

$ target remote localhost:1111

Use continue command instead of run

# Valgrind

$ valgrind ./test-tcp --filter "TEST"