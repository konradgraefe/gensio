
import pygensio
import sys
from testbase import *

# Basic test with blocking I/O
r = Reflector(o, "tcp,0")
r.startup()
port = r.get_port()

g = pygensio.gensio_alloc("tcp,localhost," + port, o, None)
g.open_s()
g.set_sync()
mydata = conv_to_bytes("Test sync string")
(rv, count) = g.write_s(mydata)
if rv != 0:
    raise Exception("Error writing: " + pygensio.err_to_string(rv))
if count != len(mydata):
    raise Exception("Write length mismatch")
(rv, data) = g.read_s(pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for read: " + pygensio.err_to_string(rv))
if data != mydata:
    raise Exception("Data mismatch")
g.clear_sync()
g.close_s()
r.shutdown_s()
del r
del g

# Basic test with non-blocking I/O
r = Reflector(o, "tcp,0")
r.startup()
port = r.get_port()
r.set_enable(False)
rv = r.wait1(pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for acc disable: " + pygensio.err_to_string(rv))
r.set_enable_s(False)
rv = r.set_enable(True, do_cb = False)

h = EvHnd(o)
g = pygensio.gensio_alloc("tcp,localhost," + port, o, h)
h.set_gensio(g)
w = pygensio.Waiter(o)
oh = Open_Done(w)
g.open(oh)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for open: " + pygensio.err_to_string(rv))
if oh.err != 0:
    raise Exception("Error in open: " + pygensio.err_to_string(oh.err))
del oh
h.set_data(conv_to_bytes("Test string"))
rv = h.wait(timeout=pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for I/O: " + pygensio.err_to_string(rv))
ch = Close_Done(w)
g.close(ch)
rv = w.wait(1, pygensio.gensio_time(1, 0))
del ch
if rv != 0:
    raise Exception("Error waiting for close: " + pygensio.err_to_string(rv))
r.shutdown()
rv = r.wait(pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for acc shutdown: " + pygensio.err_to_string(rv))
del g
del r
del o
           
print("Pass")
sys.exit(0)
