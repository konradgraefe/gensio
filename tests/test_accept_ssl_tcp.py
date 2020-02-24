#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test accept ssl-tcp")
io1 = alloc_io(o, "ssl(CA=%s/CA.pem),tcp,localhost,3023" % keydir, do_open = False)
ta = TestAccept(o, io1, "ssl(key=%s/key.pem,cert=%s/cert.pem),3023" % (keydir, keydir), do_test, do_close = False,
                expected_raddr = "ipv4,127.0.0.1,3023")
cn = io1.control(0, True, gensio.GENSIO_CONTROL_GET_PEER_CERT_NAME,
                 "-1,CN");
i = cn.index(',')
cn2 = cn[i+1:]
i = cn2.index(',')
if cn2[0:i] != "CN":
    raise Exception(
        "Invalid object name, expected %s, got %s" % ("CN", cn2[0:i]))
if cn2[i+1:] != "ser2net.org":
    raise Exception(
        "Invalid common name in certificate, expected %s, got %s" %
        ("ser2net.org", cn2[i+1:]))
cert = io1.control(0, True, gensio.GENSIO_CONTROL_CERT, None)
print("Cert = \n" + cert)
finger = io1.control(0, True, gensio.GENSIO_CONTROL_CERT_FINGERPRINT, None)
print("Fingerprint = " + finger)
i = 0;
while True:
    v = io1.control(0, True, gensio.GENSIO_CONTROL_GET_PEER_CERT_NAME,
                    str(i))
    if v is None:
        break;
    print(v)
    i = i + 1
ta.close()