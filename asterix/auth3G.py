"""asterix/auth3G.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com
Date: 2017-09-19

This file is part of asterix, a framework for communication with
smartcards based on pyscard. This file implements authentication in 3G
networks as specified in 3GPP TS 33.102 and namely Milenage algorithm
(3GPP TS 35.201, 35.206).

asterix is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

asterix is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with pyscard; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""

from binascii import hexlify, unhexlify
import unittest

# PyCrypto
from Crypto.Cipher import AES
# asterix
from formutil import s2int, int2s, randomBytes

MASK128 = (1<<128) - 1

def rot(x, r):
    """Cyclically rotate 128b number x by r bit towards the MSb"""
    assert 0 <= x <= MASK128
    assert 0 <= r <= 127
    return MASK128 & (x << r) | (x >> (128-r))
    
class MilenageAlgo:
    """Milenage 3G authentication scheme as defined in 3GPP TS 35.201, 35.206
"""
    def _check_int(self, param, label, bitlen):
        """Convert param to int and check its value"""
        if isinstance(param, str):
            param = s2int(param)
        assert isinstance(param, int) or isinstance(param, long), \
            "Wrong type of " + label
        assert 0 <= param < (1 << bitlen), "Wrong value of " + label
        return param

    def _check_str(self, param, label, bitlen=128):
        """Convert param to int and check its value"""
        if isinstance(param, int) or isinstance(param, long):
            param = int2s(param, bitlen)
        assert isinstance(param, str) and 8*len(param) == bitlen, \
            "Wrong " + label
        return param

    def _check_rand(self, rand):
        """Check provided rand and calculate temp. Use stored values if None"""
        if self.rand is None or rand is not None:
            self.rand = s2int(randomBytes(16)) if rand is None else \
                        self._check_int(rand, "RAND", 128)
            temp = self.Ek.encrypt(int2s(self.rand ^ self.OPc, 128))
            self.temp = s2int(temp)

    def __init__(self, ki, opc=None, op=None,
                 c=(0, 1, 2, 4, 8),
                 r=(64, 0, 32, 64, 96)):
        """Initialization with key, OP(C) and Milenage parameters
ki, opc, op - strings of len 16B or int/long
c, r - 5-tuple of ints"""
        ki = self._check_str(ki, "KI")
        # encryption function
        self.Ek = AES.new(ki, AES.MODE_ECB)

        assert opc is not None or op is not None, \
            "Either OP or OPC must be specified"
        
        if opc is not None:
            self.OPc = self._check_int(opc, "OPC", 128)

        if op is not None:
            op = self._check_str(op, "OP")
            op_int = s2int(op)
            topc = s2int(self.Ek.encrypt(op)) ^ op_int
            if opc is None:
                self.OPc = topc
            else:
                assert topc == opc, "OPC %s does not match to KI, OPC: %s"

        # sanity check of c & r
        assert isinstance(c, tuple) or isinstance(c, list), "Wrong type of C"
        assert isinstance(r, tuple) or isinstance(r, list), "Wrong type of R"
        assert len(c) == 5, "Wrong number of parameters C"
        assert len(r) == 5, "Wrong number of parameters R"
        assert all([isinstance(ci, int) or isinstance(ci, long) for
                    ci in c]), "Wrong type of Ci"
        assert all([isinstance(ri, int) or isinstance(ri, long) for
                    ri in r]), "Wrong type of Ri"
        assert all([ 0 <= ci <= MASK128 for ci in c]), "Wrong value of Ci"
        assert all([ 0 <= ri < 128 for ri in r]), "Wrong value of Ri"
        self.C = tuple([None] + list(c))  # parameters are numbered from 1 to 5
        self.R = tuple([None] + list(r))
        self.rand = None
        self.temp = None
        self.sqn = (1 << 5) | 1
        self.amf = 0x0000

    def f1(self, rand=None, sqn=None, amf=None):
        """Calculate network & resync authentication code.
rand, sqn, amf - str or int, if None, use the stored value
return (MAC-A, MAC-S) as two 8B str"""
        self._check_rand(rand)
        if sqn is None:
            assert self.sqn is not None, "SQN not stored"
        else:
            self.sqn = self._check_int(sqn, "SQN", 48)
        if amf is None:
            assert self.amf is not None, "AMF not stored"
        else:
            self.amf = self._check_int(amf, "AMF", 16)
        in1 = ( self.sqn << 16 ) | self.amf
        in1 |= in1 << 64

        arg = self.temp ^ rot(in1 ^ self.OPc, self.R[1]) ^ self.C[1]
        out1 = s2int(self.Ek.encrypt(int2s(arg, 128))) ^ self.OPc
        out1s = int2s(out1, 128)
        return out1s[:8], out1s[8:]

    def f2(self, rand=None):
        """Calculate authentication response.
rand - str or int, if None, use the stored value
return RES as 8B str"""
        self._check_rand(rand)
        arg = rot(self.temp ^ self.OPc, self.R[2]) ^ self.C[2]
        out2 = s2int(self.Ek.encrypt(int2s(arg, 128))) ^ self.OPc
        out2s = int2s(out2, 128)
        return out2s[8:]

    def f3(self, rand=None):
        """Calculate confidentiality key.
rand - str or int, if None, use the stored value
return CK as 16B str"""
        self._check_rand(rand)
        arg = rot(self.temp ^ self.OPc, self.R[3]) ^ self.C[3]
        out3 = s2int(self.Ek.encrypt(int2s(arg, 128))) ^ self.OPc
        return int2s(out3, 128)

    def f4(self, rand=None):
        """Calculate integrity key.
rand - str or int, if None, use the stored value
return IK as 16B str"""
        self._check_rand(rand)
        arg = rot(self.temp ^ self.OPc, self.R[4]) ^ self.C[4]
        out4 = s2int(self.Ek.encrypt(int2s(arg, 128))) ^ self.OPc
        return int2s(out4, 128)
        
    def f5(self, rand=None):
        """Calculate anonimity keys for authentication.
rand - str or int, if None, use the stored value
return AK as 48b integer"""
        self._check_rand(rand)
        arg = rot(self.temp ^ self.OPc, self.R[2]) ^ self.C[2]
        out2 = s2int(self.Ek.encrypt(int2s(arg, 128))) ^ self.OPc
        return out2 >> 80
        
    def f5s(self, rand=None):
        """Calculate anonimity keys for resync.
rand - str or int, if None, use the stored value
return AK as 48b integer"""
        self._check_rand(rand)
        arg = rot(self.temp ^ self.OPc, self.R[5]) ^ self.C[5]
        out5 = s2int(self.Ek.encrypt(int2s(arg, 128))) ^ self.OPc
        return out5 >> 80

# Unitary tests
class TestMilenage(unittest.TestCase):
    """Test vectors from 3GPP TS 35.207 rel 7"""

    def calculate(self, ki, rand, op, sqn, amf,
                  opc, mac_a, mac_s, res, ck, ik, ak_a, ak_s):
        m = MilenageAlgo(ki, op=op)
        self.assertEqual(m.OPc, s2int(opc), "Wrong OPc")
        mac = m.f1(rand, sqn, amf)
        self.assertEqual(mac[0], mac_a, "Wrong MAC_A")
        self.assertEqual(mac[1], mac_s, "Wrong MAC_A")
        self.assertEqual(m.f2(), res, "Wrong RES")
        self.assertEqual(m.f3(), ck, "Wrong CK")
        self.assertEqual(m.f4(), ik, "Wrong IK")
        self.assertEqual(m.f5(), s2int(ak_a), "Wrong AK auth")
        self.assertEqual(m.f5s(), s2int(ak_s), "Wrong AK resync")
        
        
    def testSet1(self):
        ki = unhexlify('465b5ce8b199b49faa5f0a2ee238a6bc')
        rand = unhexlify('23553cbe9637a89d218ae64dae47bf35')
        op = unhexlify('cdc202d5123e20f62b6d676ac72cb318')
        sqn = unhexlify('ff9bb4d0b607')
        amf = unhexlify('b9b9')

        # expected results:
        opc = unhexlify('cd63cb71954a9f4e48a5994e37a02baf')
        mac_a = unhexlify('4a9ffac354dfafb3')
        mac_s = unhexlify('01cfaf9ec4e871e9')
        res = unhexlify('a54211d5e3ba50bf')
        ck = unhexlify('b40ba9a3c58b2a05bbf0d987b21bf8cb')
        ik = unhexlify('f769bcd751044604127672711c6d3441')
        ak_a = unhexlify('aa689c648370')
        ak_s = unhexlify('451e8beca43b')

        self.calculate(ki, rand, op, sqn, amf,
                       opc, mac_a, mac_s, res, ck, ik, ak_a, ak_s)

    def testSet2(self):
        ki = unhexlify('0396eb317b6d1c36f19c1c84cd6ffd16')
        rand = unhexlify('c00d603103dcee52c4478119494202e8')
        op = unhexlify('ff53bade17df5d4e793073ce9d7579fa')
        sqn = unhexlify('fd8eef40df7d')
        amf = unhexlify('af17')

        # expected results:
        opc = unhexlify('53c15671c60a4b731c55b4a441c0bde2')
        mac_a = unhexlify('5df5b31807e258b0')
        mac_s = unhexlify('a8c016e51ef4a343')
        res = unhexlify('d3a628ed988620f0')
        ck = unhexlify('58c433ff7a7082acd424220f2b67c556')
        ik = unhexlify('21a8c1f929702adb3e738488b9f5c5da')
        ak_a = unhexlify('c47783995f72')
        ak_s = unhexlify('30f1197061c1')

        self.calculate(ki, rand, op, sqn, amf,
                       opc, mac_a, mac_s, res, ck, ik, ak_a, ak_s)

    def testSet3(self):
        ki = unhexlify('fec86ba6eb707ed08905757b1bb44b8f')
        rand = unhexlify('9f7c8d021accf4db213ccff0c7f71a6a')
        op = unhexlify('dbc59adcb6f9a0ef735477b7fadf8374')
        sqn = unhexlify('9d0277595ffc')
        amf = unhexlify('725c')

        # expected results:
        opc = unhexlify('1006020f0a478bf6b699f15c062e42b3')
        mac_a = unhexlify('9cabc3e99baf7281')
        mac_s = unhexlify('95814ba2b3044324')
        res = unhexlify('8011c48c0c214ed2')
        ck = unhexlify('5dbdbb2954e8f3cde665b046179a5098')
        ik = unhexlify('59a92d3b476a0443487055cf88b2307b')
        ak_a = unhexlify('33484dc2136b')
        ak_s = unhexlify('deacdd848cc6')

        self.calculate(ki, rand, op, sqn, amf,
                       opc, mac_a, mac_s, res, ck, ik, ak_a, ak_s)

    def testSet4(self):
        ki = unhexlify('9e5944aea94b81165c82fbf9f32db751')
        rand = unhexlify('ce83dbc54ac0274a157c17f80d017bd6')
        op = unhexlify('223014c5806694c007ca1eeef57f004f')
        sqn = unhexlify('0b604a81eca8')
        amf = unhexlify('9e09')

        # expected results:
        opc = unhexlify('a64a507ae1a2a98bb88eb4210135dc87')
        mac_a = unhexlify('74a58220cba84c49')
        mac_s = unhexlify('ac2cc74a96871837')
        res = unhexlify('f365cd683cd92e96')
        ck = unhexlify('e203edb3971574f5a94b0d61b816345d')
        ik = unhexlify('0c4524adeac041c4dd830d20854fc46b')
        ak_a = unhexlify('f0b9c08ad02e')
        ak_s = unhexlify('6085a86c6f63')

        self.calculate(ki, rand, op, sqn, amf,
                       opc, mac_a, mac_s, res, ck, ik, ak_a, ak_s)

    def testSet5(self):
        ki = unhexlify('4ab1deb05ca6ceb051fc98e77d026a84')
        rand = unhexlify('74b0cd6031a1c8339b2b6ce2b8c4a186')
        op = unhexlify('2d16c5cd1fdf6b22383584e3bef2a8d8')
        sqn = unhexlify('e880a1b580b6')
        amf = unhexlify('9f07')

        # expected results:
        opc = unhexlify('dcf07cbd51855290b92a07a9891e523e')
        mac_a = unhexlify('49e785dd12626ef2')
        mac_s = unhexlify('9e85790336bb3fa2')
        res = unhexlify('5860fc1bce351e7e')
        ck = unhexlify('7657766b373d1c2138f307e3de9242f9')
        ik = unhexlify('1c42e960d89b8fa99f2744e0708ccb53')
        ak_a = unhexlify('31e11a609118')
        ak_s = unhexlify('fe2555e54aa9')

        self.calculate(ki, rand, op, sqn, amf,
                       opc, mac_a, mac_s, res, ck, ik, ak_a, ak_s)

    def testSet6(self):
        ki = unhexlify('6c38a116ac280c454f59332ee35c8c4f')
        rand = unhexlify('ee6466bc96202c5a557abbeff8babf63')
        op = unhexlify('1ba00a1a7c6700ac8c3ff3e96ad08725')
        sqn = unhexlify('414b98222181')
        amf = unhexlify('4464')

        # expected results:
        opc = unhexlify('3803ef5363b947c6aaa225e58fae3934')
        mac_a = unhexlify('078adfb488241a57')
        mac_s = unhexlify('80246b8d0186bcf1')
        res = unhexlify('16c8233f05a0ac28')
        ck = unhexlify('3f8c7587fe8e4b233af676aede30ba3b')
        ik = unhexlify('a7466cc1e6b2a1337d49d3b66e95d7b4')
        ak_a = unhexlify('45b0f69ab06c')
        ak_s = unhexlify('1f53cd2b1113')

        self.calculate(ki, rand, op, sqn, amf,
                       opc, mac_a, mac_s, res, ck, ik, ak_a, ak_s)

if __name__ == '__main__':
    unittest.main()
