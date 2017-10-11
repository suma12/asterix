""" asterix/GAF.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com
Date: 2015-11-03

This file is part of asterix, a framework for  communication with smartcards
 based on pyscard. This file contains Generalized ASN1 formatter (GAF).

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

import re
from struct import pack
# for unittests
import unittest
from binascii import unhexlify


(GAFEXP_UNKNOWN_CHAR, GAFEXP_PREMATURE_END, GAFEXP_UNMATCHED_LV) = range(3)
re_comment = re.compile(r'\s*--[^\r\n]*(\r\n|\r|\n)')
re_hexdata = re.compile(r'(\s*[\dA-Fa-f][\dA-Fa-f])+')
re_hexdata = re.compile(r'(\s*[\dA-Fa-f]{2})+')
re_literal = re.compile(r"\s*'([^']*)'")
re_object = re.compile(r'\s*\$([A-Za-z_]\w*)')
re_LVstart = re.compile(r'\s*#([\(\[\{])')
re_LVend = re.compile(r'\s*([\)\]\}])')
re_empty = re.compile(r'\s*')
re_eol = re.compile(r'\r\n|\r|\n')


class GAFexception(Exception):
    reasons = {
        GAFEXP_UNKNOWN_CHAR: "unexpected character",
        GAFEXP_PREMATURE_END: "premature end of stream",
        GAFEXP_UNMATCHED_LV: "closing parenthesis does not match the opening"}

    def __init__(self, reason, GAF):
        self.reason = reason
        self.GAF = GAF

    def __str__(self):
        a = self.GAF
        return """\
GAF error - %s
%s<ERROR>%s...
   at offet %d, line %d, column %d, depth %d """ % \
            (GAFexception.reasons[self.reason],
             a.stream[a.offset-30:a.offset],
             a.stream[a.offset:a.offset+30],
             a.offset, a.line, a.column, a.depth)


class GAF:
    """ Gramatics description:
hexdigitpair = [0-9A-Fa-f][0-9A-Fa-f]
hexdata = hexdigitpair*
literal = "'"[^']*"'"
item = hexdata | literal | object | LsimpleV | LderV | LdgiV
value = item+
object = "$" [A-Za-z_]\w*
LderV = "#(" value ")"
LsimpleV = "#[" value "]"
LdgiV = "#{" value "}"

Length coding:
simple: on 1B, 0-255
DGI: on 1B for 0-254, on 3B for 255-65535 as FFxxyy
DER: 'unlimited', on 1B for 0-127, 8s xxyy...zz
white spaces (except in literal) are ignored

Usage:
  g = GAF(template)
  s = g.eval(**kw)"""
    def __init__(self, stream):
        self.stream = stream
        self.resetPos()
        self.objects = set()
        self.tree = self.readValue()

    def resetPos(self):
        self.offset = 0
        self.line = 0
        self.column = 0
        self.depth = 0

    def updatePos(self, s):
        """ Accumulate parsed offset, lines and columns in string s """
        self.offset += len(s)
        m = None
        for m in re_eol.finditer(s):
            self.line += 1
        if m:
            self.column = len(s) - m.end()
        else:
            self.column += len(s)

    def readValue(self):
        """ Read GAF from stream
Return (Closing, result as []) or result (if depth==0) """
        result = []
        while True:
            item = self.readItem()
            if isinstance(item, Closing):
                if self.depth == 0:
                    if item.c is None:
                        return result  # the whole stream parsed
                    else:
                        raise GAFexception(GAFEXP_UNMATCHED_LV, self)
                else:
                    if item.c is None:
                        raise GAFexception(GAFEXP_PREMATURE_END, self)
                    return (item, result)
            else:
                if result and isinstance(result[-1], str) and \
                   isinstance(item, str):
                    result[-1] += item
                else:
                    result.append(item)

    def readItem(self):
        """ Read an iterm from stream and return it. """
        substream = self.stream[self.offset:]
        # skip comments
        while True:
            m = re_comment.match(substream)
            if m:
                self.updatePos(substream[:m.end()])
                substream = self.stream[self.offset:]
            else:
                break
        m = re_hexdata.match(substream)
        if m:
            self.updatePos(substream[:m.end()])
            return re.sub(r'\s', '', m.group()).decode('hex')

        m = re_literal.match(substream)
        if m:
            self.updatePos(substream[:m.end()])
            return m.group(1)

        m = re_object.match(substream)
        if m:
            self.updatePos(substream[:m.end()])
            Id = m.group(1)
            self.objects.add(Id)
            return Obj(Id)

        m = re_LVstart.match(substream)
        if m:
            self.depth += 1
            self.updatePos(substream[:m.end()])
            t = LV.OpenP[m.group(1)]
            closing, value = self.readValue()
            if closing.c is None:
                raise GAFexception(GAFEXP_PREMATURE_END, self)
            if closing.c != t:
                raise GAFexception(GAFEXP_UNMATCHED_LV, self)
            self.depth -= 1
            return LV(t, value)

        m = re_LVend.match(substream)
        if m:
            self.updatePos(substream[:m.end()])
            return Closing(m.group(1))

        m = re_empty.match(substream)
        if m:
            self.updatePos(substream[:m.end()])
            return Closing()

        raise GAFexception(GAFEXP_UNKNOWN_CHAR, self)

    def eval(self, **table):
        """ Substitute objects in table into template
and return ASN1 result."""
        for v in table.values():
            assert isinstance(v, str), "Objects must be strings"
        missing = self.objects.difference(set(table))
        if missing:
            raise ValueError("Missing objects: %s" % ', '.join(missing))
        return evalValue(self.tree, table)


def len2as(l, t):
    """ Convert length to simple|der|dgi representation according to t """
    assert l >= 0, "Length must be nonnegative integer"
    if t == LV.SIMPLE:
        assert l < 0x100, "Simple length too big"
        return chr(l)
    elif t == LV.DGI:
        assert l < 0x10000, "DGI length too big"
        if l < 0xFF:
            return chr(l)
        else:
            return '\xFF' + pack(">H", l)
    elif t == LV.DER:
        if l < 0x80:
            return chr(l)
        else:
            res = []
            while l > 0:
                l, idx = divmod(l, 256)
                res.insert(0, idx)
            l = len(res)
            assert l < 0x80, "DER length too big"
            return chr(0x80+l) + ''.join([chr(x) for x in res])
    else:
        raise TypeError("Wrong LV type")


def evalValue(tree, table):
    value = ''
    for item in tree:
        if isinstance(item, str):
            value += item
        elif isinstance(item, LV):
            subvalue = evalValue(item.value, table)
            value += len2as(len(subvalue), item.lenCoding) + subvalue
        else:  # object
            value += table[item.Id]
    return value


class LV:
    (SIMPLE, DER, DGI) = range(3)
    OpenP = {'[': SIMPLE,
             '(': DER,
             '{': DGI}
    CloseP = {']': SIMPLE,
              ')': DER,
              '}': DGI}

    def __init__(self, lenCoding, value):
        self.lenCoding = lenCoding
        self.value = value


class Obj:
    def __init__(self, Id):
        self.Id = Id


class Closing:
    """ class representing end of stream or closing of LV """
    def __init__(self, c=None):
        if c is None:
            self.c = None
        else:
            self.c = LV.CloseP[c]

__all__ = ['GAF', 'GAFexception']

# in order to run test, just type on cmdline: python gaf.py
# you should see 'Ran 1 test in 0.002s OK'


class TestGAF(unittest.TestCase):
    def test_install(self):
        """ Install for install example """
        templ = """
80E6 0C00 #[
  #($aid_pack)  -- package AID
  #($aid_class) -- class AID
  #($aid_inst)  -- instance AID
  #(808000)     -- privileges
  #(
    EF #(
        A0#(
          A5#(
            80#(C0)
            81#(80)
            82#(80)))
       )
    C9 #(82020088 830180 87028800 81020255 4801EA
        'and a lot of garbage in order to have length of C9 value'
        ' be over 128 bytes and we will see der encoding length,'
        ' now it could  be enough, couldn' 27 't it?')
        -- do you see the trick with apostrophe in literal?
    EA #(80 #(0000000000 #(01 $MSL) #($TAR)00))
 )
  #()             -- token: empty
]"""
        d = {'aid_pack': unhexlify('A0000001515350'),
             'aid_class': unhexlify('A000000151535041'),
             'aid_inst': unhexlify('A000000298C00011'),
             'MSL': chr(0x16),
             'TAR': unhexlify('C00011')}
        g = GAF(templ)
        apdu = g.eval(**d)
        self.assertEqual(apdu, unhexlify('80E60C00EB07A000000151535008A00000015153504108A000000298C000110380800081CAEF0DA00BA5098001C0810180820180C981A78202008883018087028800810202554801EA616E642061206C6F74206F66206761726261676520696E206F7264657220746F2068617665206C656E677468206F662043392076616C7565206265206F7665722031323820627974657320616E642077652077696C6C207365652064657220656E636F64696E67206C656E6774682C206E6F7720697420636F756C642020626520656E6F7567682C20636F756C646E27742069743FEA0F800D000000000002011603C000110000'))
        
if __name__ == '__main__':
    unittest.main()
