""" asterix/formutil.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com, petr.tobiska@gemalto.com

This file is part of asterix, a framework for  communication with smartcards
 based on pyscard. This file contains formatting utilities.

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
from binascii import hexlify, unhexlify
from struct import pack, unpack
import random
# alternatively: from Crypto.Random import random

__all__ = ( 'l2s', 's2l', 's2int', 'int2s', 's2sDER', 'lpad', 'derLen',
            'readDERlen', 'readDERtag', 'split2TLV', 'printTLV', 'findTLValue',
            'randomBytes', 'swapNibbles', 'partition', 'bxor', 'pad80' )

def l2s( data ):
    """ Transform list of u8 to string. """
    s = ''.join( [ chr(x) for x in data ])
    return s

def s2l( s ):
    """ Transform string to list of u8. """
    return [ ord(x) for x in s ]

def s2int( s, zSign = False ):
    """ Convert string into (big) integer.
zSign = True => interpret as signed integer. """
    i = reduce( lambda x,y: 256*x+y, [ ord(c) for c in s ])
    if zSign and ord(s[0]) >= 0x80:
        i -= 256**len(s)
    return i

def int2s( n, bitlen = 0 ):
    """ Convert (big) integer into string,
 optionally pad to bitlen by zeros (if bitlen > 0), or
 pad as ASN1 integer (if bitlen < 0 )"""
    if n < 0: raise ValueError( "Negative value" )
    if n == 0 and bitlen <= 0: return '\0'
    res = []
    while n > 0:
        n, idx = divmod( n, 256 )
        res.insert( 0, idx )
    if bitlen < 0 and res[0] >= 0x80:
        res.insert( 0, 0 )
    s = ''.join( [ chr(x) for x in res ] )
    if bitlen > 0:
        bytelen = ( bitlen + 7 ) / 8
        s = '\0'*( bytelen - len( s )) + s
    return s

def s2sDER( s ):
    """ Normalize string representing non-negative number
to be valid ASN1 integer representation"""
    s = s.lstrip( '\0' ) # strip leading zeros
    if s == '' or ord(s[0]) >= 0x80:
        s = '\0' + s
    return s

def lpad( s, bitlen ):
    """ Pad string representing Big Endian integer to bitlen block."""
    bytelen = ( bitlen + 7 ) / 8
    return '\0'*( bytelen - len( s )) + s

def derLen( val ):
    """ ASN1 DER representation of len( val )."""
    if isinstance( val, str ):
        l = len( val )
    else: l = val
    if l < 0x80: return chr( l )
    s = int2s( l )
    return chr( 0x80 + len(s)) + s

def readDERtag( data ):
    """ Read ASN1 DER tag from data, returns ( tag, skip ),
tag is u8, u16, u24 ... number depending on number of bytes representing it.
skip is the number of bytes read from data."""
    l = len( data )
    assert l > 0, "Tag beyond data"
    tag = ord(data[0])
    assert tag != 0, "Tag cannot be 0"
    if tag & 0x1F != 0x1F:
        return tag, 1
    skip = 1
    while True:
        assert l > skip, "Tag beyond data"
        b = ord(data[skip])
        tag = 256*tag + b
        skip += 1
        if b < 0x80: return tag, skip
    
def readDERlen( data ):
    """ Reads ASN1 DER length from data, returns ( length, skip ),
skip is the number of bytes read from data."""
    b = ord( data[0] ) 
    if b < 0x80:
        return ( b, 1 )
    skip = b - 0x80
    assert 0 < skip and skip+1 <= len( data ), "Inconsistent DER length"
    return( s2int( data[1:1+skip] ), skip+1 )
        
def split2TLV( data, zTag = True ):
    """ Split data to list of TLVs. Tag & length coding as in ASN1."""
    offset = 0
    tlvs = []
    while offset < len( data ):
        tag = None
        if( zTag ):
            tag, skip = readDERtag( data[offset:] )
            offset += skip
            # tag = ord( data[offset] )
            # assert tag != 0, "Tag cannot be 0"
            # if tag & 0x1F == 0x1F:
            #     assert offset + 2 <= len( data ), "Length beyond data"
            #     tag = unpack( ">H", data[offset:offset+2] )[0]
            #     offset += 2
            # else:
            #     offset += 1
        l, d = readDERlen( data[offset:] )
        offset += d
        assert offset + l <= len( data ), "Length beyond data"
        tlvs.append(( tag, data[offset:offset+l] ))
        offset += l
    return tlvs

def printTLV( data, zTag = True ):
    """ Recursively interpret data as ASN1 TLVs and print them.
zTag = False => no tags on top level."""
    # we process list of triplets ( depth, tag, value ) or depth
    # stored in reverse order
    # we take the last item and try to decompose, if not possible, print it
    TAB = " "*3   # indentation
    result = ''
    toptlv = split2TLV( data, zTag )
    toptlv.reverse()
    tlvs = [ ( 0, t[0], t[1] ) for t in toptlv ]
    while tlvs:
        item = tlvs.pop() # currently processed item
        if isinstance( item, int ):   # closing bracket
            result += ")"
            continue
        d = item[0]
        if item[1] is None: tag = "    "
        elif item[1] < 0x100: tag = "  %02X" % item[1]
        else: tag = "%04X" % item[1]
        tag = '\n' + TAB*d + tag + " #( "
        try:              # try deeper level
            assert item[2] # if value empty, process as non-splittable
            tempTLVs = split2TLV( item[2] )
            # successfull, let's append deeper TLVs
            result += tag
            tlvs.append( d )  # prepare closing bracket
            tempTLVs.reverse()
            tlvs.extend( [ ( d+1, t[0], t[1] ) for t in tempTLVs ])
        except ( AssertionError, IndexError ):
            # deeper split not possible, just print
            result += tag + hexlify( item[2] ).upper() + " )"
    print result[1:] + '\n' # strip leading EOL

def findTLValue( data, tags ):
    """ Parse data and find recursively TLV addressed by tags[0], tags[1]...
Return the value or None if TLV not found.
Raise AssertException if incorrect data."""
    offset = 0
    endoff = len( data )
    for t in tags:
        while offset < endoff:
            tag, skip = readDERtag( data[offset:] )
            offset += skip
            lval, skip = readDERlen( data[offset:] )
            offset += skip
            if tag == t:
                endoff = offset + lval
                break # go to next t in tags
            offset += lval
        else:
            return None
    return data[offset:offset+lval]

def swapNibbles( s ):
    """ Swap nibbles of string s. """
    return ''.join( [ chr((ord(x) >> 4) | (( ord(x) & 0x0F ) << 4 )) for x in s ])
    
def randomBytes( n ):
    """ Generate string of *n* (pseudo)random bytes."""
    return ''.join( [ chr(random.randint(0,255)) for i in xrange( n )])

def partition(alist, indices):
    """ Split alist at positions defined in indices. """
    indices = list( indices )
    return [alist[i:j] for i, j in zip([0]+indices, indices+[None])]

re_pad80_8 = re.compile( r'^(.*)\x80\0{0,7}$' )
re_pad80_16 = re.compile( r'^(.*)\x80\0{0,15}$' )
def pad80( s, BS = 8 ):
    """ Pad bytestring s: add '\x80' and '\0'* so the result to be multiple of BS."""
    l = BS-1 - len( s ) % BS;
    return s + '\x80' + '\0'*l

def bxor( a, b ):
    """ XOR of binary strings a and b. """
    assert len( a ) == len( b ),\
        'String XOR: lengths differ: %d vs %d\n' % (len(a), len(b))
    return ''.join( map( lambda x: chr( ord(x[0]) ^ ord(x[1])) , zip( a, b )))

