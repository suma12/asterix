"""APDU.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com, petr.tobiska@gemalto.com

This file is part of asterix, a framework for  communication with smartcards
 based on pyscard. This file implements handfull APDU commands.

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

References:
[GP CS] GlobalPlatform Card Specification, Version 2.2.1, Jan 2011
[GP AmD] Secure Channel Protocol 03, Card Specification v 2.2 - Amendment D,
         Version 1.1, Sep 2009

"""

import re
from struct import pack, unpack
from binascii import hexlify, unhexlify
# PyCrypto
from Crypto.Cipher import DES, DES3, AES
# pyscard
from smartcard.ATR import ATR
# asterix
from formutil import l2s, derLen, s2int, split2TLV, findTLValue, swapNibbles
from GAF import GAF
from mycard import ISOException, resetCard
__all__ = ( 'putKey', 'storeDataPutKey',
            'selectApplet', 'openLogCh', 'closeLogCh',
            'getStatus', 'getExtCardRes', 'getData',
            'selectFile', 'readBinary', 'readRecord',
            'cardInfo', 'KeyType' )

INS_MANAGE_LOGCH = 0x70
INS_SELECT       = 0xA4
INS_READBIN      = 0xB0
INS_READREC      = 0xB2
INS_GETDATA      = 0xCA    
INS_PUTKEY       = 0xD8
INS_STOREDATA    = 0xE2
INS_GETSTATUS    = 0xF2

class KeyType:
    """Key types as defined in [GP CS] Tab 11.16"""
    # subset of currently supported keys
    DES_IMPLICIT = 0x80
    TDES_CBC     = 0x82
    DES_ECB      = 0x83
    DES_CBC      = 0x84
    AES          = 0x88

def calcKCV( keyValue, zAES = False ):
    """Calculate KCV for symmetric key.
keyValue - key values as string (DES, 3DES2k, 3DES3k, AES)
zAES     - True if key is AES (i.e. encrypt block of '01' instead of '00')

Return 3B-long string."""
    if zAES:
        assert len( keyValue ) in ( 16, 24, 32 ), "Wrong length of AES key"
        block = '\x01'*16
        tkey = AES.new( keyValue, AES.MODE_ECB )
    else:
        assert len( keyValue ) in ( 8, 16, 24 ), "Wrong length of (3)DES key"
        block = '\x00'*8
        if len( keyValue ) == 8:
            tkey = DES.new( keyValue, DES.MODE_ECB )
        else:
            tkey = DES3.new( keyValue, DES.MODE_ECB )
    return tkey.encrypt( block )[:3]

def putKey( oldKeyVersion, newKeyVersion, keyId, keyComponents,
            zMoreCmd = False, zMultiKey = False, keyDEK = None,
            lenMAC = 8 ):
    """Build APDU for PUT KEY command.
oldKeyVersion - key version to be replaced. If zero, new key is created.
newKeyVersion - key version of key being put
keyId         - id of the 1st key being put
keyComponents - list of key components being put. 
                Each componet is a tuple of key type (u8) and value (string).
zMoreCmd      - P1.b8, signals if there is more commands
zMultiKey     - P2.b8, signals if more than one component being put
keyDEK        - KIK or DEK key. keyDEK.encrypt( data ) called to encrypt
                (including padding) key component value if not None.
                If has attribute zAES and keyDEK.zAES evaluates as True, it is
                considered as AES key and [GP AmD] 7.2 formatting is used.
lenMAC        - length of CMAC for AES. Applicable if AES key with key id=0x02 (KID)
                and key version 0x01-0x0F or 0x11 is being put with AES keyDEK
                (see ETSI 102.226 rel 9+, 8.2.1.5 )

Returns APDU built (as list of u8).

See [GP CS] 11.8 and [GP AmD] 7.2 for reference.
See [GP CS] Tab 11.16 for coding of key type.
Currently only Format1 supported.
"""
    # sanity check
    assert 0 <= oldKeyVersion < 0x80
    assert 0 < newKeyVersion < 0x80
    assert 0 < keyId < 0x80
    assert len( keyComponents ) > 0
    assert lenMAC in ( 4, 8 )

    P1 = ( zMoreCmd and 0x80 or 0 ) | oldKeyVersion
    P2 = ( zMultiKey and 0x80 or 0 ) | keyId

    data = chr( newKeyVersion )
    for kc in keyComponents:
        keyType, keyVal = kc
        assert 0 <= keyType < 0xFF
        
        if keyDEK:
            encValue = keyDEK.encrypt( keyVal )
            # for AES as keyDEK, prepend length of component
            if 'zAES' in dir( keyDEK ) and keyDEK.zAES:
                encValue = derLen( keyVal ) + encValue
                # see ETSI 102.226 rel 9+, 8.2.1.5
                if keyType == KeyType.AES and keyId == 2 and \
                   newKeyVersion in range( 0x01, 0x10 ) + [ 0x11 ]:
                    encValue += chr( lenMAC )
        else:
            encValue = keyVal
        # calculate KCV
        if keyType in ( KeyType.DES_IMPLICIT, KeyType.TDES_CBC,
                        KeyType.DES_ECB, KeyType.DES_CBC,
                        KeyType.AES ):
            kcv = calcKCV( keyVal, keyType == KeyType.AES )
        else:
            kcv = ''

        data += chr( keyType ) + derLen( encValue ) + encValue + derLen( kcv ) + kcv
        keyId += 1

    apdu = [ 0x80, INS_PUTKEY, P1, P2, len( data ) ] + [ ord(x) for x in data ]
    return apdu

def storeDataPutKeyDGI( keyVer, keyComponents, keyId = 1, keyDEK = None ):
    """Build DGI for Store Data for Put Key.
keyVer        - key version of key being created
keyComponents - list of key components being put. 
                Each componet is a tuple of key type (u8), value (string) 
                and optionally Key Usage Qualifier and Key Access 
                (u8, defaults 0x18, 0x14 or 0x48 for key UQ, 0x00 for key ac.)
keyId         - id of the 1st key being created (optional, u8, default 1)
keyDEK        - KIK or DEK key. keyDEK.encrypt( data ) called to encrypt
                (including padding) key component value if not None.
                If has attribute zAES and keyDEK.zAES evaluates as True, it is
                considered as AES key and [GP AmD] 7.2 formatting is used.

Returns DGIs built (as list of string).
See GP 2.2.1 AmA 4.10.2 for reference.
"""
    # sanity check
    assert 0 < keyVer and keyVer < 0x80
    assert 0 < keyId and keyId < 0x80
    assert len( keyComponents ) > 0

    KeyUQ = ( None, 0x38, 0x34, 0xC8 ) # see GP 2.2.1, 11.1.9
    templ = """ B9 #( 95#($keyUQ) 96#($keyAc) 80#($keyType) 81#($keyLen)
                82#($keyId) 83#($keyVer) 84#($KCV))"""
    d = { 'keyVer': chr(keyVer) }
    B9 = ''
    dgi8113 = []
    for kc in keyComponents:
        assert len( kc ) in ( 2, 4 ), "wrong keyComponent" + kc.__str__()
        if len( kc ) == 2:
            keyType, keyVal = kc
            keyUQ = 1 <= keyId <= 3 and KeyUQ[keyId] or 0xFF
            keyAc = 0x00
        else:
            keyType, keyVal, keyUQ, keyAc = kc
        d['keyLen'] = chr(len( keyVal ))
        assert 0 <= keyType < 0xFF
        if keyType in ( KeyType.DES_IMPLICIT, KeyType.TDES_CBC,
                        KeyType.DES_ECB, KeyType.DES_CBC,
                        KeyType.AES ):
            d['KCV'] = calcKCV( keyVal, keyType == KeyType.AES )
        else:
            d['KCV'] = ''
        d['keyId'] = chr( keyId )
        for k in ( 'keyType', 'keyUQ', 'keyAc', 'keyId' ):
            d[ k ] = chr( locals()[k] )
        tlv = GAF( templ ).eval( **d )
        if keyDEK:
            encValue = keyDEK.encrypt( keyVal )
        else:
            encValue = keyVal
        B9 += tlv
        dgi8113.append( pack( ">HB", 0x8113, len( encValue )) + encValue )
        keyId += 1
    return( pack( ">HB", 0x00B9, len( B9 )) + B9, dgi8113 )

def storeDataPutKey( keyVer, keyComponents, keyId = 1, keyDEK = None ):
    """Build APDU for Store Data for Put Key.
keyVer, keyComponents, keyId and keyDEK as in storeDataPutKeyDGI.
Return APDU a u8 list."""
    dgi00B9, dgi8113 = storeDataPutKeyDGI( keyVer, keyComponents, keyId, keyDEK )
    data = dgi00B9 + ''.join( dgi8113 )
    assert len( data ) < 256, "Longer Put Key not implemented"
    P1 = 0x88
    P2 = 0
    apdu = [ 0x80, INS_STOREDATA, P1, P2, len( data ) ] +\
           [ ord(x) for x in data ]
    return apdu

def selectApplet( c, AID, logCh = 0 ):
    """ Select applet on a given logical channel or
open new log. channel if logCh is None. """
    if logCh is None:
        logCh = openLogCh( c )
    # select the Applet on the given logical channel
    apdu = [ logCh, INS_SELECT, 4, 0, len( AID ) ] + [ ord( x ) for x in AID ]
    resp, sw1, sw2 = c.transmit( apdu )
    if sw1 == 0x6C and len( AID ) == 0:
        apdu = [ logCh, INS_SELECT, 4, 0, sw2 ]
        resp, sw1, sw2 = c.transmit( apdu )
    if( sw1 == 0x61 ):
        apdu = [ logCh, 0xC0, 0, 0, sw2 ]
        resp, sw1, sw2 = c.transmit( apdu )
    sw = ( sw1 << 8 ) + sw2
    if sw != 0x9000 : raise ISOException( sw )
    respdata = l2s( resp )
    # close channel
    return ( respdata, logCh )

def openLogCh( c ):
    """ Manage channel to open logical channel. """
    apdu = [ 0, INS_MANAGE_LOGCH, 0, 0, 1 ]
    resp, sw1, sw2 = c.transmit( apdu )
    sw = ( sw1 << 8 ) + sw2
    if sw != 0x9000:
        raise ISOException( sw )
    return resp[0]

def closeLogCh( c, logCh ):
    apdu = [ 0, INS_MANAGE_LOGCH, 0x80, logCh, 0 ]
    resp, sw1, sw2 = c.transmit( apdu )
    sw = ( sw1 << 8 ) + sw2
    if sw != 0x9000:
        raise ISOException( sw )

class GetStatusData:
    """ Represent and interpret data from Get status for Packages and Modules"""
    def __init__( self, respdataPM, respdataApp ):
        ind = 0
        self.packages = []
        while len( respdataPM ) > ind:
            length = respdataPM[ind]
            pack_aid = l2s( respdataPM[ ind+1: ind+1+length])
            ind += length + 1
            lcs = respdataPM[ ind ]
            priv = respdataPM[ ind+1 ]
            nmod = respdataPM[ ind+2 ]
            ind += 3
            mods = []
            for i in xrange( nmod ):
                length = respdataPM[ind]
                mods.append( l2s( respdataPM[ ind+1: ind+1+length]))
                ind += length + 1
            self.packages.append( { 'pack_aid': pack_aid,
                                    'lcs': lcs,
                                    'priv': priv,
                                    'modules': mods } )
        ind = 0
        self.insts = []
        while len( respdataApp ) > ind:
            length = respdataApp[ind]
            app_aid = l2s( respdataApp[ ind+1: ind+1+length])
            ind += length + 1
            lcs = respdataApp[ ind ]
            priv = respdataApp[ ind+1 ]
            ind += 2
            self.insts.append( { 'app_aid': app_aid,
                                 'lcs': lcs,
                                 'priv': priv } )
    def __str__( self ):
        res = ''
        for p in self.packages:
            res += "Package AID: %s %02X %02X\n" % \
                   ( hexlify( p['pack_aid'] ).upper().ljust(32),
                     p['lcs'], p['priv'] )
            for m in p['modules']:
                res += "      module %s\n" % hexlify( m ).upper().ljust(32)
        for p in self.insts:
            res += "Insts AID  : %s %02X %02X\n" % \
                   ( hexlify( p['app_aid'] ).upper().ljust(32),
                     p['lcs'], p['priv'] )
        return res
    
def getStatus( sc, AID_pref = '' ):
    """ Issue GET STATUS apdu for packages and modules, and instances. """
    res = {}
    for P1 in ( 0x10, 0x40 ):
        apdu = [ 0x80, INS_GETSTATUS, P1, 0, 2+len( AID_pref ), 0x4F,
                 len(AID_pref) ] + [ ord( x ) for x in AID_pref ]
        respdata, sw1, sw2 = sc.transmit( apdu )
        sw = ( sw1 << 8 ) + sw2
        while sw == 0x6310:
            apdu = [ 0x80, INS_GETSTATUS, P1, 1, 2+len( AID_pref ), 0x4F,
                     len(AID_pref) ] + [ ord( x ) for x in AID_pref ]
            resp, sw1, sw2 = sc.transmit( apdu )
            respdata += resp
            sw = ( sw1 << 8 ) + sw2
        if sw != 0x9000: raise ISOException( sw )
        res[P1] = respdata
    return GetStatusData( res[0x10], res[0x40] )

def getData( c, tag ):
    P1 = tag >> 8
    P2 = tag & 0xFF
    apdu = [ 0x80, INS_GETDATA, P1, P2, 0 ]
    resp, sw1, sw2 = c.transmit( apdu )
    if sw1 == 0x6C:
        apdu[4] = sw2
        resp, sw1, sw2 = c.transmit( apdu )
    sw = ( sw1 << 8 ) + sw2
    if sw != 0x9000: raise ISOException( sw )
    return l2s( resp )

def getExtCardRes( c ):
    """ Issue GET DATA with tag FF21 in order to receive Extended
Card Resources (GP 2.2.1, 11.3 & ETSI TS 102.226, 8.2.1.7).
Returns [ num. of install applets, free NVM, free RAM ]"""
    # CLA = 0x00: return only value
    # CLA = 0x80: return TLV, i.e. 0xFF21 #( value )
    apdu = [ 0x80, INS_GETDATA, 0xFF, 0x21, 0 ] 
    resp, sw1, sw2 = c.transmit( apdu )
    if sw1 == 0x6C:
        apdu[4] = sw2
        resp, sw1, sw2 = c.transmit( apdu )
    sw = ( sw1 << 8 ) + sw2
    if sw != 0x9000: raise ISOException( sw )
    payload = l2s( resp )
    result = [ s2int( findTLValue( payload, ( 0xFF21, tag ))) for
               tag in ( 0x81, 0x82, 0x83 )]
    return result

def selectFile( c, path, logCh = 0 ):
    """ Select file by path from MF or MF for empty path """
    if len( path ) > 0:
        apdu = [ logCh, INS_SELECT, 8, 4, len( path )] + [ ord(x) for x in path ]
    else:
        apdu = [ logCh, INS_SELECT, 0, 4, 2, 0x3F, 0x00 ]
    resp, sw1, sw2 = c.transmit( apdu )
    if sw1 == 0x61:
        resp, sw1, sw2 = c.transmit([0, 0xC0, 0, 0, sw2])
    sw = ( sw1 << 8 ) + sw2
    if sw != 0x9000:
        raise ISOException( sw )
    return l2s( resp )

def readBinary( c, le, logCh = 0, offset = 0 ):
    """Read Binary on currently selected EF"""
    P1 = ( offset >> 8 ) & 0x7F
    P2 = offset & 0xFF
    apdu = [ logCh, INS_READBIN, P1, P2, le ]
    resp, sw1, sw2 = c.transmit( apdu )
    sw = ( sw1 << 8 ) + sw2
    if sw != 0x9000:
        raise ISOException( sw )
    return l2s( resp )

def readRecord( c, recNum, logCh = 0 ):
    """ Read record from currently selected EF"""
    apdu = [ logCh, INS_READREC, recNum, 4, 0 ]
    resp, sw1, sw2 = c.transmit( apdu )
    if sw1 == 0x6C:
        apdu[4] = sw2
        resp, sw1, sw2 = c.transmit( apdu )
    sw = ( sw1 << 8 ) + sw2
    if sw != 0x9000:
        raise ISOException( sw )
    return l2s( resp )

def cardInfo( c ):
    """Deselect, read EF_DIR, EF_ICCID"""
    resetCard( c )
    histBytes = l2s( ATR( c.getATR()).getHistoricalBytes())
    infoMF = selectFile( c, '' )
    # read EF_ICCID
    infoICCID = selectFile( c, unhexlify( '2FE2' ))
    fileSize = s2int( findTLValue( infoICCID, ( 0x62, 0x80 )))
    assert fileSize == 10, "Wrong size of EF_ICCID"
    iccid = swapNibbles( readBinary( c, fileSize ))
    # read EF_DIR
    infoDIR = selectFile( c, unhexlify( '2F00' ))
    # see ETSI 102.221 11.1.1.4.3 for coding
    fileDesc = findTLValue( infoDIR, ( 0x62, 0x82 ))
    assert len( fileDesc ) == 5 and \
        fileDesc[:2] == '\x42\x21' # linear EF
    recLen, nRec = unpack( ">HB", fileDesc[2:5] )
    dirDO = []
    for recNum in xrange( 1, nRec+1 ):
        try:
            r = readRecord( c, recNum )
            if r == '\xFF'* len( r ): continue
            aid = findTLValue( r, ( 0x61, 0x4F ))
            label = findTLValue( r, ( 0x61, 0x50 ))
            dirDO.append( { 'AID': aid,
                            'label': label } )
        except ISOException:
            break
    # select USIM and try to read IMSI
    if len( dirDO ) == 1:
        aid_usim = dirDO[0]['AID']
    else:
        aids = [ DO['AID'] for DO in dirDO
                 if re.match( DO['label'], 'USIM' )]
        if len( aids ) == 1:
            aid_usim = aids[0]
        else:
            aid_usim = None
    if aid_usim:
        infoUSIM = selectApplet( c, aid_usim )
        infoIMSI = selectFile( c, unhexlify( '7FFF6F07' ))
        try:
            bimsi = readBinary( c, 9 )
            digits = reduce( lambda d, n: d + [ ord(n) & 0x0F, ord(n) >> 4 ],
                             bimsi[ 1:1+ord(bimsi[0])], [] )
            digits.pop(0)          # remove first nibble 8 or 9
            while digits[-1] == 0x0F: digits.pop() # remove trailing F
            imsi = ''.join( [ chr(ord('0')+i) for i in digits ])
        except ISOException:
            imsi = None
    else: imsi = None
    # select default applet and get tags 45 and 42
    selectApplet( c, '' )
    try:
        cin = findTLValue( getData( c, 0x42 ), ( 0x42, ))
    except ISOException:
        cin = None
    try:
        iin = findTLValue( getData( c, 0x45 ), ( 0x45, ))
    except ISOException:
        iin = None
    return histBytes, iccid, dirDO, imsi, iin, cin
