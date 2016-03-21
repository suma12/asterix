""" asterix/SCP02.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com, petr.tobiska@gemalto.com

This file is part of asterix, a framework for  communication with smartcards
 based on pyscard. This file contains implementation of Global platform
 SCP02 protocol.

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
"""

import re
from binascii import hexlify, unhexlify
from struct import pack
# PyCrypto
from Crypto.Cipher import DES, DES3
# pyscard
from smartcard.System import readers
from smartcard.CardConnectionDecorator import CardConnectionDecorator
# asterix
from formutil import l2s, s2l, partition, bxor, pad80, unpad80
from mycard import ISOException
from GAF import GAF
__all__ = ( 'SCP02', 'SCP02Connection' )

ZERO8 = '\0' * 8
ZERO12 = '\0' * 12
INS_INIT_UPDATE = 0x50
INS_EXT_AUTH    = 0x82
# masks for "i" parameter
M_BASEKEY    = 0x01    # 1: 3 base keys; 0: 1 base key
M_CMAC_MODIF = 0x02    # 1: C-MAC on umodified APDU; 0: on modified
M_INIT_MODE  = 0x04    # 1: initiation mode explicit; 0: implicit
M_ICV        = 0x08    # 1: icv set to MAC over AID; 0: icv set to zero
M_ICV_ENC    = 0x10    # 1: encrypt icv for next MAC; 0: do not modify
M_RMAC       = 0x20    # 1: R-MAC support
M_PSEUDO     = 0x40    # 1: card challenge pseudorandom; 0: unspecified
# mask for SL
SL_CMAC         = 0x01
SL_CENC         = 0x02
SL_RMAC         = 0x10
  
class DEK( object ):
    """ Representation of DEK for en/de-cryption of sensitive data"""
    def __init__( self, keyValue ):
        assert len( keyValue ) in ( 16, 24 ), "Wrong length of 3DES key"
        self.key = DES3.new( keyValue, DES.MODE_ECB )
        self.zAES = False

    def encrypt( self, data ):
        """Encrypt sensitive data by DEK. Data must be BS-aligned.
No padding added."""
        assert len( data ) % 8 == 0, "Data length not multiple of 8."
        return self.key.encrypt( data )

    def decrypt( self, data ):
        """Decrypt sensitive data by DEK. Data must be BS-aligned.
No padding removed."""
        assert len( data ) % 8 == 0, "Data length not multiple of 16"
        return self.key.decrypt( data )

class SCP02:
    """ Implementation of SCP02 calculation. """

    def __init__( self, **kw ):
        """Constructor of SCP02 object.
Expected parameters (in dict):
  i            - parameter of SCP02, (u8, default 0x55)
  SD_AID       - AID of security domain to authenticate to (string)
                 default unhexlify('A000000151000000')
  base key(s) for session keys derivation, mandatory, strings 16B long
    base_KEY                         - for i & M_BASEKEY == 0
    base_S_ENC, base_S_MAC, base_DEK - for i & M_BASEKEY != 0
  keyVer       - key version, (uint8, default 0x20)
  seqCounter   - sequence counter, (uint16, default 0x0000)
  diverData    - bytes 1-10 of Init Update response (string 10B long,
                 default '\0'*10)
"""
        self.i = kw.get( 'i', 0x55 ) # default value
        self.SD_AID = kw.get( 'SD_AID', unhexlify('A000000151000000'))
        assert 5 <= len( self.SD_AID ) and len( self.SD_AID ) <= 16, \
            "Wrong AID length: %d" % len( self.SD_AID )
        
        keylist = self.i & M_BASEKEY == 0x00 and ( 'base_KEY', ) \
                or ( 'base_S_ENC', 'base_S_MAC', 'base_DEK' )
        for k in keylist:
            assert k in kw, "Mandatory key %s missing" % k
            assert len( kw[k] ) == 16, \
                "Wrong %s length: %d" % ( k, len( kw[k] ))
            self.__dict__[ k ] = kw[k]

        self.keyVer = kw.get( 'keyVer', 0x20 ) # default value

        seqCounter = kw.get( 'seqCounter', 0 )
        assert 0 <= seqCounter and seqCounter < 0x10000, \
            "Wrong seq. counter value %X" % seqCounter
        self.seqCounter = pack( ">H", seqCounter )

        self.diverData = kw.get( 'diverData', '\0'*10 )
        assert len( self.diverData ) == 10, \
            "Wrong length of diver. data: %d" % len( self.diverData )

    def initUpdate( self, host_challenge = '\0'*8, logCh = 0 ):
        """ Return APDU for Initial Update (as list[ uint8 ]).
Parameters:
    host_challenge (optional, default '0000000000000000')
    logCh - logical channel (optional, default 0)
 """
        assert 0 <= logCh and logCh < 20, "Wrong log. channel: %d" % logCh
        self.logCh = logCh
        assert len( host_challenge ) == 8, \
            "Wrong length of host challenge: %d" % len( host_challenge )
        self.host_challenge = host_challenge

        apdu = [ self.CLA( False ), INS_INIT_UPDATE, self.keyVer, 0, 8 ] +\
               [ ord( c ) for c in self.host_challenge ]
        return apdu

    def initUpdateResp( self, card_challenge = None ):
        """ Return expected response to Initial Update.
Parameter:
  card_challenge - card challenge if i & M_PSEUDO == 0 """
        self.deriveKeys( card_challenge )
        return self.diverData + self.keyVer + '\x02' + self.seqCounter + \
            self.card_challenge + self.card_cryptogram

    def parseInitUpdate( self, apdu_s ):
        """ Parse Init Update APDU (as string) and if correct, set
log. channel and host challenge from it. """
        pass

    def parseInitUpdateResp( self, resp ):
        """ Parse response to Init Update and if correct set diverData,
seqCounter, and card_challenge from it.
resp     - response (list[u8])
Return received seqCounter if different from the expected one, otherwise None
Raise exception in case of wrong response. """
        assert len( resp ) == 28, \
            "Wrong response length to Init Update: %d" % len( resp )
        diverData, keyVer, const02, seqCounter, card_chal, card_cryptogram =\
            partition( l2s( resp ), ( 10, 11, 12, 14, 20 ))
        assert keyVer == chr( self.keyVer ), \
            "Different key version in Init Update response"
        assert const02 == '\x02', "Wrong protocol number"
        self.seqCounter = seqCounter

        self.deriveKeys( card_chal )
        if self.i & M_PSEUDO:
            assert card_chal == self.card_challenge,\
                "Different card challenge"
        assert card_cryptogram == self.card_cryptogram, \
            "Different card cryptogram"
        
    def extAuth( self, SL = 1 ):
        """ Build Ext Auth APDU. """
        assert SL & ~( SL_CMAC | SL_CENC | SL_RMAC ) == 0, "Wrong SL %02X" % SL
        self.isCMAC = SL & SL_CMAC != 0
        self.isENC = SL & SL_CENC != 0
        self.isRMAC = SL & SL_RMAC != 0
        assert self.isENC <= self.isCMAC, "Wrong SL %02X" % SL
        if self.i & M_CMAC_MODIF:
            header = '\x80' + chr(INS_EXT_AUTH) + chr(SL) + '\0\x08'
        else:  # on modified APDU
            header = '\x84' + chr(INS_EXT_AUTH) + chr(SL) + '\0\x10'
        mac = self.calcMAC_1d( header + self.host_cryptogram, True )
        apdu = [ self.CLA(), INS_EXT_AUTH, SL, 0, 0x10 ] + \
               [ ord(x) for x in ( self.host_cryptogram + mac )]
        return apdu

    def parseExtAuth( self, apdu ):
        """ Parse Ext Auth APDU (as string) and check challenge, cryptogram and MAC. """
        pass

    def wrapAPDU( self, apdu ):
        """ Wrap APDU for SCP02, i.e. calculate MAC and encrypt.
Input APDU and output APDU are list of uint8. """
        lc = len( apdu ) - 5
        assert len( apdu ) >= 5, "Wrong APDU length: %d" % len( apdu )
        assert len( apdu ) == 5 or apdu[4] == lc, \
           "Lc differs from length of data: %d vs %d" % ( apdu[4], lc )

        cla = apdu[0]
        b8 = cla & 0x80
        if cla & 0x03 > 0 or cla & 0x40 != 0:
            # nonzero logical channel in APDU, check that are the same
            assert cla == self.CLA( False, b8 ), "CLA mismatch"
        scla = b8 | 0x04  # CLA without log. ch. but with secure messaging
        sapdu = l2s( apdu )
        # CLA without log. channel can be 80 or 00 only
        if self.isCMAC:
            if self.i & M_CMAC_MODIF: # CMAC on unmodified APDU
                mlc = lc
                clac = chr( b8 )
            else:                     # CMAC on modified APDU
                mlc = lc + 8
                clac = chr( b8 + 0x04 )
            mac = self.calcMAC_1d( clac + sapdu[1:4] + chr(mlc) + sapdu[5:] )
            mac = [ ord(x) for x in mac ]
            if self.isENC:
                k = DES3.new( self.ses_ENC, DES.MODE_CBC, ZERO8 )
                data = s2l( k.encrypt( pad80( sapdu[5:], 8 )))
                lc = len( data )
            else:
                data = apdu[5:]
            lc += 8
            apdu = [ self.CLA( True, b8 )] + apdu[1:4] + [ lc ] + data + mac
        return apdu

    def unwrapAPDU( self, apdu ):
        """ Parse MACed/encrypted APDU, decipher and check MAC. """
        raise AssertError( "Not implemented yet" )

    def wrapResp( self, resp, sw1, sw2 ):
        """ Wrap expected response as card would do. Currently no action"""
        return resp, sw1, sw2

    def unwrapResp( self, resp, sw1, sw2 ):
        """ Unwrap response. Currently no action"""
        return resp, sw1, sw2

    def wrapData( self, data, zPad = False ):
        """ Cipher data by DEK. """
        if zPad: data = pad80( data )
        assert len( data ) % 8 == 0, "Sensitive data must be BS padded"
        k = DES3.new( self.ses_DEK, DES.MODE_ECB )
        return k.encrypt( data )
 
    def unwrapData( self, data, zPad = False ):
        """ Uncipher data by DEK. """
        assert len( data ) % 8 == 0, "Sensitive data must be BS padded"
        k = DES3.new( self.ses_DEK, DES.MODE_ECB )
        ddata = k.decrypt( data )
        if zPad:
            return unpad80( ddata, 8 )
        else:
            return ddata
 
    def deriveKeys( self, card_challenge ):
        """ Derive session keys and calculate host_ and card_ cryptograms."""

        ## session keys derivation
        k = DES3.new( self.i & M_BASEKEY and self.base_S_MAC or self.base_KEY,
                      DES.MODE_CBC, IV=ZERO8 )
        self.ses_C_MAC = k.encrypt( unhexlify("0101") + self.seqCounter + \
                                    ZERO12 )
        k = DES3.new( self.i & M_BASEKEY and self.base_S_MAC or self.base_KEY,
                      DES.MODE_CBC, IV=ZERO8 )
        self.ses_R_MAC = k.encrypt( unhexlify("0102") + self.seqCounter + \
                                    ZERO12 )
        
        k = DES3.new( self.i & M_BASEKEY and self.base_DEK or self.base_KEY,
                      DES.MODE_CBC, IV=ZERO8 )
        self.ses_DEK = k.encrypt( unhexlify("0181") + self.seqCounter + ZERO12 )

        k = DES3.new( self.i & M_BASEKEY and self.base_S_ENC or self.base_KEY,
                      DES.MODE_CBC, IV=ZERO8 )
        self.ses_ENC = k.encrypt( unhexlify("0182") + self.seqCounter + ZERO12 )
        
        # key for MAC encryption
        if self.i & M_ICV_ENC:
            self.k_icv = DES.new( self.ses_C_MAC[:8], DES.MODE_ECB )

        ## card cryptogram calculation
        if self.i & M_PSEUDO:
            self.card_challenge = self.calcMAC_1d( self.SD_AID, True )[:6]
        else:
            assert len( card_challenge ) == 6,\
                "Wrong length or missing card challenge (mandatory)" 
            self.card_challenge = card_challenge
            
        self.host_cryptogram = self.calcMAC_3d( self.seqCounter + \
                                                self.card_challenge + \
                                                self.host_challenge )
        self.card_cryptogram = self.calcMAC_3d( self.host_challenge + \
                                                self.seqCounter + \
                                                self.card_challenge )

    def CLA( self, zSecure = True, b8 = 0x80 ):
        """ Return CLA byte corresponding to logical channel, for 
secured/unsecured APDU. """
        if self.logCh < 4:
            return b8  + self.logCh + ( zSecure and 0x04 or 0x00 )
        else:
            return b8 + 0x40 + (self.logCh - 4) + ( zSecure and 0x20 or 0x00 )

    def calcMAC_1d( self, s, zResetICV = False ):
        " Pad string and calculate MAC according to B.1.2.2 - " +\
            "Single DES plus final 3DES """
        e = DES.new( self.ses_C_MAC[:8], DES.MODE_ECB )
        d = DES.new( self.ses_C_MAC[8:], DES.MODE_ECB )
        s = pad80( s, 8 )
        q = len( s ) / 8
        h = zResetICV and ZERO8 or self.icv
        for i in xrange(q):
            h = e.encrypt( bxor( h, s[8*i:8*(i+1)] ))
        h = d.decrypt( h )
        h = e.encrypt( h )
        self.icv = ( self.i & M_ICV_ENC ) and self.k_icv.encrypt( h ) or h
        return h

    def calcMAC_3d( self, s ):
        """ Pad string and calculate MAC according to B.1.2.1 - Full 3DES """
        e = DES3.new( self.ses_ENC, DES.MODE_ECB )
        s = pad80( s, 8 )
        q = len( s ) / 8
        h = ZERO8
        for i in xrange(q):
            h = e.encrypt( bxor( h, s[8*i:8*(i+1)] ))
        return h

    def closeSession():
        """ Clear all session data (session keys, logCh, challanges). """
        pass

    def getDEK( self ):
        return DEK( self.ses_DEK )

class SCP02Connection( CardConnectionDecorator ):
    """ Implements SCP02 as CardConnectionDecorator. """
    def __init__( self, connection, **kw ):
        self.scp = SCP02( **kw )
        self.connection = connection
        CardConnectionDecorator.__init__( self, connection )
        if 'GAFdict' in kw:
            assert isinstance( kw['GAFdict'], dict ), "GAF dictionary expected"
            self.objects = kw['GAFdict']
        else:
            self.objects = {}

    def mut_auth( self, SL, logCh = 0, **kw ):
        """ Perform mutual authentication.
Optional paramters in kw:
 - host_challenge
 """
        # select SD
        self.scp.logCh = logCh
        aid = self.scp.SD_AID
        cla = self.scp.CLA( False, 0 )
        apdu = [ cla, 0xA4, 0x04, 0, len( aid ) ] + \
               [ ord( x ) for x in aid ]
        resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        if sw1 == 0x61:
            apdu = [ cla, 0xC0, 0, 0, sw2 ]
            resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        sw = ( sw1 << 8 ) + sw2
        if sw != 0x9000 : raise ISOException( sw )

        # Initial update
        host_challenge = kw.get( 'host_challenge', '\0'*8 )
        apdu = self.scp.initUpdate( host_challenge, logCh )
        resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        if sw1 == 0x61:
            apdu = [ cla, 0xC0, 0, 0, sw2 ]
            resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        sw = ( sw1 << 8 ) + sw2
        if sw != 0x9000 : raise ISOException( sw )
        # parse response to initial update in order to derive keys
        self.scp.parseInitUpdateResp( resp )

        # External authenticate
        apdu = self.scp.extAuth( SL )
        resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        sw = ( sw1 << 8 ) + sw2
        if sw != 0x9000 : raise ISOException( sw )

    def transmit( self, apdu, protocol=None):
        """ Wrap APDU and transmit to the card. """
        apdu_w = self.scp.wrapAPDU( apdu )
        resp, sw1, sw2 = CardConnectionDecorator.transmit( self,
                                                           apdu_w, protocol )
        if sw1 == 0x61:
            resp, sw1, sw2 = self.getResponse( sw2 )
        return resp, sw1, sw2

    def getResponse( self, sw2 ):
        """ Get Response from the last APDU."""
        apdu = [ self.scp.CLA( False, 0 ), 0xC0, 0, 0, sw2 ]
        return CardConnectionDecorator.transmit( self, apdu )

    def send( self, templ, **kw ):
        """ Evaluate GAF and transmit as APDU
templ   - a GAF template to evaluate
kw      - GAF dictionary (updates dictionary from SCP02Connection.__init__)
Return ( resp, SW ) as ( str, int )"""
        objects = self.objects.copy()
        objects.update( kw )
        papdu = s2l( GAF( templ ).eval( **objects ))
        apdu = self.scp.wrapAPDU( papdu )
        resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        if sw1 == 0x6C and len( papdu ) == 5:
            papdu[4] = sw2
            apdu = self.scp.wrapAPDU( papdu )
            resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        elif sw1 == 0x61:
            resp, sw1, sw2 = self.getResponse( sw2 )
        resp, sw1, sw2 = self.scp.unwrapResp( resp, sw1, sw2 )
        sw = ( sw1 << 8 ) + sw2
        return l2s( resp ), sw

    def getDEK( self ):
        return DEK( self.scp.ses_DEK )

# Example of usage: (c is instance of smartcard.CardConnection from pyscard)
# scp_param = { 'i': 0x55,
#               'keyVer': 0x20,
#               'base_S_ENC': 'abcdefghHGFEDCBA',
#               'base_S_MAC': 'ABCDEFGHhgfedcba' ,
#               'base_DEK': '0123456789ABCDEF',
#               'SD_AID': unhexlify( 'A000000151000000' ) }
# sc = SCP02.SCP02Connection( c, **scp_param )
# sc.mut_auth( 1 )
# delete_apdu = [ ord(x) for x in unhexlify( "80E40000124F10A0000000034411512361010154455354" )]
# sc.transmit( delete_apdu )
