"""asterix/SecurePacket.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com, petr.tobiska@gemalto.com
Date: 2014-11-11

This file is part of asterix, a framework for communication with
 smartcards based on pyscard. This file implementes Secure Packet
 according to ETSI 102.225 and 131.115. At the moment, only SMS_PP
 implemented.

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

from struct import pack, unpack
from binascii import hexlify, unhexlify
import re
# PyCrypto
from Crypto.Cipher import DES, DES3, AES
# asterix
from APDU import KeyType
from formutil import l2s

# types of secure packet
( SMS_PP, SMS_CB, CAT_TP, ) = range( 3 )

class SPI:
    """ Constants for SPI """
    CNTR1      = 0x1800   # mask for counter for Cmd
    CNTR1_PR   = 0x0800   # counter present
    CNTR1_HIGH = 0x1000   # counter must be high
    ENC1       = 0x0400   # mask/bit for encryption of Cmd
    CHSUM1     = 0x0300   # mask for checksum for Cmd
    CHSUM1_RC  = 0x0100   #  redundancy check
    CHSUM1_CC  = 0x0200   #  cryptographic checksum
    CHSUM1_DS  = 0x0300   #  digital signature
    SUBMIT     = 0x0020   # mask/bit for SMS_SUBMIT vs. SMS_DELIVERY
    ENC2       = 0x0010   # mask/bit for encryption of PoR
    CHSUM2     = 0x000C   # mask for checksum for PoR
    CHSUM2_RC  = 0x0004   #  redundancy check
    CHSUM2_CC  = 0x0008   #  cryptographic checksum
    CHSUM2_DS  = 0x000C   #  digital signature
    POR        = 0x0003   # mask for PoR
    POR_REQ    = 0x0001   #   PoR required
    POR_ERR    = 0x0002   #   send PoR on error only

class KICD:
    # masks for KIC/KID
    ALGO        = 0x03          # mask for Algo
    ALGO_DES    = 0x01          #  - DES
    ALGO_AES    = 0x02          #  - AES
    ALGO_CRC    = 0x01
    DES_CBC     = 0x00          # DES CBC
    DES3_2k     = 0x04          # 3DES 2k CBC
    DES3_3k     = 0x08          # 3DES 3k CBC
    DES_ECB     = 0x0C          # DES ECB
    CRC16       = 0x00
    CRC32       = 0x04
    def keyInd( self ):
        """ Return index of key. """
        return self.iKICD >> 4
    def __init__( self, iKICD ):
        """ Constructor for KIC/KID object.
 iKICD - coding of KIC or KID (see ETSI 102.225, 5.1.2 and 5.1.3, u8)"""
        iKICD %= 0x100
        self.iKICD = iKICD
        self.keyval = None
        if iKICD & KICD.ALGO == KICD.ALGO_DES:           # DES/3DES key
            b43 = iKICD & 0x0C           # bits 4 and 3 of KIC/KID
            self.keysize = 8 + 2*( b43 % 12 ) # mapping to DES, 3DES 2k, 3DES 3k
            self.cipModule = b43 % 12 and DES3 or DES
            self.MODE = b43 == KICD.DES_ECB and DES.MODE_EBC or DES.MODE_CBC
            self.BS = 8
            self.zAES = False
        elif iKICD & 0x0F == KICD.ALGO_AES:         # AES CBC / CMAC
            self.zAES = True
            self.cipModule = AES
            self.MODE = AES.MODE_CBC
            self.BS = 16
            self.TlenB = 8     # length of CMAC, you may manually change to 4
            self.irrPoly = 0x87            # for CMAC
        else:
            raise ValueError( "Only DES/AES implemented for KIC/KID" )
    def polyMulX( self, poly ):
        """Interpret value as a polynomial over F2m and multiply by the
polynomial x (modulo irreducible polynomial)"""
        if self.zAES:
            vals = list( unpack( ">qq", poly ))
            carry = vals[1] < 0 and 1 or 0
            vals[1] = (( vals[1] << 1 ) % 0x10000000000000000)
            if vals[0] < 0:
                vals[1] ^= self.irrPoly
            vals[0] = (( vals[0] << 1 ) % 0x10000000000000000) + carry
            return pack( ">QQ", *vals )
    def setValue( self, keyvalue ):
        keyvalue = ''.join( keyvalue )
        if self.zAES:
            assert len( keyvalue ) in ( 16, 24, 32 )
            cipher = AES.new( keyvalue, AES.MODE_ECB )
            poly = cipher.encrypt( '\x00'*self.BS )
            self.xorKey1 = self.polyMulX( poly )
            self.xorKey2 = self.polyMulX( self.xorKey1 )
        else:
            if len( keyvalue ) != self.keysize:
                raise ValueError( "KIC/KID=%02X, value length received %d" % \
                                  ( self.iKICD, len( keyvalue )))
        self.keyval = keyvalue

    def cipher( self, data, zEnc ):
        """
Encrypt (zEnc True)/decrypt (zEnc False) data (coded as str) by KIC key.
Data must be padded to BS multiple.
Return as str."""
        assert self.keyval is not None, "KIC/KID value not set"
        assert len( data ) % self.BS == 0, "Data len not multiple of BS"
        data = ''.join( data )
        cipher = self.cipModule.new( self.keyval, self.MODE, IV = '\0'*self.BS )
        if zEnc:
            return cipher.encrypt( data )
        else:
            return cipher.decrypt( data )

    def sign( self, data ):
        """
Sign data (as str) by KID key.
Return signature as str."""
        if self.zAES:
            data = [ ord(x) for x in data ]
            sLB = len( data ) % self.BS
            if( sLB > 0 or len(data) == 0 ):
                data += [ 0x80 ] + [ 0 ]*(self.BS-sLB-1)
                xorkey = self.xorKey2
            else:
                xorkey = self.xorKey1
            for i in xrange( self.BS ):
                data[-self.BS+i] ^= ord( xorkey[i] )
            cipher = AES.new( self.keyval, AES.MODE_CBC, IV = '\0'*16 )
            data = ''.join( [ chr(x) for x in data ] )
            sig = cipher.encrypt( data )[-self.BS:]
            return sig[:self.TlenB]
        else:
            padlen = len( data ) % self.BS
            if padlen > 0: padlen = self.BS - padlen
            sig = self.cipher( data + '\0'*padlen, True )
            return sig[-self.BS:]
    
class KIK( object ):
    """ Representation of KIK for en/de-cryption of sensitive data"""
    def __init__( self, keyType, keyValue ):
        self.keyType = keyType
        self.zAES = keyType == KeyType.AES
        self.keyValue = keyValue
        l = len( keyValue )
        if self.zAES:
            assert l in ( 16, 24, 32 ), "Wrong length of AES key"

    def encrypt( self, data ):
        """Encrypt sensitive data by KIK.
For (3)DES, data must be padded to BS.
For AES, if data not BS-alligned, they are padded by '80..00'"""
        l = len( data )
        if self.zAES:
            l %= 16
            if l > 0:
                data += '\x80' + '\0'*(15-l)
            key = AES.new( self.keyValue, AES.MODE_CBC, IV='\0'*16 )
        else:
            # suppose 8B aligned data
            assert l % 8 == 0
            # for (3)DES KIK, ECB is used
            # KeyType.DES_IMPLICIT is supposed to be 3DES ECB
            if self.keyType in ( KeyType.TDES_CBC, KeyType.DES_IMPLICIT ):
                key = DES3.new( self.keyValue, DES.MODE_ECB )
            elif self.keyType in ( KeyType.DES_ECB, KeyType.DES_CBC ):
                key = DES.new( self.keyValue, DES.MODE_ECB )
            else: raise ValueError( "Unknown key type %02X" % self.keyType )
        return key.encrypt( data )

    def decrypt( self, data ):
        """Decrypt sensitive data by KIK. Data must be BS-alligned.
No padding removed."""
        pass

class SecurePacket( object ):
    def __init__( self, **kw ):
        self.typ = kw.get( 'typ', SMS_PP )
        # eg. 'KIC': ( 0x25, "abcdefghHGFEDCBA" ), ...
        for k in ( 'KIC', 'KID' ):
            if k in kw:
                self.__dict__[k] = KICD( kw[k][0] )
                if len( kw[k] ) > 1 and kw[k][1]:
                    self.__dict__[k].setValue( kw[k][1] )
        for k in ( 'SPI', 'iKIDCRC', 'TAR', 'counter', 'counter_file' ):
            if k in kw: self.__dict__[k] = kw[k]
        # counter_file override counter if both present
        if 'counter_file' in kw:
            f = open( self.counter_file, 'r' )
            RE_cntr = "^\s*(0[xX])?([\da-fA-F]{1,10})\s*$"
            m = re.match( RE_cntr, f.read())
            f.close()
            assert m is not None, \
                "Wrong format of counter in file %s" % self.counter_file 
            self.counter = unhexlify( m.groups()[1].rjust( 10, '0' ))

    def getKID( self, spi = None, iKID = None, zResp = False ):
        """ Depending on SPI returns chsumLen, iKID and KIDsign"""
        if spi is None: spi = self.SPI
        if zResp: spi <<= 6  # move CHSUM2 bits to CHSUM1 position
        chsumType = spi & SPI.CHSUM1
        if chsumType == 0:
            if iKID is None:
                iKID = 0
            chsumLen = 0
            KIDsign = None
        elif chsumType == SPI.CHSUM1_RC:
            if iKID is None:
                assert 'iKIDCRC' in self.__dict__, "KID for CRC not set"
                iKID = self.iKIDCRC
            assert self.iKIDCRC & ( 0x08 | KICD.ALGO ) == KICD.ALGO_CRC, \
                "Unsupported KID for CRC"
            if iKID & 0x0C == KICD.CRC32:
                chsumLen = 4
                KIDsign = CRC32
            else:
                chsumLen = 2
                KIDsign = CRC16
        elif chsumType == SPI.CHSUM1_CC:
            assert 'KID' in self.__dict__, "KID not set"
            if iKID is None:
                iKID = self.KID.iKICD
            else: assert iKID == self.KID.iKICD, "KID differ"
            KIDsign = self.KID.sign
            if self.KID.zAES:
                chsumLen = self.KID.TlenB
            else:
                chsumLen = 8
        else: raise ValueError( "DS not implemented" )
        return ( chsumLen, iKID, KIDsign )

    def createComPacket( self, secdata ):
        """ Create Command Packet. """
        # determine counter: if not available, use zero as default
        counter = self.SPI & SPI.CNTR1 and self.counter or "\0"*5
        chsumLen, iKID, KIDsign = self.getKID()

        # header = SPI(2), KIC/KID(2), TAR(3), counter(5), padCntr(1) + RC/CC
        headerLen = 13 + chsumLen
        # determine padding counter
        if self.SPI & SPI.ENC1: # encrypt?
            ciphLen = 6 + chsumLen + len( secdata ) # COUNTER,PCNTR,RC/CC,data
            padCntr = ciphLen % self.KIC.BS
            if padCntr > 0: padCntr = self.KIC.BS - padCntr
            secdata += '\0'*padCntr
        else: padCntr = 0
        packetLen = 1 + headerLen + len( secdata )

        # part of header to be signed only
        sigHead = pack( ">HBHBB", packetLen, headerLen, self.SPI,
                        self.KIC.iKICD, iKID ) + self.TAR
        # part of header to be ciphered too
        cipHead = counter + chr( padCntr )

        # calculate checksum
        if chsumLen > 0:
            data2sign = sigHead + cipHead + secdata
            cipHead += KIDsign( data2sign )

        if self.SPI & SPI.ENC1: # encrypt?
            packet = sigHead + self.KIC.cipher( cipHead + secdata, True )
        else:
            packet = sigHead + cipHead + secdata
        return packet

    def checkComPacket( self, packet ):
        """ Check Command Packet, unwrap security.
Returns secured data """
        pLen, hLen, spi, iKIC, iKID = unpack( ">HBHBB", packet[:7] )
        assert pLen + 2 == len( packet ), "Wrong CPL"
        if spi != self.SPI:
            print "Different SPI %04X" % spi
        TAR = packet[7:10]
        if TAR != self.TAR:
            print "Different TAR", hexlify( TAR )
        chsumLen, iKID, KIDsign = self.getKID( spi, iKID )
        if spi & SPI.ENC1:
            assert iKIC == self.KIC.iKICD, "Different KIC"
            plainData = self.KIC.cipher( packet[10:], False )
        else:
            plainData = packet[10:]
        counter = plainData[:5]
        if counter != self.counter:
            print "Different counter", hexlify( counter )
        pcounter = ord( plainData[5] )
        plaindData = plainData[6:]
        assert pcounter < self.KIC.BS, "Wrong pad. counter %02X" % pcounter
        if pcounter > 0:
            assert plainData[-pcounter:] == '\0'*pcounter, "Nonzero padding"
            plainData = plainData[:-pcounter]
        if chsumLen > 0:
            chsum = plainData[6:6+chsumLen]
            plainData = plainData[6+chsumLen:]
            data2sign = packet[:10] + counter + chr( pcounter ) + \
                        plainData + '\0'*pcounter
            expCC = KIDsign( data2sign )
            assert chsum == expCC, "Wrong CC: %s vs %s expected" % (
                hexlify( chsum ).upper(), hexlify( expCC ).upper())
        return plainData

    def createRespPacket( self, secdata ):
        """ Create Response Packet. """
        pass

    def checkRespPacket( self, packet ):
        """ Check Response Packet. SMS PP expects packet with UDH."""
        chsumLen, iKID, KIDsign = self.getKID( zResp = True )
        headerLen = chsumLen + 10 # TAR, CNTR, PCNTR, RCS
        if self.typ == SMS_PP:
            UDH = unhexlify( "027100" )
            assert packet[:3] == UDH, "Missing/wrong UDH"
            packet = packet[3:]
        else:
            raise ValueError( "Only SMS PP implemented" )

        # check lenghts
        assert len( packet ) == 2 + unpack( ">H", packet[:2] )[0], \
            "Packet length mismatch"
        assert ord( packet[2] ) == headerLen, "Header length mismatch"
        # check TAR
        assert packet[3:6] == self.TAR, "TAR mismatch: exp=%s vs. rec=%s" % (
                hexlify( self.TAR ), hexlify( packet[3:6] ))

        if self.SPI & SPI.ENC2: # decipher
            assert len( packet ) % self.KIC.BS == 6, \
                "Length of ciphered part not multiple of BS"
            plainData = self.KIC.cipher( packet[6:], False )
        else:
            plainData = packet[6:]

        # check RC/CC
        if chsumLen > 0:
            data2sign = ( UDH + packet[:6] # packet+header lens, TAR
                          + plainData[:7]  # CNTR, PCNTR, RSC
                          + plainData[7+chsumLen:] ) # skip CC
            assert plainData[7:7+chsumLen] == KIDsign( data2sign ),\
                "Wrong CC"

        # check counter if ciphered
        if self.SPI & SPI.ENC2:
            assert plainData[:5] == self.counter, \
                "counter mismatch: exp=%s vs. rec=%s" % (
                    hexlify( self.counter ), hexlify( plainData[:5] ))
        # check padding
        pcntr = ord( plainData[5] )
        if pcntr > 0:
            padding = plainData[-pcntr:]
            plainData = plainData[:-pcntr]
        else:
            padding = ''
        assert pcntr < self.KIC.BS and padding == '\0'*pcntr, "Wrong padding"
        
        # return ( rcs, secured_data )
        return ( ord(plainData[6]), plainData[7+chsumLen:] )

    def incCounter( self, value = 1 ):
        """ Increment counter by given values (as int, default = 1). """        
        vals = [ ord( x ) for x in self.counter ]
        vals[4] += value
        for i in xrange( 4, 0, -1 ):
            if 0 <= vals[i] and vals[i] < 0x100: break
            vals[i-1] += vals[i] / 0x100
            vals[i] %= 0x100
        self.counter = l2s( vals )
        if 'counter_file' in self.__dict__:
            f = open( self.counter_file, 'w' )
            f.write( hexlify( self.counter ))
            f.close()

    def counter2int( self ):
        return reduce( lambda x, y: ( x << 8 ) + y,
                       [ ord(x) for x in self.counter ])

def CRC32( s ):
    """ Calculate CRC32 as defined in ETSI 102.225, 5.1.3.2 and Annex B """
    crc = 0xFFFFFFFF
    for c in s:
        x = ord(c)
        for _ in xrange( 8 ):
            carry = crc & 1
            crc >>= 1
            if carry ^ ( x & 1 ):
                crc ^= 0xedb88320
            x >>= 1
    crc ^= 0xFFFFFFFF
    return pack( ">L", crc )

def CRC16( s ):
    """ Calculate CRC16 as defined in ETSI 102.225, 5.1.3.2 and Annex B """
    crc = 0xFFFF
    for c in s:
        x = ord(c)
        for _ in xrange( 8 ):
            carry = crc & 1
            crc >>= 1
            if carry ^ ( x & 1 ):
                crc ^= 0x8408
            x >>= 1
    crc ^= 0xFFFF
    return pack( ">H", crc )

##################### tests ######################
import unittest

class TestSecurePacket( unittest.TestCase ):

    def test_incCounter( self ):
        secpacket_par = { 'counter': unhexlify( '0123456789' ), }
        sp = SecurePacket( **secpacket_par )

        for x in ( 1, 0x77, 0x1234, 0x90000000, -1, -100000000 ):
            icounter = sp.counter2int() + x
            sp.incCounter( x )
            self.assertEqual( sp.counter2int(), icounter )

    def test_SPI0400( self ):
        secpacket_par = { 'SPI': 0x0400,
                          'KIC': ( 0x15, unhexlify( "AABBCCDDEEFF00112233445566778899" )),
                          'KID': ( 0x15, '' ),
                          'TAR': '\0'*3,
                          'counter': '\0'*5, }
        payload = unhexlify( 'ABECEDAB' )
        expres = unhexlify( "00180D04001515000000B959E0D6BFABCF59F158041EEB0AB14A" )
        sp = SecurePacket( **secpacket_par )
        res = sp.createComPacket( payload )
        self.assertEqual( res, expres )

    def test_SPI0E00( self ):
        secpacket_par = { 'SPI': 0x0E00,
                          'KIC': ( 0x25, unhexlify( "2233445566778899AABBCCDDEEFF0011" )),
                          'KID': ( 0x25, unhexlify( "456789ABCDEF012356789ABCDEF01234" )),
                          'TAR': unhexlify( 'C00000' ),
                          'counter': unhexlify('0000000001') }
        payload = unhexlify( 'A0A40000023F00' )
        expres = unhexlify( "0020150E002525C0000028BDEA5BAFC32C4CE1A79B247ECEB40888775EE0A700742A" )
        sp = SecurePacket( **secpacket_par )
        res = sp.createComPacket( payload )
        self.assertEqual( res, expres )

    def test_SPI1201( self ):
        secpacket_par = { 'SPI': 0x1201,
                          'KIC': ( 0x25, unhexlify( "2233445566778899AABBCCDDEEFF0011" )),
                          'KID': ( 0x25, unhexlify( "456789ABCDEF012356789ABCDEF01234" )),
                          'TAR': unhexlify( 'C00000' ),
                          'counter': unhexlify('0000000001') }
        payload = unhexlify( 'A0A40000023F00' )
        expres = unhexlify( "001D1512012525C000000000000001004FBDB3740E950C28A0A40000023F00" )
        sp = SecurePacket( **secpacket_par )
        res = sp.createComPacket( payload )
        self.assertEqual( res, expres )

    def test_SPI1601( self ):
        secpacket_par = { 'SPI': 0x1601,
                          'KIC': ( 0x25, unhexlify( "2233445566778899AABBCCDDEEFF0011" )),
                          'KID': ( 0x25, unhexlify( "456789ABCDEF012356789ABCDEF01234" )),
                          'TAR': unhexlify( 'C00000' ),
                          'counter': unhexlify('0000000001') }
        payload = unhexlify( 'A0A40000023F00' )
        expres = unhexlify( "00201516012525C0000090B844A4FAABEF7184998080D900A6F55A7AD667B45EA3A6" )
        sp = SecurePacket( **secpacket_par )
        res = sp.createComPacket( payload )
        self.assertEqual( res, expres )

    def test_SPI1601_VTSD( self ):
        secpacket_par = { 'SPI': 0x1601,
                          'KIC': ( 0x39, unhexlify( "0956F342366C6C92F32D5392ECB1CBD5C051DB484843F0EB" )),
                          'KID': ( 0x39, unhexlify( "9CD41F792BC38C08A5DF849B4118C71AEA4D8192207297C8" )),
                          'TAR': unhexlify( 'C20010' ),
                          'counter': unhexlify('0000000006') }
        payload = unhexlify( 'A0A40000023F00' )
        expres = unhexlify( "00201516013939C20010BC10EE50A5C581408562D8F2C80D2C9AA0AED19DA2CD7D50" )
        sp = SecurePacket( **secpacket_par )
        res = sp.createComPacket( payload )
        self.assertEqual( res, expres )

    def test_SPI1201_VTSD( self ):
        secpacket_par = { 'SPI': 0x1201,
                          'KIC': ( 0x39, unhexlify( "0956F342366C6C92F32D5392ECB1CBD5C051DB484843F0EB" )),
                          'KID': ( 0x39, unhexlify( "9CD41F792BC38C08A5DF849B4118C71AEA4D8192207297C8" )),
                          'TAR': unhexlify( 'C20010' ),
                          'counter': unhexlify('0000000007') }
        payload = unhexlify( 'A0A40000023F00' )
        expres = unhexlify( "001D1512013939C200100000000007008523E37E6DBCCF7DA0A40000023F00" )
        sp = SecurePacket( **secpacket_par )
        res = sp.createComPacket( payload )
        self.assertEqual( res, expres )

    def test_SPI1531( self ):
        from formutil import findTLValue
        import CAT
        sp_par = { 'SPI': 0x1535,
                   'KIC': ( 0x15, unhexlify( '263B48DBCBC1C21C0AA13E4D4516C446' )),
                   'iKIDCRC': 0x15,
                   'TAR': unhexlify( 'C00000' ),
                   'counter': unhexlify( '0000000076' ) }
        apdu_payload = unhexlify( '80CA00E000' + '00C0000000' )
        sp = SecurePacket( **sp_par )
        data = unhexlify( 'D13A820283818B3444038119F07FF6151124135822042502700000201115351515C000004D5C2C7F43D3E774316C66CE8E1D5045755BACEF5DC83203' )
        tpdu = findTLValue( data, ( 0xD1, 0x8B ))
        sms = CAT.SMS_MT()
        sms.parseTPDU( tpdu )
        udh, secp = sms.mergeUserData()
        payload = sp.checkComPacket( secp )
        self.assertEqual( payload, apdu_payload )

        secp1 = sp.createComPacket( apdu_payload )
        self.assertEqual( secp, secp1 )

        # response
        rdata = unhexlify( 'D04781030113008202818305008B3A4100038119F000F631027100002C0EC00000888B39C361C66D5F3DC4EFCEF508CC228021DD34E577B147E54EFF18B3922C9176644E2E8AA9A695' )
        tpdu = CAT.TLV( 0x8B, findTLValue( rdata, ( 0xD0, 0x8B )))
        SCA = CAT.TLV( 0x05, findTLValue( rdata, ( 0xD0, 0x05 )))
        sms = CAT.SMS_MO()
        sms.addMessage( SCA, tpdu )
        udh, secp = sms.mergeMessages()
        rcs, payload = sp.checkRespPacket( udh + secp )
        self.assertEqual( rcs, 0 )
        self.assertEqual( payload, unhexlify( '019000E012C00401018210C00402018210C00403018210' ))
        scout_log = """
Global Platform Operation Summary: 
   Channel used: Secure channel protocol 80
   Target TAR: C00000, Security Settings SPI1: 15, SPI2: 35, KIC: 15, KID: 15
  
Task: Custom operation started  
APDU Sequence: Sending data.  
Header: 80 C2 00 00 3C 
Data In: D13A820283818B3444038119F07FF6151124135822042502700000201115351515C000004D5C2C7F43D3E774316C66CE8E1D5045755BACEF5DC83203 
SW: 9149 
Header: 80 12 00 00 49 
Data Out: D04781030113008202818305008B3A4100038119F000F631027100002C0EC00000888B39C361C66D5F3DC4EFCEF508CC228021DD34E577B147E54EFF18B3922C9176644E2E8AA9A695 
SW: 9000 
Header: 80 14 00 00 0C 
Data In: 810301130082028281830100 
SW: 9000 
 """
        
class TestCRC( unittest.TestCase ):
    def test_CRC32( self ):
        self.assertEqual( CRC32( unhexlify( "0102030405" )),
                          unhexlify( "470B99F4"))

if __name__ == '__main__':
    unittest.main()
